"""Find unambiguous byte ranges shared by initialized Ghidra blocks."""

from base64 import b64decode
from collections import defaultdict
from dataclasses import dataclass

_ANCHOR_SIZE = 16
_ANCHOR_STRIDE = 8


@dataclass
class _Extent:
    start: int
    end: int
    delta: int
    anchor_start: int
    anchor_end: int


def _occurrences(blocks: dict[int, bytes], anchors: dict[bytes, None]) -> dict:
    found = {}
    for index, data in blocks.items():
        for offset in range(len(data) - _ANCHOR_SIZE + 1):
            anchor = data[offset:offset + _ANCHOR_SIZE]
            if anchor in anchors:
                found[anchor] = None if anchor in found else (index, offset)
    return found


def _shared_extent(first: bytes, second: bytes, old: int, new: int, *, backwards: bool) -> int:
    def matches(length):
        if backwards:
            return first[old - length:old] == second[new - length:new]
        return first[old:old + length] == second[new:new + length]

    # Find the first mismatch near the anchor before testing longer slices.
    limit = min(old, new) if backwards else min(len(first) - old, len(second) - new)
    low, high = 0, min(1, limit)
    while high > low and matches(high):
        low, high = high, min(high * 2, limit)
    while low < high:
        length = (low + high + 1) // 2
        if matches(length):
            low = length
        else:
            high = length - 1
    return low


def _ranges(first: bytes, second: bytes, anchors: list[tuple[int, int]]) -> list[dict]:
    extents = []
    latest = {}
    for old, new in anchors:
        delta = new - old
        previous = latest.get(delta)
        if previous is not None and old < previous.end:
            previous.anchor_end = old + _ANCHOR_SIZE
            continue
        left = _shared_extent(first, second, old, new, backwards=True)
        right = _ANCHOR_SIZE + _shared_extent(first, second, old + _ANCHOR_SIZE, new + _ANCHOR_SIZE,
                                              backwards=False)
        extent = _Extent(old - left, old + right, delta, old, old + _ANCHOR_SIZE)
        latest[delta] = extent
        extents.append(extent)
    # Two byte alignments can extend into the same padding. Preserve their anchored portions
    # and trim overlapping extensions. Overlapping anchored portions leave both unresolved.
    bounds = [[row.start, row.end] for row in extents]
    overlapping = set()
    for destination in (False, True):
        shift = [row.delta if destination else 0 for row in extents]
        ordered = sorted(range(len(extents)), key=lambda i: extents[i].anchor_start + shift[i])
        active, end = None, 0
        for position, i in enumerate(ordered):
            extent = extents[i]
            start, stop = extent.anchor_start + shift[i], extent.anchor_end + shift[i]
            if start < end:
                overlapping.update((active, i))
            if stop > end:
                active, end = i, stop
            if position:
                neighbor = ordered[position - 1]
                left = extents[neighbor].end + shift[neighbor]
                bounds[i][0] = max(bounds[i][0], min(start, left) - shift[i])
            if position + 1 < len(ordered):
                neighbor = ordered[position + 1]
                right = extents[neighbor].start + shift[neighbor]
                bounds[i][1] = min(bounds[i][1], max(stop, right) - shift[i])
    ranges = [{"before_offset": start, "after_offset": start + extent.delta, "length": end - start}
              for i, (extent, (start, end)) in enumerate(zip(extents, bounds)) if i not in overlapping]
    return sorted(ranges, key=lambda row: row["before_offset"])


def shared_ranges(before: dict[int, bytes], after: dict[int, bytes], *, eligible, rename: bool = False) -> dict:
    """Find source-sampled anchors that occur exactly once on each side, including off-stride hits."""
    anchors = {}
    for data in before.values():
        for start in range(0, len(data) - _ANCHOR_SIZE + 1, _ANCHOR_STRIDE):
            word = data[start:start + _ANCHOR_SIZE]
            if word.count(word[:1]) < _ANCHOR_SIZE:
                anchors[word] = None
    if not anchors:
        return {}
    first, second = (_occurrences(blocks, anchors) for blocks in (before, after))
    pairs = defaultdict(list)
    for anchor, source in first.items():
        destination = second.get(anchor)
        if source is not None and destination is not None and eligible(source[0], destination[0]):
            pairs[source[0], destination[0]].append((source[1], destination[1]))
    ranges = {}
    for pair, sites in pairs.items():
        sites.sort()
        extents = _ranges(before[pair[0]], after[pair[1]], sites)
        if extents and (not rename or _independent_anchors(sites, extents)):
            ranges[pair] = extents
    return ranges


def _independent_anchors(sites: list[tuple[int, int]], extents: list[dict]) -> bool:
    """Require two disjoint windows within accepted ranges, excluding extension into padding."""
    index = 0
    first = None
    for old, new in sites:
        row = extents[index]
        while old >= row["before_offset"] + row["length"]:
            index += 1
            if index == len(extents):
                return False
            row = extents[index]
        displacement = old - row["before_offset"]
        if 0 <= displacement <= row["length"] - _ANCHOR_SIZE and new == row["after_offset"] + displacement:
            if first is None:
                first = old
            elif old - first >= _ANCHOR_SIZE:
                return True
    return False


def storage_content_matches(before, after, attributes, fixed_pairs, rename_sources, rename_destinations):
    """Find ranges for changed named pairs and candidates for renamed blocks."""
    contents = [{i: b64decode(row["content"]) for i, row in side.items() if row.get("content") is not None}
                for side in (before, after)]
    old_bytes, new_bytes = contents
    ranges = {}
    for old, new in fixed_pairs.items():
        if not before[old]["initialized"] or "content" not in before[old] or "content" not in after[new]:
            continue
        original, revised = old_bytes.get(old), new_bytes.get(new)
        digest = before[old].get("content_sha256")
        if digest and digest == after[new].get("content_sha256"):
            continue
        if original is not None and revised is not None:
            common = min(len(original), len(revised))
            if original[:common] == revised[:common]:
                continue
            ranges[old, new] = shared_ranges({old: original}, {new: revised},
                                              eligible=lambda *_: True).get((old, new), [])
        else:
            ranges[old, new] = []

    old_groups, new_groups = defaultdict(dict), defaultdict(dict)
    for blocks, side, groups in ((before, old_bytes, old_groups), (after, new_bytes, new_groups)):
        for index, row in blocks.items():
            if row["initialized"]:
                groups[attributes(row)][index] = side.get(index)
    candidates, reverse = defaultdict(list), defaultdict(list)
    for key, old_group in old_groups.items():
        new_group = new_groups.get(key, {})
        if (not rename_sources.intersection(old_group) or not rename_destinations.intersection(new_group)
                or None in old_group.values() or None in new_group.values()):
            continue
        for (old, new), extents in shared_ranges(
            old_group, new_group, eligible=lambda old, new: old in rename_sources and new in rename_destinations,
            rename=True,
        ).items():
            candidates[old].append((new, extents))
            reverse[new].append(old)
    renamed = {}
    for old, options in candidates.items():
        if len(options) == 1:
            new, extents = options[0]
            if len(reverse[new]) == 1:
                renamed[old] = new
                ranges[old, new] = extents
    return renamed, ranges
