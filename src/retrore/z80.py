"""Place ordered loads in a selected Z80 address space."""

from collections import Counter
from dataclasses import dataclass
from itertools import groupby

from .d88 import D88Disk
from .image import FLAT16_ADDRESS_LIMIT


@dataclass(frozen=True)
class SourceSpan:
    offset: int
    file_offset: int
    size: int


@dataclass(frozen=True)
class Z80Source:
    name: str
    source: str
    address: int
    data: bytes
    disk_file: str | None = None
    file_offset: int = 0
    file_spans: tuple[SourceSpan, ...] = ()

    @property
    def end(self) -> int:
        return self.address + len(self.data)

    def spans(self, offset: int, size: int) -> tuple[SourceSpan, ...]:
        spans = []
        for span in self.file_spans:
            start = max(span.offset, offset)
            end = min(span.offset + span.size, offset + size)
            if start < end:
                spans.append(SourceSpan(start - offset, span.file_offset + start - span.offset, end - start))
        return tuple(spans)

    def provenance(self, offset: int, size: int) -> dict:
        spans = self.spans(offset, size)
        report = {"file_offset": spans[0].file_offset if spans else self.file_offset + offset}
        if len(spans) > 1:
            report["file_spans"] = [
                {"offset": span.offset, "file_offset": span.file_offset, "size": span.size} for span in spans
            ]
        return report


def place_z80_sources(
    sources: list[Z80Source], entries: list[int], prefix: str, error: type[ValueError],
) -> tuple[bytes, dict]:
    """Place sources in order and describe the visible parts of each load."""
    if not sources:
        raise error(f"no {prefix} inputs to load")
    image = bytearray(FLAT16_ADDRESS_LIMIT)
    owners = [None] * FLAT16_ADDRESS_LIMIT
    names = set()
    for index, source in enumerate(sources):
        name = source.name.casefold()
        if not name or ":" in name or name.startswith(f"{prefix.lower()}_") or name in names:
            raise error(f"invalid or duplicate {prefix} source name {source.name!r}")
        names.add(name)
        if not 0 <= source.address < source.end <= FLAT16_ADDRESS_LIMIT:
            raise error(f"{prefix} source {source.name!r} is empty or exceeds the 16-bit address space")
        image[source.address:source.end] = source.data
        owners[source.address:source.end] = [index] * len(source.data)

    ranges = []
    for index, addresses in groupby(range(FLAT16_ADDRESS_LIMIT), key=owners.__getitem__):
        if index is not None:
            start = next(addresses)
            end = start + 1 + sum(1 for _ in addresses)
            ranges.append((index, start, end))
    counts = Counter(index for index, _, _ in ranges)
    origin = ranges[0][1]
    units = []
    for index, start, end in ranges:
        source = sources[index]
        name = source.name if counts[index] == 1 and start == source.address else f"{source.name}_{start:04x}"
        units.append({
            "name": name, "kind": "ram", "linear": start, "size": end - start, "image_offset": start - origin,
            "file_size": end - start, **source.provenance(start - source.address, end - start),
            "source": source.source, "disk_file": source.disk_file,
        })
    if len({unit["name"].casefold() for unit in units}) != len(units):
        raise error(f"duplicate {prefix} memory block name")

    entry_records = []
    for address in dict.fromkeys(entries):
        unit = next((unit for unit in units if unit["linear"] <= address < unit["linear"] + unit["size"]), None)
        if unit is None:
            raise error(f"{prefix} entry {address:x} is outside loaded RAM")
        entry_records.append({"linear": address, "unit_address": f"{unit['name']}:{address - unit['linear']:04x}"})
    return bytes(image[origin:ranges[-1][2]]), {
        "base_address": origin,
        "sources": [
            {"name": source.name, "source": source.source, "disk_file": source.disk_file,
             "linear": source.address, "size": len(source.data), **source.provenance(0, len(source.data))}
            for source in sources
        ],
        "units": units, "entry": entry_records[0] if entry_records else None, "entries": entry_records,
    }


def disk_span_source(
    disk: D88Disk, filename: str, name: str, address: int, cylinder: int, head: int, record: int, count: int = 1,
    size: int | None = None,
) -> Z80Source:
    """Read a D88 sector span, optionally truncated to `size` bytes, with original container offsets."""
    payload = bytearray()
    spans = []
    for sector in disk.read_sectors(cylinder, head, record, count):
        spans.append(SourceSpan(len(payload), sector.file_offset, len(sector.data)))
        payload.extend(sector.data)
    if size is not None:
        payload = payload[:size]
        spans = [SourceSpan(span.offset, span.file_offset, min(span.size, size - span.offset))
                 for span in spans if span.offset < size]
    return Z80Source(name, filename, address, bytes(payload), file_offset=spans[0].file_offset, file_spans=tuple(spans))


def copy_z80_source(
    sources: list[Z80Source], address: int, size: int, destination: int, error: type[ValueError], prefix: str,
) -> Z80Source:
    """Copy a span of the topmost load that covers it to a new runtime address."""
    end = address + size
    for source in reversed(sources):
        if source.address < end and address < source.end:
            if source.address <= address < end <= source.end:
                offset = address - source.address
                return Z80Source(
                    f"copy_{destination:04x}_from_{address:04x}_{size:x}", source.source,
                    destination, source.data[offset:offset + size], source.disk_file,
                    file_offset=source.file_offset + offset, file_spans=source.spans(offset, size),
                )
            break
    raise error(f"{prefix} copy {address:x}:{size:x} must fit within a single visible load")
