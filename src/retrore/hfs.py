"""Read application resource forks from classic HFS volumes and Disk Copy 4.2 images."""

from collections.abc import Iterator
from dataclasses import dataclass
from struct import unpack_from

from .errors import CodedError
from .members import Member, match_members

_SECTOR_SIZE = 512
_MDB = 2 * _SECTOR_SIZE
_DC42_HEADER = 84
_HFS_MAGIC = b"BD"
_ROOT_FOLDER = 2
_CATALOG_FILE = 4
_RESOURCE_FORK = 0xFF


class HfsError(CodedError):
    """A malformed or unsupported Classic Macintosh disk image."""


def is_hfs_disk(data: bytes) -> bool:
    return data[_MDB:_MDB + 2] == _HFS_MAGIC or (
        data[82:84] == b"\x01\x00" and data[_DC42_HEADER + _MDB:_DC42_HEADER + _MDB + 2] == _HFS_MAGIC
    )


@dataclass(frozen=True)
class HfsFork:
    name: str
    data: bytes
    # Logical fork offset, container file offset, byte count.
    spans: tuple[tuple[int, int, int], ...]
    member: Member


@dataclass(frozen=True)
class _CatalogFile:
    name: str
    parent: int
    file_id: int
    is_application: bool
    resource_size: int
    resource_extents: tuple[tuple[int, int], ...]


def _extent_record(data: bytes, offset: int) -> tuple[tuple[int, int], ...]:
    values = unpack_from(">6H", data, offset)
    return tuple((start, count) for start, count in zip(values[::2], values[1::2], strict=True) if count)


def _leaf_records(tree: bytes, name: str) -> Iterator[bytes]:
    # HFS uses 512-byte nodes. The 14-byte descriptor is followed by the header record in node 0.
    if len(tree) < _SECTOR_SIZE or tree[8] != 1 or unpack_from(">H", tree, 32)[0] != _SECTOR_SIZE:
        raise HfsError(f"invalid HFS {name} B-tree header")
    expected, node, last = unpack_from(">3I", tree, 20)
    seen = set()
    count_seen = last_seen = 0
    while node:
        if node in seen or (node + 1) * _SECTOR_SIZE > len(tree):
            raise HfsError(f"invalid HFS {name} B-tree leaf chain")
        seen.add(node)
        start = node * _SECTOR_SIZE
        leaf = tree[start:start + _SECTOR_SIZE]
        following, previous, kind, height, count = unpack_from(">IIbBH", leaf)
        index = _SECTOR_SIZE - 2 * (count + 1)
        if kind != -1 or height != 1 or index < 14 or previous != last_seen:
            raise HfsError(f"invalid HFS {name} B-tree leaf")
        offsets = unpack_from(f">{count + 1}H", leaf, index)[::-1]
        if offsets[0] < 14 or offsets[-1] > index or any(a >= b for a, b in zip(offsets, offsets[1:])):
            raise HfsError(f"invalid HFS {name} B-tree record offsets")
        for left, right in zip(offsets, offsets[1:]):
            yield leaf[left:right]
        count_seen += count
        last_seen, node = node, following
    if count_seen != expected or last != last_seen:
        raise HfsError(f"incomplete HFS {name} B-tree")


class HfsDisk:
    """An unpartitioned classic HFS volume with optional Disk Copy 4.2 header."""

    def __init__(self, data: bytes):
        self.container = "hfs"
        self._start, self._end = 0, len(data)
        if data[_MDB:_MDB + 2] != _HFS_MAGIC and data[82:84] == b"\x01\x00":
            data_size, tag_size = unpack_from(">2I", data, 64)
            if data[0] > 63 or not data_size or data_size % _SECTOR_SIZE or tag_size % 12:
                raise HfsError("invalid Disk Copy 4.2 header")
            self.container = "dc42"
            self._start, self._end = _DC42_HEADER, _DC42_HEADER + data_size
            if self._end + tag_size > len(data):
                raise HfsError("truncated Disk Copy 4.2 image")
        self._data = data
        mdb_at = self._start + _MDB
        if mdb_at + 162 > self._end or data[mdb_at:mdb_at + 2] != _HFS_MAGIC:
            raise HfsError("expected a classic HFS volume")
        self._count, self._block_size = unpack_from(">HI", data, mdb_at + 18)
        self._allocation = self._start + unpack_from(">H", data, mdb_at + 28)[0] * _SECTOR_SIZE
        if (not self._count or self._block_size < _SECTOR_SIZE or self._block_size % _SECTOR_SIZE
                or self._allocation < self._start + 3 * _SECTOR_SIZE
                or self._allocation + self._block_size * self._count > self._end):
            raise HfsError("invalid HFS allocation block geometry")
        self._overflow_size = unpack_from(">I", data, mdb_at + 130)[0]
        self._overflow_extents = _extent_record(data, mdb_at + 134)
        self._overflow_records = None
        catalog_size = unpack_from(">I", data, mdb_at + 146)[0]
        catalog_extents = _extent_record(data, mdb_at + 150)
        catalog, _ = self._read_fork(catalog_size, catalog_extents, "catalog", _CATALOG_FILE, 0)
        self._files, self._folders = self._read_catalog(catalog)

    def _read_fork(
        self, size: int, extents: tuple[tuple[int, int], ...], name: str, file_id: int | None = None, fork: int = 0,
    ) -> tuple[bytes, tuple[tuple[int, int, int], ...]]:
        if size > self._block_size * self._count:
            raise HfsError(f"HFS {name} exceeds the volume size")
        payload = bytearray()
        spans = []
        used_blocks = 0
        occupied = set()
        while len(payload) < size:
            if not extents:
                raise HfsError(f"HFS {name} is missing extents at allocation block {used_blocks}")
            for start, count in extents:
                blocks = range(start, start + count)
                if start + count > self._count or not occupied.isdisjoint(blocks):
                    raise HfsError(f"HFS {name} has an invalid or repeated allocation block")
                occupied.update(blocks)
                at = self._allocation + start * self._block_size
                length = min(count * self._block_size, size - len(payload))
                if not length:
                    break
                # Adjacent physical extents are contiguous to the consumer.
                if spans and spans[-1][1] + spans[-1][2] == at:
                    logical, previous, previous_size = spans[-1]
                    spans[-1] = (logical, previous, previous_size + length)
                else:
                    spans.append((len(payload), at, length))
                payload.extend(self._data[at:at + length])
                used_blocks += count
            if len(payload) < size:
                extents = self._overflow().get((fork, file_id, used_blocks), ()) if file_id is not None else ()
        return bytes(payload), tuple(spans)

    def _overflow(self) -> dict:
        if self._overflow_records is None:
            records = {}
            if self._overflow_size:
                tree, _ = self._read_fork(self._overflow_size, self._overflow_extents, "overflow")
                for record in _leaf_records(tree, "extents overflow"):
                    if len(record) < 20 or record[0] != 7:
                        raise HfsError("invalid HFS extents overflow record")
                    key = unpack_from(">BIH", record, 1)
                    if key in records:
                        raise HfsError("duplicate HFS extents overflow key")
                    records[key] = _extent_record(record, 8)
            self._overflow_records = records
        return self._overflow_records

    @staticmethod
    def _read_catalog(tree: bytes) -> tuple[list[_CatalogFile], dict[int, tuple[int, str]]]:
        files, folders = [], {}
        for record in _leaf_records(tree, "catalog"):
            if len(record) < 8 or not 6 <= record[0] <= 37:
                raise HfsError("invalid HFS catalog key")
            name_size = record[6]
            record_at = (record[0] + 2) & ~1
            if 6 + name_size > record[0] or record_at + 2 > len(record):
                raise HfsError("truncated HFS catalog record")
            parent = unpack_from(">I", record, 2)[0]
            name = record[7:7 + name_size].decode("mac_roman")
            item = record[record_at:]
            if item[0] == 1:
                if len(item) < 70:
                    raise HfsError("truncated HFS folder record")
                folder = unpack_from(">I", item, 6)[0]
                if folder in folders:
                    raise HfsError("duplicate HFS catalog folder ID")
                folders[folder] = (parent, name)
            elif item[0] == 2:
                if len(item) < 102:
                    raise HfsError("truncated HFS file record")
                file_id = unpack_from(">I", item, 20)[0]
                resource_size = unpack_from(">I", item, 36)[0]
                files.append(_CatalogFile(name, parent, file_id, item[4:8] == b"APPL", resource_size,
                                          _extent_record(item, 86)))
        return files, folders

    def _path(self, item: _CatalogFile) -> str:
        parts, seen = [item.name], set()
        parent = item.parent
        while parent != _ROOT_FOLDER:
            if parent in seen or parent not in self._folders:
                raise HfsError("invalid HFS catalog folder chain")
            seen.add(parent)
            parent, name = self._folders[parent]
            parts.append(name)
        return "/".join(reversed(parts))

    def _member(self, item: _CatalogFile) -> Member:
        return Member(f"file:{item.file_id}", self._path(item), "file", bool(item.resource_size),
                      size=item.resource_size, details={"application": item.is_application, "fork": "resource"})

    def list_members(self) -> list[Member]:
        return [self._member(item) for item in self._files]

    def read_resource_fork(self, name: str | None = None) -> HfsFork:
        """Select an application automatically or read a named file's resource fork."""
        if name is None:
            matches = [item for item in self._files if item.is_application and item.resource_size]
        else:
            entries = [(self._member(item), item) for item in self._files]
            matches = [item for _, item in match_members(entries, name)] if name.casefold().startswith("id:") else []
            if not matches:
                parts = name.replace(":", "/").strip("/").casefold()
                matches = [item for member, item in entries
                           if (member.name if "/" in parts else item.name).casefold() == parts]
        if not matches:
            label = repr(name) if name is not None else "an application with a resource fork"
            raise HfsError(f"HFS disk does not contain {label}")
        if len(matches) > 1:
            names = ", ".join(f"{member.name!r} ({member.selector})"
                              for member in map(self._member, matches[:8]))
            more = f" and {len(matches) - 8} more" if len(matches) > 8 else ""
            raise HfsError(f"select one HFS file with --disk-file NAME: {names}{more}")
        item = matches[0]
        if not item.resource_size:
            raise HfsError(f"HFS file {item.name!r} has no resource fork")
        member = self._member(item)
        fork, spans = self._read_fork(item.resource_size, item.resource_extents, member.name, item.file_id, _RESOURCE_FORK)
        return HfsFork(member.name, fork, spans, member)
