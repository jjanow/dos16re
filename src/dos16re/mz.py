"""Parse and relocate DOS MZ load modules."""

from dataclasses import dataclass
from struct import Struct

_HEADER = Struct("<2s13H")
_RELOCATION = Struct("<HH")
_WORD = Struct("<H")
_PAGE_SIZE = 512
_PARAGRAPH_SIZE = 16
_SEGMENT_MASK = 0xFFFF
_REAL_MODE_SIZE = 0x100000

DEFAULT_BASE_SEGMENT = 0x1000


class MZError(ValueError):
    """An invalid or unsupported MZ load module."""


@dataclass(frozen=True)
class Address:
    segment: int
    offset: int

    @property
    def linear(self) -> int:
        return self.segment * _PARAGRAPH_SIZE + self.offset

    def __str__(self) -> str:
        return f"{self.segment:04x}:{self.offset:04x}"


@dataclass(frozen=True)
class MZHeader:
    last_page_bytes: int
    page_count: int
    relocation_count: int
    header_paragraphs: int
    min_alloc_paragraphs: int
    max_alloc_paragraphs: int
    initial_ss: int
    initial_sp: int
    checksum: int
    initial_ip: int
    initial_cs: int
    relocation_offset: int
    overlay_number: int

    @property
    def header_size(self) -> int:
        return self.header_paragraphs * _PARAGRAPH_SIZE

    @property
    def file_size(self) -> int:
        last_page_size = self.last_page_bytes or _PAGE_SIZE
        return (self.page_count - 1) * _PAGE_SIZE + last_page_size


@dataclass(frozen=True)
class LoadedMZ:
    base_segment: int
    image: bytes
    entry: Address
    stack: Address


@dataclass(frozen=True)
class MZExecutable:
    header: MZHeader
    relocations: tuple[Address, ...]
    image: bytes

    @classmethod
    def parse(cls, data: bytes) -> "MZExecutable":
        if len(data) < _HEADER.size:
            raise MZError("truncated MZ header")

        signature, *fields = _HEADER.unpack_from(data)
        if signature != b"MZ":
            raise MZError("missing MZ signature")
        header = MZHeader(*fields)

        if header.page_count == 0 or header.last_page_bytes >= _PAGE_SIZE:
            raise MZError("invalid MZ page counts")
        if not _HEADER.size <= header.header_size <= header.file_size:
            raise MZError("invalid MZ header size")
        if header.file_size > len(data):
            raise MZError("truncated MZ executable")

        # The file may contain overlay data after the declared MZ module.
        image = data[header.header_size:header.file_size]
        relocations = _parse_relocations(data, header, len(image))
        return cls(header, relocations, image)

    def load(self, base_segment: int = DEFAULT_BASE_SEGMENT) -> LoadedMZ:
        if not 0 <= base_segment <= _SEGMENT_MASK:
            raise MZError("base segment must be between 0000 and ffff")
        if base_segment * _PARAGRAPH_SIZE + len(self.image) > _REAL_MODE_SIZE:
            raise MZError("load module extends past the 1 MiB image limit")

        image = bytearray(self.image)
        for relocation in self.relocations:
            offset = relocation.linear
            value, = _WORD.unpack_from(image, offset)
            _WORD.pack_into(image, offset, (value + base_segment) & _SEGMENT_MASK)

        header = self.header
        entry = Address((base_segment + header.initial_cs) & _SEGMENT_MASK, header.initial_ip)
        stack = Address((base_segment + header.initial_ss) & _SEGMENT_MASK, header.initial_sp)
        return LoadedMZ(base_segment, bytes(image), entry, stack)


def _parse_relocations(data: bytes, header: MZHeader, image_size: int) -> tuple[Address, ...]:
    if header.relocation_count == 0:
        return ()

    start = header.relocation_offset
    end = start + header.relocation_count * _RELOCATION.size
    if start < _HEADER.size or end > header.header_size:
        raise MZError("MZ relocation table is outside the header")

    relocations = []
    for index, (offset, segment) in enumerate(_RELOCATION.iter_unpack(data[start:end])):
        address = Address(segment, offset)
        if address.linear + _WORD.size > image_size:
            raise MZError(f"MZ relocation {index} at {address} is outside the load module")
        relocations.append(address)
    return tuple(relocations)
