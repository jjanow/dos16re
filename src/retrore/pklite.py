"""Statically decompress standard PKLITE DOS code images and relocation tables."""

import re
from io import BytesIO
from struct import Struct

from .mz import Address, MZError, MZHeader, UnsupportedPacker

# Format reconstructions by Jason Summers:
# https://entropymine.wordpress.com/2022/01/16/notes-on-pklite-format-part-3/
# https://entropymine.wordpress.com/2023/05/11/notes-on-pklite-format-part-6-v1-20-compression/
_WORD = Struct("<H")
_HEADER_FIELDS = Struct("<13H")
_FOOTER = Struct("<4H")
_SPECIAL, _FAR_PAIR, _ZERO = -1, -2, -3
_SMALL_LENGTHS = dict(zip("010 00 100 101 1100 1101 1110 1111 011".split(), (*range(2, 10), _SPECIAL)))
_LARGE_LENGTHS = dict(zip(("10 11 000 0010 0011 0100 01010 01011 01100 011010 011011 0111010 "
                           "0111011 0111100 01111010 01111011 01111100 011111010 011111011 011111100 "
                           "011111101 011111110 011111111 011100").split(), (*range(2, 25), _SPECIAL)))
_LARGE_120_LENGTHS = dict(zip(("10 11 000 0101 0110 00110 00111 001000 001001 0100000 0100001 0100010 "
                               "0100011 01001000 01001001 01001010 010010110 010010111 010011 0111 00101").split(),
                              (*range(2, 20), _SPECIAL, _FAR_PAIR, _ZERO)))
_SMALL_120_LENGTHS = dict(zip("10 11 000 0100 0101 01110 011110 011111 0110 0011 0010".split(),
                              (*range(2, 10), _SPECIAL, _FAR_PAIR, _ZERO)))
_OFFSET_SUFFIX = [f"{code:07b}" for code in range(48, 64)]
_OFFSETS = dict(zip("1 0000 0001 00100 00101 00110 00111 010000 010001 010010 010011 010100 010101 010110 0101110 0101111"
                    .split() + _OFFSET_SUFFIX, range(32)))
_OFFSETS_120 = dict(zip("1 000 00100 00101 00110 00111 010000 010001 010010 010011 010100 010101 0101100 0101101 0101110 0101111"
                        .split() + _OFFSET_SUFFIX, range(32)))
_EXE_DECODER = re.compile(rb"\xfd\x8c\xdb\x53(?:(?:\x83\xc3(.))|(?:\x81\xc3(..)))", re.DOTALL)
_EXE_120_DECODER = re.compile(rb"\xfd\x5f(?:\xc7\x85....)?\x4f\x4f\xbe(..)\x03\xf2\x8b\xca\xd1\xe9\xf3",
                              re.DOTALL)
_COM_DECODERS = tuple((re.compile(pattern, re.DOTALL), version, start) for pattern, version, start in (
    (rb"\xba..\xa1\x02\x00\x2d\x20\x06\x8c\xcb", 36, 500),
    (rb"\xb8..\xba..\x3b\xc4\x73\x67\x8b", 44, 448),
    (rb"\xb8..\xba..\x3b\xc4\x73\x69\x8b", 46, 450),
    (rb"\x50\xb8..\xba..\x3b\xc4\x73\x79", 46, 464),
))


def _read(stream: BytesIO, size: int) -> bytes:
    value = stream.read(size)
    if len(value) != size:
        raise MZError("truncated PKLITE stream")
    return value


class _BitStream:
    def __init__(self, stream: BytesIO):
        self.stream = stream
        self._fill()

    def _fill(self) -> None:
        self.word, = _WORD.unpack(_read(self.stream, 2))
        self.remaining = 16

    def bit(self) -> str:
        bit = self.word & 1
        self.word >>= 1
        self.remaining -= 1
        if not self.remaining:
            self._fill()
        return "1" if bit else "0"

    def prefix(self, table: dict[str, int]) -> int:
        prefix = ""
        for _ in range(9):
            prefix += self.bit()
            if prefix in table:
                return table[prefix]
        raise MZError("invalid PKLITE prefix code")


def _expand(stream: BytesIO, *, large: bool = False, extra: bool = False, version_120: bool = False,
            limit: int = 0x100000) -> bytes:
    if version_120:
        lengths = _LARGE_120_LENGTHS if large else _SMALL_120_LENGTHS
        offsets = _OFFSETS_120
    else:
        lengths = _LARGE_LENGTHS if large else _SMALL_LENGTHS
        offsets = _OFFSETS
    bias = (20 if version_120 else 25) if large else 10
    bits = _BitStream(stream)
    output = bytearray()
    while True:
        if bits.bit() == "0":
            value = _read(stream, 1)[0]
            output.append(value ^ bits.remaining if extra else value)
        else:
            length = bits.prefix(lengths)
            if length == _SPECIAL:
                size = _read(stream, 1)[0]
                if size == 0xFF:
                    return bytes(output)
                if size == 0xFE and large:
                    continue
                if size > 0xFC:
                    raise UnsupportedPacker("PKLITE uncompressed-area variant")
                length = size + bias
            if length == _ZERO:
                output.append(0)
            else:
                high = 1 if length == _FAR_PAIR else 0 if length == 2 else bits.prefix(offsets)
                distance = high * 256 + _read(stream, 1)[0]
                if not 0 < distance <= len(output):
                    raise MZError(f"invalid PKLITE match distance {distance}")
                for _ in range(2 if length == _FAR_PAIR else length):
                    output.append(output[-distance])
        if len(output) > limit:
            raise MZError("decompressed PKLITE image exceeds the DOS image limit")


def _relocations(stream: BytesIO, image_size: int, extra: bool) -> tuple[Address, ...]:
    entries = []
    segment = 0
    while True:
        if extra:
            count, = _WORD.unpack(_read(stream, 2))
            if count == 0xFFFF:
                break
            if segment > 0xFFFF:
                raise MZError("PKLITE relocation table exceeds the DOS address space")
        else:
            count = _read(stream, 1)[0]
            if not count:
                break
            segment, = _WORD.unpack(_read(stream, 2))
        if len(entries) + count > 0xFFFF:
            raise MZError("PKLITE relocation count exceeds the MZ limit")
        for offset, in _WORD.iter_unpack(_read(stream, count * 2)):
            address = Address(segment, offset)
            if address.linear + 2 > image_size:
                raise MZError(f"PKLITE relocation {address} is outside the load module")
            entries.append(address)
        segment += 0x0FFF
    return tuple(entries)


def _version(value: int) -> str:
    return f"PKLITE {(value >> 8) & 0xF}.{value & 0xFF:02d}"


def _original_header(data: bytes, header: MZHeader) -> MZHeader | None:
    start = header.relocation_offset + header.relocation_count * 4
    if not 0x1E <= start <= len(data) - _HEADER_FIELDS.size:
        return None
    original = MZHeader(*_HEADER_FIELDS.unpack_from(data, start))
    if (original.page_count and original.last_page_bytes <= 511 and
            0x1C <= original.header_size < original.file_size):
        return original
    return None


def unpack_pklite(packed: bytes, packed_header: bytes, header: MZHeader) -> tuple[
    bytes, Address, Address, tuple[Address, ...], int, str,
]:
    if len(packed_header) <= 0x1F:
        raise UnsupportedPacker("PKLITE")
    version, = _WORD.unpack_from(packed_header, 0x1C)
    number = version & 0x0FFF
    if number not in (*range(0x100, 0x110), 0x114, 0x132, 0x201) or version & 0xC000:
        raise UnsupportedPacker(_version(version) if (version >> 8) & 0xF else "PKLITE")
    large, extra = bool(version & 0x2000), bool(version & 0x1000)
    version_120 = number == 0x114
    entry_cs = header.initial_cs - 0x10000 if header.initial_cs >= 0x8000 else header.initial_cs
    entry = entry_cs * 16 + header.initial_ip
    if not 0 <= entry < len(packed):
        raise UnsupportedPacker(_version(version))

    starts = set()
    for match in _EXE_DECODER.finditer(packed, entry, entry + 768):
        offset = int.from_bytes(match[1] or match[2], "little") * 16 + entry - header.initial_ip
        if match.end() <= offset < len(packed):
            starts.add(offset)
    for match in _EXE_120_DECODER.finditer(packed, entry, entry + 768):
        offset = int.from_bytes(match[1], "little") + 2 + entry - header.initial_ip
        if match.end() <= offset < len(packed):
            starts.add(offset)
    # Early registered versions scramble the decoder, but use stable data offsets.
    if not starts and extra and 0x100 <= number <= 0x10F and packed_header[0x1E:0x24].lower() == b"pklite":
        minor = number & 0xFF
        if large:
            offset = 704 if minor >= 14 else 656 if minor >= 12 else 672
        else:
            offset = 512 if minor >= 14 else 480
        if offset < len(packed):
            starts.add(offset)
    if not starts:
        raise UnsupportedPacker(_version(version))

    original = None if extra else _original_header(packed_header, header)
    results = []
    errors = []
    for start in sorted(starts):
        stream = BytesIO(packed)
        stream.seek(start)
        try:
            image = _expand(stream, large=large, extra=extra, version_120=version_120)
            relocations = _relocations(stream, len(image), extra)
            ss, sp, cs, ip = _FOOTER.unpack(_read(stream, _FOOTER.size))
            relative_entry = Address(cs if cs < 0x8000 else cs - 0x10000, ip)
            if not 0 <= relative_entry.linear < len(image):
                raise MZError("PKLITE entry is outside the decompressed image")
            if original is not None and (
                original.file_size - original.header_size != len(image) or
                original.relocation_count != len(relocations) or
                (original.initial_ss, original.initial_sp, original.initial_cs, original.initial_ip) != (ss, sp, cs, ip)
            ):
                raise MZError("PKLITE decoded image disagrees with the preserved original MZ header")
            min_alloc = original.min_alloc_paragraphs if original else 0
            results.append((image, Address(cs, ip), Address(ss, sp), relocations, min_alloc, _version(version)))
        except MZError as error:
            errors.append(error)
    if len(results) > 1:
        raise MZError("ambiguous PKLITE compressed data offsets")
    if not results:
        raise errors[0]
    return results[0]


def unpack_pklite_com(data: bytes, limit: int) -> tuple[bytes, str | None]:
    for pattern, version, start in _COM_DECODERS:
        if pattern.match(data) and data[version + 2:version + 4].lower() == b"pk":
            label = _version(_WORD.unpack_from(data, version)[0])
            stream = BytesIO(data)
            stream.seek(start)
            return _expand(stream, limit=limit), label
    return data, None
