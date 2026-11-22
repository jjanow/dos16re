"""Identify DOS packers and recover their original load modules."""

import re
from io import BytesIO
from struct import Struct, unpack_from
from zlib import crc32

from .mz import Address, MZError, MZHeader

_WORD = Struct("<H")
_RELOC_LOOP = bytes.fromhex("0e 1f 8b 1e 04 00 fc 33")
_ERROR_MESSAGE = b"Packed file is corrupt"
_LZEXE_ENTRY_CRCS = {
    (0x4B6802C9, 0xCF419437): "LZEXE 0.90",
    (0x246655C5, 0x0AE99574): "LZEXE 0.91",
    (0xD8A60F13, 0x8F680F0C): "LZEXE 0.91e",
}
_PKLITE_ENTRY = re.compile(
    rb"(?:\xb8..\xba..(?:\x8c\xdb\x03\xd8\x3b|\x05\x00\x00\x3b\x06)"
    rb"|\x50\xb8..\xba..\x05\x00\x00\x3b)",
    re.DOTALL,
)


def detect_packer(header: MZHeader, extra_header: bytes, image: bytes) -> str | None:
    cs, = unpack_from("<h", _WORD.pack(header.initial_cs))
    entry = cs * 16 + header.initial_ip
    if entry < 0:
        entry = header.initial_cs * 16 + header.initial_ip
    if not 0 <= entry < len(image):
        return None

    stub = image[entry:entry + 400]
    if header.relocation_count == 0 and entry >= 2 and image[entry - 2:entry] == b"RB":
        if header.initial_ip in (16, 18, 20) and entry >= header.initial_ip:
            return "EXEPACK"
        if _RELOC_LOOP in stub or _ERROR_MESSAGE in stub:
            return "unknown EXEPACK variant"

    if header.relocation_count == 0:
        variant = _LZEXE_ENTRY_CRCS.get((crc32(stub[:32]), crc32(stub[32:64])))
        if variant:
            return variant
        if extra_header.startswith((b"LZ09", b"LZ90", b"LZ91")):
            return "unknown LZEXE variant"
    if cs == -16 and header.initial_ip == 0x100 and header.relocation_count <= 2:
        if extra_header[2:].startswith(b"PKLITE") or _PKLITE_ENTRY.match(stub):
            return "PKLITE"
    return None


def unpack_exepack(packed: bytes, decoder: Address) -> tuple[
    bytes, Address, Address, tuple[Address, ...]
]:
    # EXEPACK headers are 16, 18 or 20 bytes and end immediately before the decoder.
    start = decoder.segment * 16
    ip, cs, _, block_size = unpack_from("<4H", packed, start)
    sp, ss, paragraphs = unpack_from("<3H", packed, start + (10 if decoder.offset == 20 else 8))
    skip = _WORD.unpack_from(packed, decoder.linear - 4)[0] if decoder.offset >= 18 else 1
    if not 1 <= skip <= min(decoder.segment, paragraphs):
        raise MZError("invalid EXEPACK skip length")

    end = start + block_size
    if not decoder.linear + 32 <= end <= len(packed):
        raise MZError("EXEPACK header declares an invalid decoder size")
    skip_bytes = (skip - 1) * 16
    image = _expand(packed[:start - skip_bytes], paragraphs * 16 - skip_bytes)
    relocations = _read_relocations(packed, decoder.linear, start, end, len(image))
    return image, Address(cs, ip), Address(ss, sp), relocations


def _expand(source: bytes, size: int) -> bytes:
    src = len(source.rstrip(b"\xff"))
    dst = size
    image = bytearray(size)
    # The stream encodes the suffix in reverse order. Any remaining prefix is literal.
    while src >= 3:
        opcode = source[src - 1]
        count, = _WORD.unpack_from(source, src - 3)
        src -= 3
        if not 0xB0 <= opcode <= 0xB3 or count > dst:
            raise MZError("invalid EXEPACK compression record")
        dst -= count
        if opcode & 2:
            if count > src:
                raise MZError("truncated EXEPACK literal run")
            image[dst:dst + count] = source[src - count:src]
            src -= count
        else:
            if not src:
                raise MZError("truncated EXEPACK fill run")
            src -= 1
            image[dst:dst + count] = source[src:src + 1] * count
        if opcode & 1:
            if src != dst:
                raise MZError("EXEPACK records do not match the declared image size")
            image[:dst] = source[:src]
            return bytes(image)
    raise MZError("EXEPACK stream is missing its final record")


def _read_relocations(
    packed: bytes, entry: int, header_start: int, end: int, image_size: int,
) -> tuple[Address, ...]:
    # The decoder's relocation loop takes an immediate pointer to its table.
    # Some patched decoders retain only the error string as a usable marker.
    marker = packed.find(_RELOC_LOOP, entry + 2, end)
    candidates = []
    if marker >= 0:
        candidates.append(header_start + _WORD.unpack_from(packed, marker - 2)[0])
    message = packed.find(_ERROR_MESSAGE, entry, end)
    if message >= 0:
        candidates.append(message + len(_ERROR_MESSAGE))

    for start in candidates:
        if not entry < start <= end - 32:
            continue
        stream = BytesIO(packed[start:end])
        try:
            relocations = _page_relocations(stream)
        except MZError:
            continue
        if stream.tell() == end - start and all(
            address.linear + 2 <= image_size for address in relocations
        ):
            return relocations
    raise MZError("invalid or unrecognized EXEPACK relocation table")


def _read_word(stream: BytesIO) -> int:
    raw = stream.read(2)
    if len(raw) != 2:
        raise MZError("truncated packed DOS word")
    return _WORD.unpack(raw)[0]


def _page_relocations(stream: BytesIO) -> tuple[Address, ...]:
    relocations = []
    for page in range(16):
        size = _read_word(stream) * 2
        offsets = stream.read(size)
        if len(offsets) != size:
            raise MZError("truncated packed DOS relocation table")
        relocations.extend(
            Address(page * 0x1000, offset) for offset, in _WORD.iter_unpack(offsets)
        )
    return tuple(relocations)


def unpack_lzexe(packed: bytes, decoder: Address, variant: str) -> tuple[
    bytes, Address, Address, tuple[Address, ...]
]:
    header_start = decoder.segment * 16
    if header_start + 14 > len(packed):
        raise MZError("truncated LZEXE header")
    ip, cs, sp, ss, compressed_paragraphs, _, decoder_size = unpack_from(
        "<7H", packed, header_start
    )
    compressed_start = header_start - compressed_paragraphs * 16
    if not 0 <= compressed_start < header_start:
        raise MZError("invalid LZEXE compressed image size")
    image = _expand_lzexe(BytesIO(packed[compressed_start:header_start]))
    version_90 = variant == "LZEXE 0.90"
    reloc_start = header_start + (0x19D if version_90 else 0x158)
    reloc_end = header_start + decoder_size
    if not reloc_start < reloc_end <= len(packed):
        raise MZError("invalid LZEXE relocation table bounds")
    stream = BytesIO(packed[reloc_start:reloc_end])
    relocations = _page_relocations(stream) if version_90 else _lzexe_deltas(stream, len(image))
    if any(address.linear + 2 > len(image) for address in relocations):
        raise MZError("LZEXE relocation outside the load module")
    return image, Address(cs, ip), Address(ss, sp), relocations


def _read_byte(stream: BytesIO) -> int:
    raw = stream.read(1)
    if not raw:
        raise MZError("truncated LZEXE stream")
    return raw[0]


def _lzexe_deltas(stream: BytesIO, image_size: int) -> tuple[Address, ...]:
    relocations = []
    linear = 0
    while True:
        delta = _read_byte(stream)
        if delta == 0:
            delta = _read_word(stream)
            if delta == 1:
                return tuple(relocations)
            if delta == 0:
                linear += 0xFFF0
                continue
        linear += delta
        if linear + 2 > image_size:
            raise MZError("LZEXE relocation outside the load module")
        relocations.append(Address(*divmod(linear, 16)))


def _expand_lzexe(stream: BytesIO) -> bytes:
    control = _read_word(stream)
    bits_remaining = 16

    def bit() -> int:
        nonlocal control, bits_remaining
        value = control & 1
        control >>= 1
        bits_remaining -= 1
        # The decoder fetches the next control word before reading token data.
        if not bits_remaining:
            control = _read_word(stream)
            bits_remaining = 16
        return value

    image = bytearray()
    while True:
        if bit():
            if len(image) == 0x100000:
                raise MZError("LZEXE image exceeds the 1 MiB limit")
            image.append(_read_byte(stream))
            continue
        if bit():
            low, high = _read_byte(stream), _read_byte(stream)
            distance = 0x2000 - ((high & 0xF8) << 5 | low)
            count = (high & 7) + 2
            if count == 2:
                extended = _read_byte(stream)
                if extended == 0:
                    return bytes(image)
                if extended == 1:
                    continue
                count = extended + 1
        else:
            count = (bit() << 1 | bit()) + 2
            distance = 0x100 - _read_byte(stream)
        if distance > len(image) or len(image) + count > 0x100000:
            raise MZError("invalid LZEXE back-reference")
        for _ in range(count):
            image.append(image[-distance])
