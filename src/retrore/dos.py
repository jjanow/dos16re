"""Load DOS real-mode programs and locate embedded overlay members."""

from dataclasses import replace
from struct import pack_into

from .dos_overlays import embedded_overlays
from .mz import Address, DEFAULT_BASE_SEGMENT, LoadedMZ, MZError, MZExecutable, read_mz_header
from .overlays import LinkedOverlay
from .pklite import unpack_pklite_com

_PSP_SIZE = 0x100
_INITIAL_SP = 0xFFFE


def load_dos_flat(data: bytes, base_segment: int = DEFAULT_BASE_SEGMENT, *, com: bool,
                  offset: int | None = None, entry: int | None = None) -> LoadedMZ:
    """Use one 64 KiB segment for the image and its default stack."""
    if not 0 <= base_segment <= 0xF000:
        raise MZError("the DOS load segment must leave room for a 64 KiB allocation within the first MiB")
    if com and (offset is not None or entry is not None):
        raise MZError("--dos-offset and --dos-entry require --dos-raw")

    start = _PSP_SIZE if com else (0 if offset is None else offset)
    if not 0 <= start < _INITIAL_SP:
        raise MZError("DOS load offset must leave room for the image and its initial stack word")
    data, packer = unpack_pklite_com(data, _INITIAL_SP - start) if com else (data, None)
    if not 0 < len(data) <= _INITIAL_SP - start:
        raise MZError(f"DOS {'COM' if com else 'raw'} image at offset {start:04x} must contain "
                      f"1 to {_INITIAL_SP - start} bytes")
    entry_offset = start if entry is None else entry
    if not start <= entry_offset < start + len(data):
        raise MZError("DOS entry offset must point inside the input bytes")

    prefix = bytearray(start)
    if com:
        # Minimal DOS PSP. Process-specific environment and interrupt vectors are left zero.
        prefix[0:2] = b"\xcd\x20"
        pack_into("<H", prefix, 2, (base_segment + 0x1000) & 0xFFFF)
        prefix[0x50:0x53] = b"\xcd\x21\xcb"
        prefix[0x81] = 0x0D
    return LoadedMZ(base_segment, bytes(prefix) + data, Address(base_segment, entry_offset),
                    Address(base_segment, _INITIAL_SP), packer=packer,
                    dos_format="COM" if com else "RAW", load_offset=start)


def load_dos_mz(data: bytes, base_segment: int, source: str) -> tuple[LoadedMZ, list[LinkedOverlay]]:
    header = read_mz_header(data)
    if header.overlay_number:
        raise MZError(f"MZ member is overlay {header.overlay_number}; pass the complete executable")
    executable = MZExecutable.parse(data)
    loaded = executable.load(base_segment)
    overlays, diagnostics = embedded_overlays(data, executable, source, base_segment)
    toolchain = None
    # Borland's header generation is independent of the TLINK banner version.
    if (0x22 <= header.relocation_offset <= header.header_size
            and data[0x1C:0x1F] == b"\x01\x00\xfb" and data[0x20:0x22] in (b"\x6a\x72", b"\x72\x6a")):
        generation = data[0x1F]
        toolchain = {"family": "Borland TLINK", "header_version": f"{generation >> 4}.{generation & 15}",
                     "evidence": "extended MZ header", "file_offset": 0x1C}
    return replace(loaded, diagnostics=tuple(diagnostics), toolchain=toolchain), overlays
