"""Export Sharp X68000 Human68k `.X` executables as flat, relocated 68k images."""

from collections.abc import Iterator
from struct import Struct, pack_into, unpack_from

from .image import DEFAULT_M68K_BASE, M68K_ADDRESS_LIMIT, X68K_FORMAT

X_MAGIC = b"HU"
# Magic, reserved byte, load mode, link base, entry, TEXT, DATA, BSS, relocation and symbol table sizes.
_HEADER = Struct(">2sBBIIIIIII")
HEADER_SIZE = 0x40
_LOAD_MODES = {0: "normal", 1: "smallest", 2: "high"}
# Symbol types in the XC/HLK symbol table. Common symbols are allocated after BSS.
_SYMBOL_UNITS = {0x0201: "text", 0x0202: "data", 0x0203: "bss", 0x0003: "bss"}

# Human68k DOS calls ($FFxx) and FLOAT2/FPACK calls ($FExx) are line-F words that the 68000 executes as
# exceptions. Names follow the SHARP/Hudson include files; $FF50-$FF7F use the Human68k 2.x numbers.
DOS_CALLS = {
    0x00: "_EXIT", 0x01: "_GETCHAR", 0x02: "_PUTCHAR", 0x03: "_COMINP", 0x04: "_COMOUT", 0x05: "_PRNOUT",
    0x06: "_INPOUT", 0x07: "_INKEY", 0x08: "_GETC", 0x09: "_PRINT", 0x0A: "_GETS", 0x0B: "_KEYSNS", 0x0C: "_KFLUSH",
    0x0D: "_FFLUSH", 0x0E: "_CHGDRV", 0x0F: "_DRVCTRL", 0x10: "_CONSNS", 0x11: "_PRNSNS", 0x12: "_CINSNS",
    0x13: "_COUTSNS", 0x17: "_FATCHK", 0x18: "_HENDSP", 0x19: "_CURDRV", 0x1A: "_GETSS", 0x1B: "_FGETC",
    0x1C: "_FGETS", 0x1D: "_FPUTC", 0x1E: "_FPUTS", 0x1F: "_ALLCLOSE", 0x20: "_SUPER", 0x21: "_FNCKEY",
    0x22: "_KNJCTRL", 0x23: "_CONCTRL", 0x24: "_KEYCTRL", 0x25: "_INTVCS", 0x26: "_PSPSET", 0x27: "_GETTIM2",
    0x28: "_SETTIM2", 0x29: "_NAMESTS", 0x2A: "_GETDATE", 0x2B: "_SETDATE", 0x2C: "_GETTIME", 0x2D: "_SETTIME",
    0x2E: "_VERIFY", 0x2F: "_DUP0", 0x30: "_VERNUM", 0x31: "_KEEPPR", 0x32: "_GETDPB", 0x33: "_BREAKCK",
    0x34: "_DRVXCHG", 0x35: "_INTVCG", 0x36: "_DSKFRE", 0x37: "_NAMECK", 0x39: "_MKDIR", 0x3A: "_RMDIR",
    0x3B: "_CHDIR", 0x3C: "_CREATE", 0x3D: "_OPEN", 0x3E: "_CLOSE", 0x3F: "_READ", 0x40: "_WRITE", 0x41: "_DELETE",
    0x42: "_SEEK", 0x43: "_CHMOD", 0x44: "_IOCTRL", 0x45: "_DUP", 0x46: "_DUP2", 0x47: "_CURDIR", 0x48: "_MALLOC",
    0x49: "_MFREE", 0x4A: "_SETBLOCK", 0x4B: "_EXEC", 0x4C: "_EXIT2", 0x4D: "_WAIT", 0x4E: "_FILES",
    0x4F: "_NFILES", 0x50: "_SETPDB", 0x51: "_GETPDB", 0x52: "_SETENV", 0x53: "_GETENV", 0x54: "_VERIFYG",
    0x55: "_COMMON", 0x56: "_RENAME", 0x57: "_FILEDATE", 0x58: "_MALLOC2", 0x5A: "_MAKETMP", 0x5B: "_NEWFILE",
    0x5C: "_LOCK", 0x5F: "_ASSIGN", 0x7A: "_FFLUSH_SET", 0x7B: "_OS_PATCH", 0x7C: "_GETFCB", 0x7D: "_S_MALLOC",
    0x7E: "_S_MFREE", 0x7F: "_S_PROCESS", 0x80: "_SETPDB", 0x81: "_GETPDB", 0x82: "_SETENV", 0x83: "_GETENV",
    0x84: "_VERIFYG", 0x85: "_COMMON", 0x86: "_RENAME", 0x87: "_FILEDATE", 0x88: "_MALLOC2", 0x8A: "_MAKETMP",
    0x8B: "_NEWFILE", 0x8C: "_LOCK", 0x8F: "_ASSIGN", 0xA0: "_MALLOC3", 0xA1: "_SETBLOCK2", 0xA2: "_MALLOC4",
    0xA3: "_S_MALLOC2", 0xAA: "_FFLUSH_SET", 0xAB: "_OS_PATCH", 0xAC: "_GETFCB", 0xAD: "_S_MALLOC",
    0xAE: "_S_MFREE", 0xAF: "_S_PROCESS", 0xF0: "_EXITVC", 0xF1: "_CTRLVC", 0xF2: "_ERRJVC", 0xF3: "_DISKRED",
    0xF4: "_DISKWRT", 0xF5: "_INDOSFLG", 0xF6: "_SUPER_JSR", 0xF7: "_BUS_ERR", 0xF8: "_OPEN_PR", 0xF9: "_KILL_PR",
    0xFA: "_GET_PR", 0xFB: "_SUSPEND_PR", 0xFC: "_SLEEP_PR", 0xFD: "_SEND_PR", 0xFE: "_TIME_PR",
    0xFF: "_CHANGE_PR",
}
FPACK_CALLS = {
    0x00: "__LMUL", 0x01: "__LDIV", 0x02: "__LMOD", 0x04: "__UMUL", 0x05: "__UDIV", 0x06: "__UMOD", 0x08: "__IMUL",
    0x09: "__IDIV", 0x0C: "__RANDOMIZE", 0x0D: "__SRAND", 0x0E: "__RAND", 0x10: "__STOL", 0x11: "__LTOS",
    0x12: "__STOH", 0x13: "__HTOS", 0x14: "__STOO", 0x15: "__OTOS", 0x16: "__STOB", 0x17: "__BTOS",
    0x18: "__IUSING", 0x1A: "__LTOD", 0x1B: "__DTOL", 0x1C: "__LTOF", 0x1D: "__FTOL", 0x1E: "__FTOD",
    0x1F: "__DTOF", 0x20: "__VAL", 0x21: "__USING", 0x22: "__STOD", 0x23: "__DTOS", 0x24: "__ECVT", 0x25: "__FCVT",
    0x26: "__GCVT", 0x28: "__DTST", 0x29: "__DCMP", 0x2A: "__DNEG", 0x2B: "__DADD", 0x2C: "__DSUB", 0x2D: "__DMUL",
    0x2E: "__DDIV", 0x2F: "__DMOD", 0x30: "__DABS", 0x31: "__DCEIL", 0x32: "__DFIX", 0x33: "__DFLOOR",
    0x34: "__DFRAC", 0x35: "__DSGN", 0x36: "__SIN", 0x37: "__COS", 0x38: "__TAN", 0x39: "__ATAN", 0x3A: "__LOG",
    0x3B: "__EXP", 0x3C: "__SQR", 0x3D: "__PI", 0x3E: "__NPI", 0x3F: "__POWER", 0x40: "__RND", 0x41: "__SINH",
    0x42: "__COSH", 0x43: "__TANH", 0x44: "__ATANH", 0x45: "__ASIN", 0x46: "__ACOS", 0x47: "__LOG10",
    0x48: "__LOG2", 0x49: "__DFREXP", 0x4A: "__DLDEXP", 0x4B: "__DADDONE", 0x4C: "__DSUBONE", 0x4D: "__DDIVTWO",
    0x4E: "__DIEECNV", 0x4F: "__IEEDCNV", 0x50: "__FVAL", 0x51: "__FUSING", 0x52: "__STOF", 0x53: "__FTOS",
    0x54: "__FECVT", 0x55: "__FFCVT", 0x56: "__FGCVT", 0x58: "__FTST", 0x59: "__FCMP", 0x5A: "__FNEG",
    0x5B: "__FADD", 0x5C: "__FSUB", 0x5D: "__FMUL", 0x5E: "__FDIV", 0x5F: "__FMOD", 0x60: "__FABS",
    0x61: "__FCEIL", 0x62: "__FFIX", 0x63: "__FFLOOR", 0x64: "__FFRAC", 0x65: "__FSGN", 0x66: "__FSIN",
    0x67: "__FCOS", 0x68: "__FTAN", 0x69: "__FATAN", 0x6A: "__FLOG", 0x6B: "__FEXP", 0x6C: "__FSQR", 0x6D: "__FPI",
    0x6E: "__FNPI", 0x6F: "__FPOWER", 0x70: "__FRND", 0x71: "__FSINH", 0x72: "__FCOSH", 0x73: "__FTANH",
    0x74: "__FATANH", 0x75: "__FASIN", 0x76: "__FACOS", 0x77: "__FLOG10", 0x78: "__FLOG2", 0x79: "__FFREXP",
    0x7A: "__FLDEXP", 0x7B: "__FADDONE", 0x7C: "__FSUBONE", 0x7D: "__FDIVTWO", 0x7E: "__FIEECNV",
    0x7F: "__IEEFCNV", 0xE0: "__CLMUL", 0xE1: "__CLDIV", 0xE2: "__CLMOD", 0xE3: "__CUMUL", 0xE4: "__CUDIV",
    0xE5: "__CUMOD", 0xE6: "__CLTOD", 0xE7: "__CDTOL", 0xE8: "__CLTOF", 0xE9: "__CFTOL", 0xEA: "__CFTOD",
    0xEB: "__CDTOF", 0xEC: "__CDCMP", 0xED: "__CDADD", 0xEE: "__CDSUB", 0xEF: "__CDMUL", 0xF0: "__CDDIV",
    0xF1: "__CDMOD", 0xF2: "__CFCMP", 0xF3: "__CFADD", 0xF4: "__CFSUB", 0xF5: "__CFMUL", 0xF6: "__CFDIV",
    0xF7: "__CFMOD", 0xF8: "__CDTST", 0xF9: "__CFTST", 0xFA: "__CDINC", 0xFB: "__CFINC", 0xFC: "__CDDEC",
    0xFD: "__CFDEC", 0xFE: "__FEVARG", 0xFF: "__FEVECS",
}
# Stock X68000 address map (24-bit bus). Programs load in main RAM; the rest is video, I/O, SRAM, and ROM.
MEMORY_MAP = (
    (0x000000, 0xC00000, "main_ram", "ram"), (0xC00000, 0xE00000, "gvram", "ram"), (0xE00000, 0xE80000, "tvram", "ram"),
    (0xE80000, 0xE82000, "crtc", "io"), (0xE82000, 0xE84000, "vicon", "io"), (0xE84000, 0xE86000, "dmac", "io"),
    (0xE86000, 0xE88000, "areaset", "io"), (0xE88000, 0xE8A000, "mfp", "io"), (0xE8A000, 0xE8C000, "rtc", "io"),
    (0xE8C000, 0xE8E000, "printer", "io"), (0xE8E000, 0xE90000, "sysport", "io"), (0xE90000, 0xE92000, "opm", "io"),
    (0xE92000, 0xE94000, "adpcm", "io"), (0xE94000, 0xE96000, "fdc", "io"), (0xE96000, 0xE98000, "hdc", "io"),
    (0xE98000, 0xE9A000, "scc", "io"), (0xE9A000, 0xE9C000, "ppi", "io"), (0xE9C000, 0xE9E000, "ioi", "io"),
    (0xE9E000, 0xEB0000, "expansion_io", "io"), (0xEB0000, 0xEC0000, "sprite", "io"),
    (0xEC0000, 0xED0000, "user_io", "io"), (0xED0000, 0xED4000, "sram", "ram"), (0xF00000, 0xFC0000, "cgrom", "rom"),
    (0xFC0000, 0x1000000, "rom", "rom"),
)
# Registers named in the SHARP/Hudson-style include files distributed with the XEiJ emulator.
HARDWARE_LABELS = (
    (0xE80000, "CRTC_H_FRONT_END"), (0xE80002, "CRTC_H_SYNC_END"), (0xE80004, "CRTC_H_BACK_END"),
    (0xE80006, "CRTC_H_DISP_END"), (0xE80008, "CRTC_V_FRONT_END"), (0xE8000A, "CRTC_V_SYNC_END"),
    (0xE8000C, "CRTC_V_BACK_END"), (0xE8000E, "CRTC_V_DISP_END"), (0xE80010, "CRTC_ADJUST"),
    (0xE80012, "CRTC_RASTER"), (0xE80014, "CRTC_TEXT_X"), (0xE80016, "CRTC_TEXT_Y"), (0xE80018, "CRTC_GRAPHIC_X_0"),
    (0xE8001A, "CRTC_GRAPHIC_Y_0"), (0xE8001C, "CRTC_GRAPHIC_X_1"), (0xE8001E, "CRTC_GRAPHIC_Y_1"),
    (0xE80020, "CRTC_GRAPHIC_X_2"), (0xE80022, "CRTC_GRAPHIC_Y_2"), (0xE80024, "CRTC_GRAPHIC_X_3"),
    (0xE80026, "CRTC_GRAPHIC_Y_3"), (0xE80028, "CRTC_MODE_RESOLUTION"), (0xE80029, "CRTC_RESOLUTION_BYTE"),
    (0xE8002A, "CRTC_ACCESS"), (0xE8002C, "CRTC_BLOCK"), (0xE8002E, "CRTC_MASK"), (0xE80030, "CRTC_R24"),
    (0xE80480, "CRTC_ACTION"), (0xE82000, "VICON_GPALET"), (0xE82200, "VICON_TSPALET"),
    (0xE82400, "VICON_MEMORY_MODE"), (0xE82500, "VICON_PRIORITY"), (0xE82600, "VICON_VISIBLE"),
    (0xE84000, "DMAC_0_BASE"), (0xE84040, "DMAC_1_BASE"), (0xE84080, "DMAC_2_BASE"), (0xE840C0, "DMAC_3_BASE"),
    (0xE86001, "AREASET_0"), (0xE88001, "MFP_GPDR"), (0xE88003, "MFP_AER"), (0xE88005, "MFP_DDR"),
    (0xE88007, "MFP_IERA"), (0xE88009, "MFP_IERB"), (0xE8800B, "MFP_IPRA"), (0xE8800D, "MFP_IPRB"),
    (0xE8800F, "MFP_ISRA"), (0xE88011, "MFP_ISRB"), (0xE88013, "MFP_IMRA"), (0xE88015, "MFP_IMRB"),
    (0xE88017, "MFP_VECTOR"), (0xE88019, "MFP_TACR"), (0xE8801B, "MFP_TBCR"), (0xE8801D, "MFP_TCDCR"),
    (0xE8801F, "MFP_TADR"), (0xE88021, "MFP_TBDR"), (0xE88023, "MFP_TCDR"), (0xE88025, "MFP_TDDR"),
    (0xE88027, "MFP_SYNC_CHAR"), (0xE88029, "MFP_UCR"), (0xE8802B, "MFP_RSR"), (0xE8802D, "MFP_TSR"),
    (0xE8802F, "MFP_UDR"), (0xE8A001, "RTC_0_ONE_SECOND"), (0xE8A003, "RTC_0_TEN_SECONDS"),
    (0xE8A005, "RTC_0_ONE_MINUTE"), (0xE8A007, "RTC_0_TEN_MINUTES"), (0xE8A009, "RTC_0_ONE_HOUR"),
    (0xE8A00B, "RTC_0_TEN_HOURS"), (0xE8A00D, "RTC_0_DAY_OF_WEEK"), (0xE8A00F, "RTC_0_ONE_DAY"),
    (0xE8A011, "RTC_0_TEN_DAYS"), (0xE8A013, "RTC_0_ONE_MONTH"), (0xE8A015, "RTC_0_TEN_MONTHS"),
    (0xE8A017, "RTC_0_ONE_YEAR"), (0xE8A019, "RTC_0_TEN_YEARS"), (0xE8A01B, "RTC_MODE"), (0xE8A01D, "RTC_TEST"),
    (0xE8A01F, "RTC_RESET"), (0xE8C001, "PRN_DATA"), (0xE8C003, "PRN_STROBE"), (0xE8E001, "SYSPORT_CONTRAST"),
    (0xE8E003, "SYSPORT_TV"), (0xE8E005, "SYSPORT_VIDEO"), (0xE8E007, "SYSPORT_MISC"), (0xE8E009, "SYSPORT_WAIT"),
    (0xE8E00B, "SYSPORT_MODEL"), (0xE8E00D, "SYSPORT_SRAM"), (0xE8E00F, "SYSPORT_POWER"), (0xE90001, "OPM_ADDRESS"),
    (0xE90003, "OPM_DATA"), (0xE92001, "ADPCM_STATUS"), (0xE92003, "ADPCM_DATA"), (0xE94001, "FDC_STATUS"),
    (0xE94003, "FDC_DATA"), (0xE94005, "FDD_STATUS"), (0xE94007, "FDD_CONTROL"), (0xE96001, "HDC_DATA"),
    (0xE96003, "HDC_STATUS"), (0xE96005, "HDC_RESET"), (0xE96007, "HDC_SELECTION"), (0xE96020, "SPC_IN_BASE"),
    (0xE98001, "SCC_B_COMMAND"), (0xE98003, "SCC_B_DATA"), (0xE98005, "SCC_A_COMMAND"), (0xE98007, "SCC_A_DATA"),
    (0xE9A001, "PPI_PORT_A"), (0xE9A003, "PPI_PORT_B"), (0xE9A005, "PPI_PORT_C"), (0xE9A007, "PPI_CONTROL"),
    (0xE9C001, "IOI_STATUS"), (0xE9C003, "IOI_VECTOR"), (0xEA0000, "SPC_EX_BASE"), (0xEA0020, "SCSI_HANDLE_EX"),
    (0xEAFF81, "AREASET_2"), (0xEAFF83, "AREASET_4"), (0xEAFF85, "AREASET_6"), (0xEAFF87, "AREASET_8"),
    (0xEAFF89, "AREASET_A"), (0xEB0000, "SPRC_SCROLL"), (0xEB0400, "SPRC_SCROLL_128"), (0xEB0800, "SPRC_BG_0_X"),
    (0xEB0802, "SPRC_BG_0_Y"), (0xEB0804, "SPRC_BG_1_X"), (0xEB0806, "SPRC_BG_1_Y"), (0xEB0808, "SPRC_CONTROL"),
    (0xEB080A, "SPRC_H_FRONT_END"), (0xEB080C, "SPRC_H_BACK_END"), (0xEB080E, "SPRC_V_BACK_END"),
    (0xEB0810, "SPRC_RESOLUTION"), (0xEB0812, "SPRC_BANK_CONTROL"), (0xEB0814, "SPRC_BANK_NUMBER"),
    (0xEB4000, "SPRC_BANK_TEXT_0"), (0xEB6000, "SPRC_BANK_TEXT_1"), (0xEB8000, "SPRC_PATTERN"),
    (0xEBC000, "SPRC_TEXT_0"), (0xEBE000, "SPRC_TEXT_1"),
)
# Calls after which control does not return to the caller.
DOS_NO_RETURN = (0x00, 0x31, 0x4C)

# Stacked DOS call arguments, first (last pushed, lowest address) first: (name, type, size in bytes).
# Callers push words with move.w and longs with move.l or pea, so the layout is packed without padding.
# Widths follow call sites in XC's library and the XEiJ sample sources; mode-dependent calls list only the
# fixed prefix and are variadic. Every call returns in D0.
_W = 2
_L = 4
_NAME = ("name", "char*", _L)
_HANDLE = ("handle", "short", _W)
_BUFFER = ("buffer", "void*", _L)
DOS_PARAMETERS: dict[int, tuple[tuple[tuple[str, str, int], ...], str, bool]] = {
    0x00: ((), "int", False), 0x01: ((), "int", False), 0x02: ((("code", "short", _W),), "int", False),
    0x03: ((), "int", False), 0x04: ((("code", "short", _W),), "int", False),
    0x05: ((("code", "short", _W),), "int", False), 0x06: ((("code", "short", _W),), "int", False),
    0x07: ((), "int", False), 0x08: ((), "int", False), 0x09: ((("string", "char*", _L),), "int", False),
    0x0A: ((_BUFFER,), "int", False), 0x0B: ((), "int", False), 0x0C: ((("mode", "short", _W),), "int", True),
    0x0D: ((), "int", False), 0x0E: ((("drive", "short", _W),), "int", False),
    0x0F: ((("mode_drive", "short", _W),), "int", True), 0x10: ((), "int", False), 0x11: ((), "int", False),
    0x12: ((), "int", False), 0x13: ((), "int", False), 0x19: ((), "int", False),
    0x1B: ((_HANDLE,), "int", False), 0x1C: ((_BUFFER, _HANDLE), "int", False),
    0x1D: ((("code", "short", _W), _HANDLE), "int", False), 0x1E: ((("string", "char*", _L), _HANDLE), "int", False),
    0x1F: ((), "int", False), 0x20: ((("stack", "void*", _L),), "int", False),
    0x23: ((("mode", "short", _W),), "int", True), 0x24: ((("mode", "short", _W),), "int", True),
    0x25: ((("vector", "short", _W), ("handler", "void*", _L)), "void*", False), 0x27: ((), "int", False),
    0x28: ((("time", "int", _L),), "int", False), 0x29: ((_NAME, _BUFFER), "int", False),
    0x2A: ((), "int", False), 0x2B: ((("date", "short", _W),), "int", False), 0x2C: ((), "int", False),
    0x2D: ((("time", "short", _W),), "int", False), 0x2E: ((("flag", "short", _W),), "int", False),
    0x30: ((), "int", False), 0x31: ((("length", "int", _L), ("code", "short", _W)), "int", False),
    0x33: ((("flag", "short", _W),), "int", False), 0x35: ((("vector", "short", _W),), "void*", False),
    0x36: ((("drive", "short", _W), _BUFFER), "int", False), 0x37: ((_NAME, _BUFFER), "int", False),
    0x39: ((_NAME,), "int", False), 0x3A: ((_NAME,), "int", False), 0x3B: ((_NAME,), "int", False),
    0x3C: ((_NAME, ("attribute", "short", _W)), "int", False), 0x3D: ((_NAME, ("mode", "short", _W)), "int", False),
    0x3E: ((_HANDLE,), "int", False), 0x3F: ((_HANDLE, _BUFFER, ("length", "int", _L)), "int", False),
    0x40: ((_HANDLE, _BUFFER, ("length", "int", _L)), "int", False), 0x41: ((_NAME,), "int", False),
    0x42: ((_HANDLE, ("offset", "int", _L), ("mode", "short", _W)), "int", False),
    0x43: ((_NAME, ("attribute", "short", _W)), "int", False),
    0x44: ((("mode", "short", _W), ("unit", "short", _W)), "int", True), 0x45: ((_HANDLE,), "int", False),
    0x46: ((_HANDLE, ("new_handle", "short", _W)), "int", False),
    0x47: ((("drive", "short", _W), _BUFFER), "int", False), 0x48: ((("length", "int", _L),), "void*", False),
    0x49: ((("block", "void*", _L),), "int", False),
    0x4A: ((("block", "void*", _L), ("length", "int", _L)), "int", False),
    0x4B: ((("mode", "short", _W), _NAME, ("command", "char*", _L), ("environment", "void*", _L)), "int", False),
    0x4C: ((("code", "short", _W),), "int", False), 0x4D: ((), "int", False),
    0x4E: ((_BUFFER, _NAME, ("attribute", "short", _W)), "int", False), 0x4F: ((_BUFFER,), "int", False),
}
# Human68k 2.x moved $FF50-$FF5F to $FF80-$FF8F; both numberings take the same arguments.
for _number, _parameters in {
    0x50: ((("process", "void*", _L),), "void*", False), 0x51: ((), "void*", False),
    0x52: ((_NAME, ("environment", "void*", _L), ("value", "char*", _L)), "int", False),
    0x53: ((_NAME, ("environment", "void*", _L), _BUFFER), "int", False),
    0x56: ((("old_name", "char*", _L), ("new_name", "char*", _L)), "int", False),
    0x57: ((_HANDLE, ("date_time", "int", _L)), "int", False),
    0x58: ((("mode", "short", _W), ("length", "int", _L)), "void*", False),
    0x5A: ((_NAME, ("attribute", "short", _W)), "int", False), 0x5B: ((_NAME, ("attribute", "short", _W)), "int", False),
    0x5C: ((("mode", "short", _W), _HANDLE, ("offset", "int", _L), ("length", "int", _L)), "int", False),
}.items():
    DOS_PARAMETERS[_number] = DOS_PARAMETERS[_number + 0x30] = _parameters


class XError(ValueError):
    """A malformed Human68k executable."""


def line_f_name(word: int) -> str | None:
    """Return the DOS or FPACK name of a line-F call word, or None."""
    table = {0xFF: DOS_CALLS, 0xFE: FPACK_CALLS}.get(word >> 8)
    return None if table is None else table.get(word & 0xFF)


def _relocation_sites(table: memoryview) -> Iterator[tuple[int, int]]:
    """Yield (offset, width) for each site. Word deltas, 0x0001 escapes to a long delta, odd marks a word site."""
    offset = position = 0
    while position < len(table):
        if position + 2 > len(table):
            raise XError("truncated Human68k relocation table")
        delta = unpack_from(">H", table, position)[0]
        position += 2
        if delta == 1:
            if position + 4 > len(table):
                raise XError("truncated Human68k relocation table")
            delta = unpack_from(">I", table, position)[0]
            position += 4
        width = 4
        if delta & 1:
            delta &= ~1
            width = 2
        offset += delta
        yield offset, width


def _import_symbols(table: memoryview, units: list[dict]) -> dict:
    by_name = {unit["name"]: unit for unit in units}
    counts: dict[str, int] = {}
    position = 0
    while position + 6 <= len(table):
        kind, value = unpack_from(">HI", table, position)
        position += 6
        end = bytes(table[position:]).find(b"\0")
        if end < 0:
            raise XError("unterminated Human68k symbol name")
        name = bytes(table[position:position + end]).decode("cp932", errors="replace")
        position += end + 1 + ((end + 1) & 1)
        label = {0x0003: "common"}.get(kind) or _SYMBOL_UNITS.get(kind, "other")
        counts[label] = counts.get(label, 0) + 1
        unit = by_name.get(_SYMBOL_UNITS.get(kind, ""))
        if unit is None or not name:
            continue
        offset = value - unit["image_offset"]
        if 0 <= offset < unit["size"] or (offset == unit["size"] and kind != 0x0201):
            unit["symbols"].append({"name": name, "offset": offset})
    return counts


def build_x_image(data: bytes, program: str, base: int = DEFAULT_M68K_BASE) -> tuple[bytes, dict]:
    """Place TEXT, DATA, and BSS consecutively at `base` and apply the Human68k relocation table."""
    if not 0 <= base < M68K_ADDRESS_LIMIT or base % 2:
        raise XError("X68000 base address must be even and within the 24-bit address space")
    if len(data) < HEADER_SIZE:
        raise XError("truncated Human68k executable header")
    (magic, _reserved, load_mode, link_base, entry, text_size, data_size, bss_size,
     relocation_size, symbol_size) = _HEADER.unpack_from(data)
    if magic != X_MAGIC:
        raise XError("missing Human68k HU magic")
    initialized = text_size + data_size
    if base + initialized + bss_size > M68K_ADDRESS_LIMIT:
        raise XError("X68000 layout exceeds the 24-bit address space")
    relocation_start = HEADER_SIZE + initialized
    symbol_start = relocation_start + relocation_size
    if symbol_start + symbol_size > len(data):
        raise XError("truncated Human68k TEXT, DATA, relocation, or symbol table")
    entry_offset = entry - link_base
    if not 0 <= entry_offset < text_size or entry_offset % 2:
        raise XError(f"Human68k entry 0x{entry:x} is outside TEXT")

    units = [
        {"name": name, "kind": kind, "linear": base + start, "image_offset": start, "size": size,
         "file_offset": HEADER_SIZE + start if kind != "bss" else None,
         "file_size": size if kind != "bss" else 0, "symbols": [], "relocations": []}
        for name, kind, start, size in (
            ("text", "code", 0, text_size), ("data", "data", text_size, data_size),
            ("bss", "bss", initialized, bss_size),
        )
    ]
    view = memoryview(data)
    symbol_counts = _import_symbols(view[symbol_start:symbol_start + symbol_size], units)
    image = bytearray(view[HEADER_SIZE:relocation_start])
    delta = base - link_base
    word_sites = 0
    for offset, width in _relocation_sites(view[relocation_start:symbol_start]):
        if offset % 2 or offset + width > initialized:
            raise XError(f"invalid Human68k relocation offset 0x{offset:x}")
        code = ">I" if width == 4 else ">H"
        original = unpack_from(code, image, offset)[0]
        value = (original + delta) & (0xFFFFFFFF if width == 4 else 0xFFFF)
        pack_into(code, image, offset, value)
        unit = units[0] if offset < text_size else units[1]
        record = {"offset": offset - unit["image_offset"], "original": original, "value": value}
        if width == 2:
            record["width"] = 2
            word_sites += 1
        unit["relocations"].append(record)
    image.extend(bytes(bss_size))
    return bytes(image), {
        "version": 1, "format": X68K_FORMAT, "program": program, "base_address": base,
        "header": {"load_mode": _LOAD_MODES.get(load_mode, load_mode), "link_base": link_base,
                   "relocation_table_size": relocation_size, "symbol_table_size": symbol_size,
                   "word_relocations": word_sites, "symbols": symbol_counts},
        "entry": {"unit_address": f"text:{entry_offset:04x}", "linear": base + entry_offset}, "units": units,
        "memory_map": [
            {"name": name, "linear": start, "size": end - start, "read": kind, "write": "none" if kind == "rom" else kind}
            for start, end, name, kind in MEMORY_MAP
        ],
        "hardware_labels": [{"name": name, "linear": address} for address, name in HARDWARE_LABELS],
        "line_f_calls": {
            "dos": {f"{0xFF00 | number:04X}": name for number, name in DOS_CALLS.items()},
            "fpack": {f"{0xFE00 | number:04X}": name for number, name in FPACK_CALLS.items()},
            "no_return": [f"{0xFF00 | number:04X}" for number in DOS_NO_RETURN],
            "dos_prototypes": {
                f"{0xFF00 | number:04X}": {
                    "parameters": [{"name": name, "type": kind, "size": size} for name, kind, size in parameters],
                    "result": result, "variadic": variadic,
                }
                for number, (parameters, result, variadic) in sorted(DOS_PARAMETERS.items())
            },
        },
    }
