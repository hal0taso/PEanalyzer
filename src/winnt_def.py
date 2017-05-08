from ctypes import *

# Map the Microsoft types to ctypes for clarity
BYTE      = c_ubyte
WORD      = c_ushort
DWORD     = c_ulong
SIZE_T    = c_ulong

# Constants
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_SIZEOF_SHORT_NAME = 8

class IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ('e_magic',	WORD),
        ('e_cblp',	WORD),
        ('e-cp',	WORD),
        ('e_crlc',	WORD),
        ('e_cparhdr',	WORD),
        ('e_minalloc',	WORD),
        ('e_maxalloc',	WORD),
        ('e_ss',	WORD),
        ('e_sp',	WORD),
        ('e_csum',	WORD),
        ('e_ip',	WORD),
        ('e_cs',	WORD),
        ('e_lfarlc',	WORD),
        ('e_ovno',	WORD),
        ('e_res',	WORD * 4),
        ('e_oemid',	WORD),
        ('e_oeminfo',	WORD),
        ('e_res2',	WORD * 10),
        ('e_lfanew',	WORD),
        ]

class IMAGE_NT_HEADERS32(Structure):
    _fields_ = [
        ('Signature',		DWORD),
        ('FileHeader',		IMAGE_FILE_HEADER),
        ('OptionalHeader',	IMAGE_OPTIONAL_HEADER32)
    ]

class IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ('Macine',			WORD),
        ('NumberOfSections',		WORD),
        ('TimeDateStamp',		DWORD),
        ('PointerToSymbolTable',	DWORD),
        ('NumberOfSymbols',		DWORD),
        ('SizeOfOptionalHeader',	WORD),
        ('Characteristics', 		WORD),
    ]

class IMAGE_OPTIONAL_HEADER32(Structure):
    _fields_ = [
        # Standard fields.
        ('Magic',			WORD),
        ('MajorLinkerVersion',		BYTE),
        ('MinorLinkerVersion',		BYTE),
        ('SizeOfCode',			DWORD),
        ('SizeOfInitializedData',	DWORD),
        ('AddressOfEntryPoint',		DWORD),
        ('BaseOfCode',			DWORD),
        ('BaseOfData',			DWORD),
        # NT additional fields
        ('ImageBase',			DWORD),
        ('SectionAlignment',		DWORD),
	('FileAlignment',		DWORD),
        ('MajorOperatingSystemVersion',	WORD),
        ('MinorOperatingSystemVersion',	WORD),
        ('MajorImageVersion',		WORD),
        ('MinorImageVersion',		WORD),
        ('MajorSubsystemVersion',	WORD),
        ('MinorSubsystemVersion',	WORD),
        ('Win32VersionValue',		DWORD),
        ('SizeOfImage',			DWORD),
        ('SizeOfHeaders',		DWORD),
        ('CheckSum',			DWORD),
        ('Subsystem',			WORD),
        ('DllCharacteristics',		WORD),
        ('SizeOfStackReserve',		DWORD),
        ('SizeOfStackCommit',		DWORD),
        ('SizeOfHeapReserve',		DWORD),
        ('SizeOfHeapCommit',		DWORD),
        ('LoaderFlags',			DWORD),
        ('NumberOfRvaAndSizes',		DWORD),
        ('DataDirectory',		IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]

class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ('VirtualAddress',	DWORD),
        ('Size',		DWORD),
    ]


class IMAGE_SECTION_HEADER(Structure):
    _fields_ = [
        ('Name',			BYTE * IMAGE_SIZEOF_SHORT_NAME),
        ('Misc',			MISC),
        ('VirtualAddress',		DWORD),
        ('SizeOfRawData',		DWORD),
        ('PointerToRawData',		DWORD),
        ('PointerToRelocations',	DWORD),
        ('PointerToLinenumbers',	DWORD),
        ('NumberOfRelocations',		WORD),
        ('NumberOfLinenumbers',		WORD),
        ('Characteristics',		DWORD),
    ]

class MISC(Union):
    _fields_ = [
        ('PhysicalAddress',	DWORD),
        ('VirtualSize',		DWORD),
    ]
