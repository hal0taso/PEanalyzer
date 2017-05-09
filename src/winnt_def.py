from ctypes import *
import io

# Map the Microsoft types to ctypes for clarity
BYTE    = c_ubyte
WORD    = c_uint16
DWORD   = c_uint32
LONG	= c_uint32
SIZE_T  = c_uint32


# Constants
IMAGE_DOS_SIGNATURE			= 0x5A4D

# IMAGE_DATA_DIRECTORY
IMAGE_NUMBEROF_DIRECTORY_ENTRIES 	= 16
IMAGE_DIRECTORY_ENTRY_EXPORT 		= 0	# Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT		= 1 	# Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE		= 2 	# Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION		= 3	# Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY		= 4	# Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC		= 5 	# Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG 		= 6	# Debug Directory
# IMAGE_DIECTORY_ENTRY_COPYRIGHT	= 7	# (X86 usage)
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE	= 7	# Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR		= 8	# RVA of GP
IMAGE_DIRECTORY_ENTRY_TLS		= 9	# TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 	= 10	# Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT	= 11	# Bound Import Directory in headersI
IMAGE_DIRECTORY_ENTRY_IAT		= 12	# Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT	= 13	# Delay Load Import Descriptors
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	= 14	# COM Runtime descriptor

IMAGE_SIZEOF_SHORT_NAME 		= 8

# IMAGE_FILE_HEADER.Characteristics
IMAGE_FILE_RELOCS_STRIPPED		= 0x0001
IMAGE_FILE_EXECUTABLE_IMAGE		= 0x0002
IMAGE_FILE_LINE_NUMS_STRIPPED		= 0x0004
IMAGE_FILE_LOCAL_SYMS_STRIPPED		= 0x0008
IMAGE_FILE_AGGRESIVE_WS_TRIM		= 0x0010
IMAGE_FILE_LARGE_ADDRESS_AWARE		= 0x0020
IMAGE_FILE_BYTES_REVRESED_LO		= 0x0080
IMAGE_FILE_32BIT_MACHINE		= 0x0100
IMAGE_FILE_DEBUG_STRIPPED		= 0x0200
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP	= 0x0400

# IMAGE_OPTIONAL_HEADER.Subsystem
IMAGE_SUBSYSTEM_NATIVE			= 1
IMAGE_SUBSYSTEM_WINDOWS_GUI		= 2
IMAGE_SUBSYSTEM_WINDOWS_CUI		= 3

MagicNumberDict = dict(
    [
        ('IMAGE_DOS_HEADER', IMAGE_DOS_SIGNATURE),
        
    ]
)

# from MSDN(https://msdn.microsoft.com/ja-jp/library/windows/desktop/ms680341(v=vs.85).aspx)
IMAGE_SCN_CNT_CODE 			= 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA 		= 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA	= 0x00000080
IMAGE_SCN_MEM_DISCARDABLE		= 0x02000000
IMAGE_SCN_MEM_NOT_CACHED		= 0x04000000
IMAGE_SCN_MEM_NOT_PAGED			= 0x08000000
IMAGE_SCN_MEM_SHARED			= 0x10000000
IMAGE_SCN_MEM_EXECUTE			= 0x20000000
IMAGE_SCN_MEM_READ			= 0x40000000
IMAGE_SCN_MEM_WRITE			= 0x80000000



iCharacteristics = [
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA,
    IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_NOT_CACHED, IMAGE_SCN_MEM_NOT_PAGED,
    IMAGE_SCN_MEM_SHARED, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE
]


pcszCharacteristics = [
    'CODE',
    'INITIALIZED_DATA',
    'UNINITIALIZED_DATA',
    'MEM_DISCARDABLE',
    'MEM_NOT_CACHED',
    'MEM_NOT_PAGED',
    'MEM_SHARED',
    'MEM_EXECUTE',
    'MEM_READ',
    'MEM_WRITE',
]


class IMAGE_FILE_HEADER(Structure):
    pass


class IMAGE_OPTIONAL_HEADER32(Structure):
    pass

class IMAGE_DATA_DIRECTORY(Structure):
    pass


class IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ('e_magic',	WORD),
        ('e_cblp',	WORD),
        ('e_cp',	WORD),
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
        ('e_lfanew',	LONG),
    ]



    
class IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ('Machine',			WORD),
        ('NumberOfSections',		WORD),
        ('TimeDateStamp',		DWORD),
        ('PointerToSymbolTable',	DWORD),
        ('NumberOfSymbols',		DWORD),
        ('SizeOfOptionalHeader',	WORD),
        ('Characteristics', 		WORD),
    ]

    
    
class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ('VirtualAddress',	DWORD),
        ('Size',		DWORD),
    ]


class IMAGE_OPTIONAL_HEADER32(Structure):
    _fields_ = [
        # Standard fields.
        ('Magic',			WORD),
        ('MajorLinkerVersion',		BYTE),
        ('MinorLinkerVersion',		BYTE),
        ('SizeOfCode',			DWORD),
        ('SizeOfInitializedData',	DWORD),
        ('SizeOfUninitializedData',	DWORD),
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



    
class MISC(Union):
    _fields_ = [
        ('PhysicalAddress',	DWORD),
        ('VirtualSize',		DWORD),
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

    
class IMAGE_NT_HEADERS32(Structure):
    _fields_ = [
        ('Signature',		DWORD),
        ('FileHeader',		IMAGE_FILE_HEADER),
        ('OptionalHeader',	IMAGE_OPTIONAL_HEADER32)
    ]
