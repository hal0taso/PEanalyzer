from ctypes import *
import io
import struct

def Banner(s):
    print('{:=^60}'.format(s.__class__.__name__))



    
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

iIMAGE_NUMBER_OF_DERECTORY = [
    'EXPORT',
    'IMPORT',
    'RESOURCE',
    'EXCEPTION',
    'SECURITY',
    'BASERELOC',
    'DEBUG',
    'ARCHITECTURE',
    'GLOBALPTR',
    'TLS',
    'LOAD_CONFIG',
    'BOUND_IMPORT',
    'IAT',
    'DELAY_IMPORT',
    'COM_DESCRIPTER',
    ]

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


class wStructure(Structure):

    def banner(self):
        print('{:=^60}'.format(self.__class__.__name__))

    def sinit(self, data, ptr=0):
        io.BytesIO(data[ptr:ptr+sizeof(self)]).readinto(self)

    def chr2str(self, chr_array):
        return ''.join([chr(c) for c in chr_array]).strip('\0')



def sinit(s, data, ptr=0):
    io.BytesIO(data[ptr:ptr+sizeof(s)]).readinto(s)

class aIMAGE_SECTION_HEADER:

    '''
    aIMAGE_SECTION_HEADER:
    Return list of IMAGE_SECTION_HEADER.
    
    e.g.
    array_ish = aIMAGE_SECTION_HEADER(image_file_header.NumberOfSections, data, section_table_ptr)
    '''
    
    def __init__(self, section_num, data, ptr):
        self.array = (IMAGE_SECTION_HEADER * section_num)()
        self.section_num = section_num
        self.section_table = ptr
        for i in range(section_num):
            sinit(self.array[i], data, ptr)
            ptr += sizeof(IMAGE_SECTION_HEADER)
        
    def info(self):
        print('{:=^60}'.format('SectionTable: {}'.format(self.section_num)))
        print('Section Table start from: 0x{:08x}'.format(self.section_table))
        for i in range(self.section_num):
            self.array[i].info(i)                
        
class IMAGE_FILE_HEADER(Structure):
    pass


class IMAGE_OPTIONAL_HEADER32(Structure):
    pass


class IMAGE_DATA_DIRECTORY(Structure):
    pass


class IMAGE_DOS_HEADER(wStructure):
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

    def __init__(self, r):
        self.sinit(r)

    def info(self):
        self.banner()
        print('    e_magic:                     0x{:04x}'.format(self.e_magic))
        print('    e_lfanew:                    0x{:08x}'.format(self.e_lfanew))
        if not self.e_magic == 0x5a4d:
            print('[!] Error: e_magic does not matched "MZ')
            exit()


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

    def info(self):
        print('        VirtualAddress:            0x{:08x}'.format(self.DataDirectory[i].VirtualAddress))
        print('        Size:                      0x{:08x}'.format(self.DataDirectory[i].Size))
        
        

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


    

    def info(self):
        Banner(self)
        print('    Magic:                       0x{:04x}'.format(self.Magic))
        print('    SizeOfCode:                  0x{:08x}'.format(self.SizeOfCode))
        print('    SizeOfInitializedData:       0x{:08x}'.format(self.SizeOfInitializedData))
        print('    SizeOfUninitializedData:     0x{:08x}'.format(self.SizeOfUninitializedData))
        print('    AddressOfEntryPoint:         0x{:08x}'.format(self.AddressOfEntryPoint))
        print('    BaseOfCode:                  0x{:08x}'.format(self.BaseOfCode))
        print('    BaseOfData:                  0x{:08x}'.format(self.BaseOfData))
        print('    ImageBase:                   0x{:08x}'.format(self.ImageBase))    
        print('    SectionAlignment:            0x{:08x}'.format(self.SectionAlignment))
        print('    FileAlignment:               0x{:08x}'.format(self.FileAlignment))
        print('    SizeOfImage:                 0x{:08x}'.format(self.SizeOfImage))
        print('    NumberOfRvaAndSizes          0x{:08x}'.format(self.NumberOfRvaAndSizes))
        


    
class Misc(Union):
    _fields_ = [
        ('PhysicalAddress',	DWORD),
        ('VirtualSize',		DWORD),
    ]


class IMAGE_SECTION_HEADER(Structure):
    _fields_ = [
        ('Name',			BYTE * IMAGE_SIZEOF_SHORT_NAME),
        ('Misc',			Misc),
        ('VirtualAddress',		DWORD),
        ('SizeOfRawData',		DWORD),
        ('PointerToRawData',		DWORD),
        ('PointerToRelocations',	DWORD),
        ('PointerToLinenumbers',	DWORD),
        ('NumberOfRelocations',		WORD),
        ('NumberOfLinenumbers',		WORD),
        ('Characteristics',		DWORD),
    ]


    def info(self, i):
        print('{:02d}: {}'.format(i+1, self.getNameb())) # join([chr(name) for name in self.Name])))
        print('    VirtualSize:                 0x{:08x}'.format(self.Misc.VirtualSize))        
        print('    VirtualAddress:              0x{:08x}'.format(self.VirtualAddress))
        print('    RawDataSize:                 0x{:08x}'.format(self.SizeOfRawData))
        print('    RawDataOffsets:              0x{:08x}'.format(self.PointerToRawData))
        print('    Characteristics:             0x{:08x}'.format(self.Characteristics))
        for i in range(len(iCharacteristics)):
            if(self.Characteristics & iCharacteristics[i]):
                print('        {}'.format(pcszCharacteristics[i]))


    def getName(self):
        return ''.join([chr(name) for name in self.Name])

    def getNameb(self):
        return ''.join([chr(name) for name in self.Name]).strip('\0')
    
class IMAGE_NT_HEADERS32(Structure):
    _fields_ = [
        ('Signature',		DWORD),
        ('FileHeader',		IMAGE_FILE_HEADER),
        ('OptionalHeader',	IMAGE_OPTIONAL_HEADER32)
    ]

    def info(self):
        Banner(self)
        bsig = struct.pack('<I', self.Signature)
        signature = ''.join(chr(c) for c in bsig)
        print('    Signature:                   0x{:08x} (ASCII:{})'.format(self.Signature, signature))
        if not (self.Signature == 0x4550):
            print('[!] Error: This File is Not PE.')
            exit()
                
            
class _U(Union):
    _fields_ = [
        ('Characteristics',	DWORD),
        ('OriginalFirstThunk',	DWORD),
    ]

    
class IMAGE_IMPORT_DESCRIPTER(Structure):
    _anonymous_ = ('u',)
    _fields_ = [
        ('u',			_U),
        ('TimeDateStamp',	DWORD),
        ('ForwarderChain',	DWORD),
        ('Name',		DWORD),
        ('FirstThunk',		DWORD),
    ]



class u1(Union):
    _fields_ = [
        ('ForwarderString',	DWORD), # PBYTE
        ('Function',		DWORD), # PDWORD
        ('Ordinal',		DWORD),
        ('AddressOfData',	DWORD), # PIMAGE_IMPORT_BY_NAME
    ]

class IMAGE_THUNK_DATA32(Structure):
    _fields_ = [
        ('u1',	u1),
    ]


class IMAGE_IMPORT_BY_NAME(Structure):
    _fields_ = [
        ('Hint',	WORD),
        ('Name',	BYTE),
    ]
