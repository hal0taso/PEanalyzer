# -*- coding: utf-8 -*-

import sys
import struct

# ファイルをバイナリモードで読み込み
fd = open(sys.argv[1], 'rb')
r = fd.read()

'''
BYTE:  1byte
WORD:  2byte
DWORD: 4byte
LONG:  4byte
'''

'''
for unpacking binary, struct.unpack('<fmt', v1,v2...)
for packing binary, struct.pack('<fmt', v1, v2...)
'''

'''
PE File Format 
http://hp.vector.co.jp/authors/VA050396/tech_06.html
+-------------------------------+
|  MS-DOS Header or Program     |
|+-----------------------------+|
|| MS-DOS Header               ||
|+-----------------------------+|
||MS-DOS Real-Mode Stub Program||
|+-----------------------------+|
+-------------------------------+
|  NT Header                    |
|+-----------------------------+|
|| Signature                   ||
|+-----------------------------+|
|| File Header                 ||
|+-----------------------------+|
|| Optional Header             ||
|+-----------------------------+|
+-------------------------------+
|  Section Table                |
|+-----------------------------+|
|| Section Header              ||
|+-----------------------------+|
||  ....                       ||
|+-----------------------------+|
|| Section Header              ||
|+-----------------------------+|
+-------------------------------+
| Section Data                  |
+-------------------------------+
|   ....                        |
+-------------------------------+
| Section Data                  |
+-------------------------------+

'''

def CheckSize(ins, _s):
    if(len(_s) != ins.s_SIZE):
            print('[!] StructSizeException :{name} is expect {exp_size} bytes input.'.format(
                name=ins.__class__.__name__, exp_size=ins.s_SIZE))
            print('[!] Input Size is: {}'.format(len(_s)))
            exit()

def Banner(ins):
    print('{:=^60}'.format(ins.__class__.__name__))

def CheckMagic(var, val, collect, wrong):
    if(var == val):
        print(collect)
    else:
        print(wrong)
    
# DOS Header
class IMAGE_DOS_HEADER():
    
    '''
    // Size: 64 bytes
    typedef struct _IMAGE_DOS_HEADER{
    	// DOS .EXE header
        WORD e_magic;		// Magic number
        WORD e_cblp;		// Bytes on last page on file
        WORD e_cp;		// Pages in file
        WORD e_crlc;		// Relocations
        WORD e_cparhdr;	// Size of header in paragraphs
        WORD e_minalloc;	// Minimum extra paragraphs needed
        WORD e_maxalloc;	// Maximam extra paragraphs needed
        WORD e_ss;		// Initial (relative) SS value
        WORD e_sp;		// Initial SP value
        WORD e_csum;		// Checksum
        WORD e_ip;		// Initial IP value
        WORD e_cs;		// Initial (relative) CS value
        WORD e_lfarlc;		// File address of relocation table
        WORD e_ovno;		// Overlay number
        WORD e_res[4];		// Reserved words
        WORD e_oemid;		// OEM identifier (for e_oeminfo)
        WORD e_oeminfo;	// OEM infomation; e_oemid specific
        WORD e_res2[10];	// Reserved words
        LONG e_lfanew;		// File address of new exe header
    } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
    '''

    s_SIZE = 64
    
    def __init__(self, _s):
        Banner(self)
        
        self.e_res = [None]*4
        self.e_res2 = [None]*10

        CheckSize(self, _s)

        # unpacking header
        (
            self.e_magic,
            self.e_cblp,
            self.e_cp,
            self.e_crlc,
            self.e_cparhdr,
            self.e_minalloc,
            self.e_maxalloc,
            self.e_ss,
            self.e_sp,
            self.e_csum,
            self.e_ip,
            self.e_cs,
            self.e_lfarlc,
            self.e_ovno,
            self.e_res[0], self.e_res[1], self.e_res[2], self.e_res[3],
            self.e_oemid,
            self.e_oeminfo,
            self.e_res2[0], self.e_res2[1], self.e_res2[2], self.e_res2[3], self.e_res2[4],
            self.e_res2[5], self.e_res2[6], self.e_res2[7], self.e_res2[8], self.e_res2[9],
            self.e_lfanew,
        ) = struct.unpack('<30HI', _s)

        # if (self.e_magic != 0x5a4d):
        #     print("[!] This file is NOT PE format.")
        #     exit()

        CheckMagic(self.e_magic, 0x5a4d, "[*] PE format.", "[!] Error: NOT PE format.")
    def putVal(self):
        print("[*] Magic number: {}".format(hex((self.e_magic))))
        print("[*] File address of new exe header: {}".format(hex(self.e_lfanew)))

        
class IMAGE_FILE_HEADER():

    '''
    // Size: 20 bytes
    typedef struct _IMAGE_FILE_HEADER {
        WORD  Machine;
        WORD  NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD  SizeOfOptionalHeader;
        WORD  Characteristics;
    } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
    '''

    s_SIZE = 20

    def __init__(self, _s):
        # if(len(_s) != 22):
        #     print('[!] Failed to initialize IMAGE_NT_HEADER32. Check Byte size.')
        #     print('[!] Input Size is: {}'.format(len(_s)))
        #     exit()
        Banner(self)
        CheckSize(self, _s)

        (
            self.Machine,
            self.NumberOfSections,
            self.TimeDateStamp,
            self.PointerToSymbolTable,
            self.NumberOfSymbols,
            self.SizeOfOptionalHeader,
            self.Characteristics,
         ) = struct.unpack('<2H3I2H', _s)
        


class IMAGE_OPTIONAL_HEADER():

    '''
    // Size: 224 bytes
    typedef struct _IMAGE_OPTIOAL_HEADER {
        //
        // Standard fields.
        // Size: 28 bytes

        WORD  Magic;
        BYTE  MajorLinkerVersion;
        BYTE  MinorLinkerVersion;
        DWORD SizeOfCode;
        DWORD SizeOfInitializedData;
        DWORD SizeOfUninitializedData;
        DWORD AddressOfEntryPoint;
        DWORD BaseOfCode;
        DWORD BaseOfData;

        //
        // NT additional fields
        // Size: 68 bytes + (8 bytes * 16 = 128 bytes) = 196 bytes

        DWORD ImageBase;
        DWORD SectionAlignment;
        DWORD FileAlignment;
        WORD  MajorOperatingSystemVersion;
        WORD  MinorOperatingSystemVersion;
        WORD  MajorImageVersion;
        WORD  MinorImageVersion;
        WORD  MajorSubsystemVersion;
        WORD  MinorSubsystemVersion;
        DWORD Win32VersionValue;
        DWORD SizeOfImage;
        DWORD SizeOfHeaders;
        DWORD CheckSum;
        WORD  Subsystem;
        WORD  DllCharacteristics;
        DWORD SizeOfStackReserve;
        DWORD SizeOfStackCommit;
        DWORD SizeOfHeapReserve;
        DWORD SizeOfHeapCommit;
        DWORD LoaderFlags;
        DWORD NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
    '''

    s_SIZE = 224
    IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
    
    def __init__(self, _s):
        Banner(self)
        CheckSize(self, _s)
        (
            # Standard fields
            self.Magic,
            self.MajorLinkerVersion,
            self.MinorLinkerVersion,
            self.SizeOfCode,
            self.SizeOfInitializedData,
            self.SizeOfUninitializedData,
            self.AddressOfEntryPoint,
            self.BaseOfCode,
            self.BaseOfData,
            # NT additional fields
            self.ImageBase,
            self.SectionAlignment,
            self.FileAlignment,
            self.MajorOperatingSystemVersion,
            self.MinorOperatingSystemVersion,
            self.MajorImageVersion,
            self.MinorImageVersion,
            self.MajorSubsystemVersion,
            self.MinorSubsystemVersion,
            self.Win32VersionValue,
            self.SizeOfImage,
            self.SizeOfHeaders,
            self.CheckSum,
            self.Subsystem,
            self.DllCharacteristics,
            self.SizeOfStackReserve,
            self.SizeOfStackCommit,
            self.SizeOfHeapReserve,
            self.SizeOfHeapCommit,
            self.LoaderFlags,
            self.NumberOfRvaAndSizes,
        ) = struct.unpack('<H2B6I3I6H4I2H6I', _s[:96])

        self.DataDirectory = [None]*16
        for i in range(self.IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
            self.DataDirectory[i] = IMAGE_DATA_DIRECTORY(_s[96+8*i:96+8*i+8])

    def CheckBit(self):
        if self.Magic == 0x10b:
            print('[*] 32 Bit Executable')
        elif self.Magic == 0x20b:
            print('[*] 64 Bit Executable')
        else:
            print('[!] Failed: Excutable bit undefined.')
            print('[!] IMAGE_OPTIONAL_HEADER.Magic: {}'.format(hex(self.Magic)))
            
class IMAGE_DATA_DIRECTORY():

    '''
    // Size: 8 bytes
    typedef struct _IMAGE_DATA_DIRECTORY {
        DWORD VirtualAddress;
        DWORD Size;
    } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
    '''

    s_SIZE = 8

    def __init__(self, _s):
        # Banner(self)
        CheckSize(self, _s)
        (self.VirtualAddress,
         self.Size) = struct.unpack('<2I', _s)

class IMAGE_NT_HEADERS():

    '''
    // Size: 4 bytes + 20 bytes + 224 bytes = 248 bytes
    typedef struct _IMAGE_NT_HEADERS {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
    '''

    # first, read signature and IMAGE_OPTIONAL_HEADER
    s_SIZE = 4 + IMAGE_FILE_HEADER.s_SIZE + IMAGE_OPTIONAL_HEADER.s_SIZE

    def __init__(self, _s):
        Banner(self)
        CheckSize(self, _s)
        # if(len(_s) != 130):
        #     print('[!] Failed to initialize IMAGE_NT_HEADER32. Check Byte size.')
        #     print('[!] Input Size is: {}'.format(len(_s)))
        #     exit()
        (self.Signature,) = struct.unpack('<I', _s[:4])
        self.FileHeader = IMAGE_FILE_HEADER(_s[4:4+IMAGE_FILE_HEADER.s_SIZE])
        self.OptionalHeader = IMAGE_OPTIONAL_HEADER(_s[-1 * IMAGE_OPTIONAL_HEADER.s_SIZE:])


    def listSection(self):
        NumberOfSections = self.FileHeader.NumberOfSections


class IMAGE_SECTION_HEADER():

    '''
    #define IMAGE_SIZEOF_SHORT_NAME 8

    typedef struct _IMAGE_SECTION_HEADER {
        BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
        union {
                DWORD PhysicalAddress;
                DWORD VirtualSize;
        } Misc;
        DWORD VirtualAddress;
        DWORD SizeOfRawData;
        DWORD PointerToRawData;
        DWORD PointerToRelocations;
        DWORD PointerToLinenumbers;
        WORD NumberOfRelocations;
        WORD NumberOfLinenumbers;
        DWORD Characteristics;
    } IMAGE_SECTION_HEADER,*PIMAGE_SECTION_HEADER;
    '''

    IMAGE_SIZEOF_SHORT_NAME = 8
    
    def __init__(self, _s):
        (
            self.Name,
            self.PhysicalAddress,
            self.VirtualSize,
            self.VirtualAddress,
            self.SizeOfRawData,
            self.PointerToRawData,
            self.PointerToRelocations,
            self.PointerToLinenumbers,
            self.NumberOfRelocations,
            self.NumberOfLinenumbers,
            self.Characteristics,
         )

im = IMAGE_DOS_HEADER(r[0:64])
im.putVal()
PE_head = im.e_lfanew
print(PE_head)
print(PE_head + IMAGE_NT_HEADERS.s_SIZE)
inh = IMAGE_NT_HEADERS(r[PE_head:PE_head + IMAGE_NT_HEADERS.s_SIZE])

print(struct.pack('<I',inh.Signature))

inh.OptionalHeader.CheckBit()
print('SizeOfInitializedData: {}'.format(hex(inh.OptionalHeader.SizeOfInitializedData)))
