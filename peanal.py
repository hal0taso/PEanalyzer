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

def CheckSize(classname, _s, num):
    if(len(_s) != num):
            print('[!] Failed to initialize {}. Check Byte size.'.format(classname))
            print('[!] Input Size is: {}'.format(len(_s)))
            exit()
    

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

    def __init__(self, _s):
        print("===== IMAGE_DOS_HEADER =====")
        self.e_res = [None]*4
        self.e_res2 = [None]*10

        # unpacking header
        (self.e_magic,
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
        ) = struct.unpack('<HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHI', _s)

        if (self.e_magic != 0x5a4d):
            print("[!] This file is NOT PE format.")
            exit()

    def put_val(self):
        print("[*] Magic number: {}".format(hex(self.e_magic)))
        print("[*] File address of new exe header: {}".format(hex(self.e_lfanew)))
        


class IMAGE_NT_HEADERS32():

    '''
    // Size: 4 bytes + 22 bytes + 104 bytes = 130 bytes
    typedef struct _IMAGE_NT_HEADERS {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADER32, *PIMAGE_NT_HEADERS32;
    '''

    def __init__(self, _s):
        print("===== IMAGE_NT_HEADER =====")
        CheckSize("IMAGE_NT_HEADER32", _s, 128)
        # if(len(_s) != 130):
        #     print('[!] Failed to initialize IMAGE_NT_HEADER32. Check Byte size.')
        #     print('[!] Input Size is: {}'.format(len(_s)))
        #     exit()
        (self.Signature,) = struct.unpack('<I', _s[:4])
        self.FileHeader = IMAGE_FILE_HEADER(_s[4:24])
        self.OptionalHeader = IMAGE_OPTIONAL_HEADER32(_s[24:])

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

    def __init__(self, _s):
        # if(len(_s) != 22):
        #     print('[!] Failed to initialize IMAGE_NT_HEADER32. Check Byte size.')
        #     print('[!] Input Size is: {}'.format(len(_s)))
        #     exit()
        print("===== IMAGE_FILE_HEADER =====")
        CheckSize('IMAGE_FILE_HEADER', _s, 20)

        (self.Machine,
         self.NumberOfSections,
         self.TimeDateStamp,
         self.PointerToSymbolTable,
         self.NumberOfSymbols,
         self.SizeOfOptionalHeader,
         self.Characteristics,
         ) = struct.unpack('<HHIIIHH', _s)
 

class IMAGE_OPTIONAL_HEADER32():

    '''
    // Size: 104 bytes
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
        // Size: 68 bytes + 8 bytes = 76 bytes

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

    def __init__(self, _s):
        print("===== IMAGE_OPTIONAL_HEADER32 =====")
        CheckSize('IMAGE_OPTIONAL_HEADER32', _s, 104)
        pass

class IMAGE_DATA_DIRECTORY():

    '''
    // Size: 8 bytes
    typedef struct _IMAGE_DATA_DIRECTORY {
        DWORD VirtualAddress;
        DWORD Size;
    } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
    '''

    def __init__(self, _s):
        print("===== IMAGE_DATA_DIRECTORY =====")
        CheckSize('IMAGE_DATA_DIRECTORY', _s, 8)
        (self.VirtualAddress,
         self.Size) = struct.unpack('<II', _s)
    
im = IMAGE_DOS_HEADER(r[0:64])
im.put_val()

inh = IMAGE_NT_HEADERS32(r[im.e_lfanew:im.e_lfanew+128])
print(hex(inh.Signature))

# print("[*] This file is PE.")
