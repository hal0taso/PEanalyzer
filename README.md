# PEanalyzer
analyze PE header and section.

for Seccamp2017 and Sel-Educating

# usage
```
 ./src/pe.py -h
usage: pe.py [-h] [-v] [-s SECTION [SECTION ...] | -r SECTION [SECTION ...] |
             -A]
             FILE

Analysinc PE excutable format.

positional arguments:
  FILE                  FILE to analyze

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         show information of each header or section. does not
                        extract string literals.
  -s SECTION [SECTION ...], --section SECTION [SECTION ...]
                        show string literals in specified section
  -r SECTION [SECTION ...], --raw SECTION [SECTION ...]
                        show rawdata of specified section
  -A, --all             search string literals of all section
  ``` 
  
# example

## 1. default

search all Section Contain Initialized data or Memory can read and print string literals

```
$ ./src/pe.py ./testfile/ConsoleApplication1.exe
```

## 2. specified section

search specified Section and print string literals.  
section name is what you can see using -v option.

```
$ ./src/pe.py ./testfile/ConsoleApplication1.exe
```

## 3. show header and section infomation

you can see pe header information

```
$ ./src/pe.py ./testfile/ConsoleApplication1.exe -v
======================IMAGE_DOS_HEADER======================
    e_magic:                     0x5a4d
    e_lfanew:                    0x00000080
=====================IMAGE_NT_HEADERS32=====================
    Signature:                   0x00004550 (ASCII:PE)
==================IMAGE_OPTIONAL_HEADER32===================
    Magic:                       0x010b
    SizeOfCode:                  0x00001000
    SizeOfInitializedData:       0x00000800
    SizeOfUninitializedData:     0x00000000
    AddressOfEntryPoint:         0x00002e6e
    BaseOfCode:                  0x00002000
    BaseOfData:                  0x00004000
    ImageBase:                   0x00400000
    SectionAlignment:            0x00002000
    FileAlignment:               0x00000200
    SizeOfImage:                 0x00008000
    NumberOfRvaAndSizes          0x00000010
======================SectionTable: 3=======================
Section Table start from: 0x00000178
01: .text
    VirtualSize:                 0x00000e74
    VirtualAddress:              0x00002000
    RawDataSize:                 0x00001000
    RawDataOffsets:              0x00000200
    Characteristics:             0x60000020
        CODE
        MEM_EXECUTE
        MEM_READ
02: .rsrc
    VirtualSize:                 0x00000590
    VirtualAddress:              0x00004000
    RawDataSize:                 0x00000600
    RawDataOffsets:              0x00001200
    Characteristics:             0x40000040
        INITIALIZED_DATA
        MEM_READ
03: .reloc
    VirtualSize:                 0x0000000c
    VirtualAddress:              0x00006000
    RawDataSize:                 0x00000200
    RawDataOffsets:              0x00001800
    Characteristics:             0x42000040
        INITIALIZED_DATA
        MEM_DISCARDABLE
        MEM_READ
```
