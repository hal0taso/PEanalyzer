import io
import sys
import struct
from winnt_def import *



def Banner(s):
    print('{:=^60}'.format(s.__class__.__name__))


def search_str(data):
    print('{:=^60}'.format('START STRING SEARCH'))
    lstr = []
    text = ''
    code = False
    for b in data:
        if 0x20 <= b <= 0x7e and (not code):
            text += chr(b)
        elif len(text) > 1:
            lstr.append(text)
            text = ''
        elif len(text) == 0 and b == 0x55: # PUSH EBP = 0x55
            code = True
        elif code and (b in [0xc2, 0xc3, 0x90, 0x00]):
            code = False
        else:
            text = ''
    else:
        for s in lstr:
            print(s)
    print('{:=^60}'.format('END'))


        

def main():
    # read pefile
    fd = open(sys.argv[1], 'rb')
    printflag=False

    if len(sys.argv) == 3 and sys.argv[2] == 'p':
        printflag = True
        
    r = fd.read()

    # まずはIMAGE_DOS_HEADERから
    idh = IMAGE_DOS_HEADER()
    io.BytesIO(r[:sizeof(IMAGE_DOS_HEADER)]).readinto(idh)
    infoDosHeader(idh, printflag)
    
    # PEヘッダの位置を取得
    pe_header = idh.e_lfanew
    
    # IMAGE_NT_HEADERS32を取得
    inh = IMAGE_NT_HEADERS32()
    io.BytesIO(r[pe_header:pe_header + sizeof(IMAGE_NT_HEADERS32)]).readinto(inh)

    infoNTHeader(inh, printflag)

    
    ifh = inh.FileHeader
    ioh = inh.OptionalHeader

    infoOptionalHeader(ioh, printflag)
    

    section_table = pe_header + sizeof(IMAGE_NT_HEADERS32)
    ish_array = (IMAGE_SECTION_HEADER * ifh.NumberOfSections)()

    infoSectionTable(ish_array, section_table, ifh.NumberOfSections, r, printflag)

    
    search_str(r[ish_array[0].PointerToRawData:ish_array[0].PointerToRawData + ish_array[0].SizeOfRawData])
    fd.close()


    
def infoDosHeader(idh, printflag=False):
    if printflag:
        Banner(idh)
        print('    e_magic:                     0x{:04x}'.format(idh.e_magic))
        print('    e_lfanew:                    0x{:08x}'.format(idh.e_lfanew))
    if not idh.e_magic == 0x5a4d:
        print('[!] Error: e_magic does not matched "MZ')
        exit()

def infoNTHeader(inh, printflag=False):
    if printflag:
        Banner(inh)
        bsig = struct.pack('<I', inh.Signature)
        signature = ''.join(chr(c) for c in bsig)
        print('    Signature:                   0x{:08x} (ASCII:{})'.format(inh.Signature, signature))
    if not inh.Signature == 0x4550:
        print('[!] Error: This File is Not PE.')
        exit()
    


def infoDataDir(ioh, printflag=False):
    if printflag:
        for i in range(15):
            print('      {:02d} {}'.format(i, iIMAGE_NUMBER_OF_DERECTORY[i]))
            print('        VirtualAddress:            0x{:08x}'.format(ioh.DataDirectory[i].VirtualAddress))
            print('        Size:                      0x{:08x}'.format(ioh.DataDirectory[i].Size))
        
    
def infoOptionalHeader(ioh, printflag=False):
    if printflag:
        Banner(ioh)
        print('    Magic:                       0x{:04x}'.format(ioh.Magic))
        print('    SizeOfCode:                  0x{:08x}'.format(ioh.SizeOfCode))
        print('    SizeOfInitializedData:       0x{:08x}'.format(ioh.SizeOfInitializedData))
        print('    SizeOfUninitializedData:     0x{:08x}'.format(ioh.SizeOfUninitializedData))
        print('    AddressOfEntryPoint:         0x{:08x}'.format(ioh.AddressOfEntryPoint))
        print('    BaseOfCode:                  0x{:08x}'.format(ioh.BaseOfCode))
        print('    BaseOfData:                  0x{:08x}'.format(ioh.BaseOfData))
        print('    ImageBase:                   0x{:08x}'.format(ioh.ImageBase))    
        print('    SectionAlignment:            0x{:08x}'.format(ioh.SectionAlignment))
        print('    FileAlignment:               0x{:08x}'.format(ioh.FileAlignment))
        print('    SizeOfImage:                 0x{:08x}'.format(ioh.SizeOfImage))
        print('    NumberOfRvaAndSizes          0x{:08x}'.format(ioh.NumberOfRvaAndSizes))
        infoDataDir(ioh, printflag)
    

def infoSectionTable(ish_array, section_table, section_num, r, printflag=False):
    if printflag:
        print('{:=^60}'.format('SectionTable: {}'.format(section_num)))
        print('Section Table start from: 0x{:08x}'.format(section_table))
    
    for i in range(0, section_num):
        section_header = section_table + (i * sizeof(IMAGE_SECTION_HEADER))
        io.BytesIO(r[section_header:section_header + sizeof(IMAGE_SECTION_HEADER)]).readinto(ish_array[i])
        if printflag:
            print('{:02d} {}'.format(i + 1, ''.join([chr(name) for name in ish_array[i].Name])))
            print('    VirtualSize:                 0x{:08x}'.format(ish_array[i].Misc.VirtualSize))        
            print('    VirtualAddress:              0x{:08x}'.format(ish_array[i].VirtualAddress))
            print('    RawDataSize:                 0x{:08x}'.format(ish_array[i].SizeOfRawData))
            print('    RawDataOffsets:              0x{:08x}'.format(ish_array[i].PointerToRawData))
            print('    Characteristics:             0x{:08x}'.format(ish_array[i].Characteristics))
            for j in range(len(iCharacteristics)):
                if(ish_array[i].Characteristics & iCharacteristics[j]):
                    print('        {}'.format(pcszCharacteristics[j]))
            

def print_raw_data(data, ptr, size):
    print(data[ptr:ptr + size])

    
if __name__ == '__main__':
    main()
