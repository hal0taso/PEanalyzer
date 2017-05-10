import io
import sys
import struct
from winnt_def import *



def Banner(s):
    print('{:=^60}'.format(s.__class__.__name__))


def magic_chk(magic_num, keys):
    for dic in MagicNumberDict:
        pass

def search_str(data):
    print('{:=^60}'.format('START STRING SEARCH'))
    lstr = []
    text = ''
    for b in data:
        if 0x20 <= b <= 0x7e:
            text += chr(b)
        elif len(text) == 1: # and ord(text) == 0x20:
            text = ''
        elif len(text) > 0:
            lstr.append(text)
            text = ''
        else:
            pass
    else:
        for s in lstr:
            print(s)
    print('{:=^60}'.format('END'))


        
# read pefile
def main():
    fd = open(sys.argv[1], 'rb')
    r = fd.read()

    # まずはIMAGE_DOS_HEADERから
    idh = IMAGE_DOS_HEADER()
    io.BytesIO(r[:sizeof(IMAGE_DOS_HEADER)]).readinto(idh)
    infoDosHeader(idh)
    
    # PEヘッダの位置を取得
    pe_header = idh.e_lfanew
    
    # IMAGE_NT_HEADERS32を取得
    inh = IMAGE_NT_HEADERS32()
    io.BytesIO(r[pe_header:pe_header + sizeof(IMAGE_NT_HEADERS32)]).readinto(inh)

    infoNTHeader(inh)

    
    ifh = inh.FileHeader
    ioh = inh.OptionalHeader

    infoOptionalHeader(ioh)
    
#   print('IMAGE_FILE_HEADER.NumberOfSections:	 0x{:04x}'.format(ifh.NumberOfSections))

    section_table = pe_header + sizeof(IMAGE_NT_HEADERS32)
    ish_array = (IMAGE_SECTION_HEADER * ifh.NumberOfSections)()

    infoSectionTable(ish_array, section_table, ifh.NumberOfSections, r)

    search_str(r[ish_array[0].PointerToRawData:ish_array[0].PointerToRawData + ish_array[0].SizeOfRawData])
    fd.close()


#    print('{:=^60}'.format(''.join([chr(name) for name in ish_array[0].Name])))
#    index = ish_array[0].PointerToRawData
#    print(r[index:index + ish_array[0].SizeOfRawData])



    
def infoDosHeader(idh):
    Banner(idh)
    print('    e_magic:                     0x{:04x}'.format(idh.e_magic))
    print('    e_lfanew:                    0x{:08x}'.format(idh.e_lfanew))
    

def infoNTHeader(inh):
    Banner(inh)
    bsig = struct.pack('<I', inh.Signature)
    signature = ''.join(chr(c) for c in bsig)
    if signature == 'PE':
        print('[!] Error: This File is Not PE.')
        exit()
    print('    Signature:                   0x{:04x} (ASCII:{})'.format(inh.Signature, signature))


def infoDataDir(ioh):
    for i in range(15):
        print('      {:02d} {}'.format(i, iIMAGE_NUMBER_OF_DERECTORY[i]))
        print('        VirtualAddress:            0x{:08x}'.format(ioh.DataDirectory[i].VirtualAddress))
        print('        Size:                      0x{:08x}'.format(ioh.DataDirectory[i].Size))
        
    
def infoOptionalHeader(ioh):
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
    infoDataDir(ioh)
    

def infoSectionTable(ish_array, section_table, section_num, r):
    print('{:=^60}'.format('SectionTable: {}'.format(section_num)))
    print('Section Table start from: 0x{:08x}'.format(section_table))
    
    for i in range(0, section_num):
        section_header = section_table + (i * sizeof(IMAGE_SECTION_HEADER))
        io.BytesIO(r[section_header:section_header + sizeof(IMAGE_SECTION_HEADER)]).readinto(ish_array[i])

        print('{:02d} {}'.format(i + 1, ''.join([chr(name) for name in ish_array[i].Name])))
        print('    VirtualSize:                 0x{:08x}'.format(ish_array[i].Misc.VirtualSize))        
        print('    VirtualAddress:              0x{:08x}'.format(ish_array[i].VirtualAddress))
        print('    RawDataSize:                 0x{:08x}'.format(ish_array[i].SizeOfRawData))
        print('    RawDataOffsets:              0x{:08x}'.format(ish_array[i].PointerToRawData))
        print('    Characteristics:             0x{:08x}'.format(ish_array[i].Characteristics))
        for j in range(len(iCharacteristics)):
            if(ish_array[i].Characteristics & iCharacteristics[j]):
                print('        {}'.format(pcszCharacteristics[j]))
                

if __name__ == '__main__':
    main()
