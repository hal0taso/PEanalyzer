import io
import sys
from winnt_def import *



def Banner(ins):
    print('{:=^60}'.format(ins.__class__.__name__))


def magic_chk(magic_num, keys):
    for dic in MagicNumberDict:
        pass

        
# read pefile
def main():
    fd = open(sys.argv[1], 'rb')
    r = fd.read()

    # まずはIMAGE_DOS_HEADERから
    idh = IMAGE_DOS_HEADER()
    Banner(idh)
    io.BytesIO(r[:sizeof(IMAGE_DOS_HEADER)]).readinto(idh)
    print('IMAGE_DOS_HEADER.e_magic:		 0x{:04x}'.format(idh.e_magic))
    
    # PEヘッダの位置を取得
    pe_header = idh.e_lfanew
    print('IMAGE_DOS_HEADER.e_lfanew:		 0x{:08x}'.format(idh.e_lfanew))
    
    # IMAGE_NT_HEADERS32を取得。これで内部の構造体にもうまいこと値が入ってくれるみたい。
    inh = IMAGE_NT_HEADERS32()
    Banner(inh)
    io.BytesIO(r[pe_header:pe_header + sizeof(IMAGE_NT_HEADERS32)]).readinto(inh)
    print('IMAGE_NT_HEADER.Signature:		 0x{:08x}'.format(inh.Signature))

    ifh = inh.FileHeader
    ioh = inh.OptionalHeader

    print('IMAGE_OPTIONAL_HEADER.Magic:		 0x{:04x}'.format(ioh.Magic))
    print('IMAGE_FILE_HEADER.NumberOfSections:	 0x{:04x}'.format(ifh.NumberOfSections))

    section_table = pe_header + sizeof(IMAGE_NT_HEADERS32)

    print('Section Table start from: {}'.format(hex(section_table)))
    ish_array = (IMAGE_SECTION_HEADER * ifh.NumberOfSections)()

    for i in range(0, ifh.NumberOfSections):
        section_header = section_table + (i * sizeof(IMAGE_SECTION_HEADER))
        io.BytesIO(r[section_header:section_header + sizeof(IMAGE_SECTION_HEADER)]).readinto(ish_array[i])

        print('========== Section Table : {} =========='.format(ifh.NumberOfSections))
        print('{:02d} {}'.format(i + 1, ''.join([chr(name) for name in ish_array[i].Name])))
        print('    raw data offsets: 		0x{:08x}'.format(ish_array[i].PointerToRawData))
        print('    raw data size:		0x{:08x}'.format(ish_array[i].SizeOfRawData))
        print('    Characteristics:		0x{:08x}'.format(ish_array[i].Characteristics))
        for j in range(len(iCharacteristics)):
            if(ish_array[i].Characteristics & iCharacteristics[j]):
                print('        {}'.format(pcszCharacteristics[j]))
                

if __name__ == '__main__':
    main()
