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
    pe_head = idh.e_lfanew
    print('IMAGE_DOS_HEADER.e_lfanew:		 0x{:08x}'.format(idh.e_lfanew))
    
    # IMAGE_NT_HEADERS32を取得。これで内部の構造体にもうまいこと値が入ってくれるみたい。
    inh = IMAGE_NT_HEADERS32()
    Banner(inh)
    io.BytesIO(r[pe_head:pe_head+sizeof(IMAGE_NT_HEADERS32)]).readinto(inh)
    print('IMAGE_NT_HEADER.Signature:		 0x{:08x}'.format(inh.Signature))

    ifh = inh.FileHeader
    ioh = inh.OptionalHeader

    print('IMAGE_OPTIONAL_HEADER.Magic:		 0x{:04x}'.format(ioh.Magic))
    print('IMAGE_FILE_HEADER.NumberOfSections:	 0x{:04x}'.format(ifh.NumberOfSections))
    

if __name__ == '__main__':
    main()
