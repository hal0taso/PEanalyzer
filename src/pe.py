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
    idh.info(printflag)
    
    # PEヘッダの位置を取得
    pe_header = idh.e_lfanew
    
    # IMAGE_NT_HEADERS32を取得
    inh = IMAGE_NT_HEADERS32()
    io.BytesIO(r[pe_header:pe_header + sizeof(IMAGE_NT_HEADERS32)]).readinto(inh)

    inh.info(printflag)

    
    ifh = inh.FileHeader
    ioh = inh.OptionalHeader

    ioh.info(printflag)
    

    section_table = pe_header + sizeof(IMAGE_NT_HEADERS32)
    ish_array = (IMAGE_SECTION_HEADER * ifh.NumberOfSections)()

    ish.info(ish_array, section_table, ifh.NumberOfSections, r, printflag)

    
    search_str(r[ish_array[0].PointerToRawData:ish_array[0].PointerToRawData + ish_array[0].SizeOfRawData])
    fd.close()


    



    



    

    

            

def print_raw_data(data, ptr, size):
    print(data[ptr:ptr + size])

    
if __name__ == '__main__':
    main()
