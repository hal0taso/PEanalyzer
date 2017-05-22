import sys
from winnt_def import *

def search_str(data):
    print('{:=^60}'.format('START STRING SEARCH'))
    lstr = []
    text = ''
    code = False
    for b in data:
        # if len(text) == 0 and b == 0x55: # PUSH EBP = 0x55
        #     code = True
        # elif code and (b in [0xc2, 0xc3, 0x90, 0x00]):
        #     code = False
        # else:
        #     text = ''
        if 0x20 <= b <= 0x7e: #and (not code):
            text += chr(b)
        elif len(text) > 1:
            lstr.append(text)
            text = ''
        else:
            text = ''

    else:
        for s in lstr:
            print(s)
    print('{:=^60}'.format('END'))


def lfnull(s):
    return '{:\0<8}'.format(s)
    

def main():
    # read pefile
    fd = open(sys.argv[1], 'rb')

    if len(sys.argv) == 3 and sys.argv[2] == 'p':
        printflag = True
        
    r = fd.read()

    # まずはIMAGE_DOS_HEADERから
    idh = IMAGE_DOS_HEADER()
    sinit(idh, r)
    idh.info()
    
    # PEヘッダの位置を取得
    pe_header = idh.e_lfanew
    
    # IMAGE_NT_HEADERS32を取得
    inh = IMAGE_NT_HEADERS32()
    io.BytesIO(r[pe_header:pe_header + sizeof(IMAGE_NT_HEADERS32)]).readinto(inh)
    inh.info()
    
    ifh = inh.FileHeader
    ioh = inh.OptionalHeader

    ioh.info()
    
    section_table = pe_header + sizeof(IMAGE_NT_HEADERS32)
    
    ish = aIMAGE_SECTION_HEADER(ifh.NumberOfSections, r, section_table)

    ish.info()

    

    for i in range(ish.section_num):
        print([chr(name) for name in ish.array[i].Name])
        name = ''.join([chr(name) for name in ish.array[i].Name])
        print('Name: {}, Length: {}'.format(name, len(name)))
                       
        if (''.join([chr(name) for name in ish.array[i].Name]) == lfnull('.text')):
            search_str(r[ish.array[i].PointerToRawData:ish.array[i].PointerToRawData + ish.array[i].SizeOfRawData])
        elif (''.join([chr(name) for name in ish.array[i].Name]) == lfnull('.rodata')):
            search_str(r[ish.array[i].PointerToRawData:ish.array[i].PointerToRawData + ish.array[i].SizeOfRawData])


    fd.close()

# for 目grep
def print_raw_data(data, ptr, size):
    print(data[ptr:ptr + size])

    
if __name__ == '__main__':
    main()
