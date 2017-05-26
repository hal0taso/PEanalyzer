import sys
from winnt_def import *
import argparse

# バイナリデータから文字列抽出を行う
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

        # ascii 文字の範囲内にあるかどうかの確認 
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


# 文字列の左側をヌルバイトでパディング
def lfnull(s):
    return '{:\0<8}'.format(s)
    

def main():

    # set options using argparse library
    parser = argparse.ArgumentParser(description="extract string literals from PE excutable format.")

    parser.add_argument("file",
                        help="file to analyze")
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosisy.\nif you use this option, this program print information of each header",
                        action="store_true")
    parser.add_argument("-s", "--section",
                        help="if you want to show raw data of section, you can use this option with section name")

    args = parser.parse_args()

    
    # read pefile
    if args.file:
        fd = open(args.file, 'rb')

    if len(sys.argv) == 3 and sys.argv[2] == 'p':
        printflag = True
        
    r = fd.read()

    # まずはIMAGE_DOS_HEADERから
    idh = IMAGE_DOS_HEADER()
    sinit(idh, r)
    
    
    # PEヘッダの位置を取得
    pe_header = idh.e_lfanew
    
    # IMAGE_NT_HEADERS32を取得
    inh = IMAGE_NT_HEADERS32()
    io.BytesIO(r[pe_header:pe_header + sizeof(IMAGE_NT_HEADERS32)]).readinto(inh)
    
    
    ifh = inh.FileHeader
    ioh = inh.OptionalHeader


    
    section_table = pe_header + sizeof(IMAGE_NT_HEADERS32)
    
    ish = aIMAGE_SECTION_HEADER(ifh.NumberOfSections, r, section_table)


    if args.verbose:
        idh.info()
        inh.info()
        ioh.info()
        ish.info()

        


    

    for i in range(ish.section_num):
        
        # セクション名の中にヌル文字が入ってるのを確認。
        # print([chr(name) for name in ish.array[i].Name])
        # name = ''.join([chr(name) for name in ish.array[i].Name])
        # print('Name: {}, Length: {}'.format(name, len(name)))

        # .textセクションから文字列を抽出
        if (''.join([chr(name) for name in ish.array[i].Name]) == lfnull('.text')):
            search_str(r[ish.array[i].PointerToRawData:ish.array[i].PointerToRawData + ish.array[i].SizeOfRawData])

    fd.close()    

# for 目grep
def print_raw_data(data, ptr, size):
    print(data[ptr:ptr + size])

    
if __name__ == '__main__':
    main()
