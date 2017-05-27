#!/usr/bin/env python3
import sys
from winnt_def import *
import argparse

# バイナリデータから文字列抽出を行う
def is_str(data):

    '''
    extract string literal from binary data.
    Compare data is in range of ASCII code.
    if it is in ASCII code and length is larger than 1, it is considered as string literal.
    '''
    
    # print('{:=^60}'.format('START STRING SEARCH'))
    lstr = []
    text = ''
    code = False
    for b in data:
        # ascii 文字の範囲内にあるかどうかの確認 
        if 0x20 <= b <= 0x7e or b == 0x09: #and (not code):
            text += chr(b)
        elif len(text) >= 4:
            lstr.append(text)
            text = ''
        else:
            text = ''

    else:
        for s in lstr:
            print(s)
    # print('{:=^60}'.format('END'))

def is_initialized_data_section(a_ish, sec_num):

    '''
    check each IMAGE_SECTION_HEADER.
    '''

    init_data_sec = []

    # 各IMAGE_SECTION_HEADERのCharacteristicsのフラグをチェック
    # INITIALIZED_DATAのフラグが立っているセクションを見る
    for i in range(sec_num):
        if(a_ish.array[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA):
            init_data_sec.append(a_ish.array[i].getName())
    return init_data_sec
    


def print_raw_data(data, ptr, size):
    '''
    目grepをしろ！！！
    '''
    
    print(data[ptr:ptr + size])



def search_str_each_section(r, a_ish, section_name=[], raw=False):

    '''
    search_str_each_section(ish):
    
    search string literals from section.
    ish is IMAGE_SECTION_HEADER.
    if section name is empty, search all section
    '''
    
    for i in range(a_ish.section_num):
        
        # セクション名の中にヌル文字が入ってるのを確認。
        # print([chr(name) for name in ish.array[i].Name])
        # name = ''.join([chr(name) for name in ish.array[i].Name])
        # print('Name: {}, Length: {}'.format(name, len(name)))
        
        # .textセクションから文字列を抽出
        if section_name:
            if a_ish.array[i].getName() in section_name:
                #            print(''.join([chr(name) for name in ish.array[i].Name]))
                if raw:
                    print_raw_data(r,
                                   ish.array[i].PointerToRawData,
                                   ish.array[i].SizeOfRawData)
                else:
                    is_str(r[a_ish.array[i].PointerToRawData:a_ish.array[i].PointerToRawData + a_ish.array[i].SizeOfRawData])
        else:
            if raw:
                print_raw_data(r, a_ish.array[i].PointerToRawData, a_ish.array[i].SizeOfRawData)
            else:
                is_str(r[a_ish.array[i].PointerToRawData:a_ish.array[i].PointerToRawData + a_ish.array[i].SizeOfRawData])





# 文字列の左側をヌルバイトでパディング
def lfnull(s):
    return '{:\0<8}'.format(s)
    

def main():

    # set options using argparse library
    parser = argparse.ArgumentParser(description="Analysinc PE excutable format.")

    # 文字列抽出に関するオプションは競合するのでグループ化する
    search_group = parser.add_mutually_exclusive_group()
    
    parser.add_argument("FILE",
                        help="FILE to analyze")
    
    parser.add_argument("-v", "--verbose",
                        help="increase output verbosisy.\nif you use this option, this program print information of each header",
                        action="store_true")

    # グルーピングした奴ら
    search_group.add_argument("-s", "--section", nargs='+',
                        help="show string literals in specified section")
    
    search_group.add_argument("-r", "--raw", nargs='+', metavar='SECTION',
                        help="show rawdata of specified section")
    search_group.add_argument("-A", "--all",
                        help="search string literals of all section",
                        action="store_true")

    # オプションの読み込み
    args = parser.parse_args()

    
    # read pefile
    if args.FILE:
        fd = open(args.FILE, 'rb')
        
    r = fd.read()

    # まずはIMAGE_DOS_HEADERから
    idh = IMAGE_DOS_HEADER(r)
    # sinit(idh, r)
    
    
    # PEヘッダの位置を取得
    ptr_pe_header = idh.e_lfanew
    # IMAGE_NT_HEADERS32を取得
    inh = IMAGE_NT_HEADERS32(r,ptr_pe_header)
    # io.BytesIO(r[ptr_pe_header:ptr_pe_header + sizeof(IMAGE_NT_HEADERS32)]).readinto(inh)
    ifh = inh.FileHeader
    ioh = inh.OptionalHeader
    section_table = ptr_pe_header + sizeof(IMAGE_NT_HEADERS32)
    a_ish = aIMAGE_SECTION_HEADER(ifh.NumberOfSections, r, section_table)


    if args.verbose:
        idh.info()
        inh.info()
        ioh.info()
        a_ish.info()


    if args.section:
        search_str_each_section(r, a_ish, args.section)
    elif args.raw:
        search_str_each_section(r, a_ish, args.raw, raw=True)
    elif args.all:
        search_str_each_section(r, a_ish)
    else:
        search_str_each_section(r, a_ish,
            is_initialized_data_section(a_ish, ifh.NumberOfSections))
        
    fd.close()

    
if __name__ == '__main__':
    main()
