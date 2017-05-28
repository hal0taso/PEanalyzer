#!/usr/bin/env python3
import sys
from winnt_def import *
import argparse

STRING_MIN = 4

# バイナリデータから文字列抽出を行う
def print_str(data, str_min=STRING_MIN):

    '''
    extract string literal from binary data.
    Compare data is in range of ASCII code.
    if it is in ASCII code and length is larger than 1, it is considered as string literal.
    '''
    
    lstr = []
    text = ''
    code = False
    for b in data:
        # ascii 文字の範囲内にあるかどうかの確認 
        if 0x20 <= b <= 0x7e or b == 0x09:
            text += chr(b)
        elif len(text) >= str_min:
            lstr.append(text)
            text = ''
        else:
            text = ''

    else:
        for s in lstr:
            print(s)


# この関数はセクション中のバイナリデータをそのまま出力する
# 呼び出し位置の都合上、print_strに対応した名前にしている
def print_raw(data, ptr, size):
    '''
    目grepをしろ！！！
    '''
    
    print(data[ptr:ptr + size])

            

def is_initialized_data(a_ish, sec_num):

    '''
    check each IMAGE_SECTION_HEADER.
    '''

    init_data_sec = []

    # 各IMAGE_SECTION_HEADERのCharacteristicsのフラグをチェック
    # INITIALIZED_DATAのフラグが立っているセクションを見る
    for i in range(sec_num):
        isInitialized = a_ish.array[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA
        isRead = a_ish.array[i].Characteristics & IMAGE_SCN_MEM_READ
        if isRead or isInitialized:
            init_data_sec.append(a_ish.array[i].getName())
    return init_data_sec
    



def search_str_each_section(r, a_ish, section_name=[],raw=False, str_min=STRING_MIN):

    '''
    search_str_each_section(ish):
    
    search string literals from section.
    ish is IMAGE_SECTION_HEADER.
    if section name is empty, search all section
    '''
    
    for i in range(a_ish.section_num):
        
        # .textセクションから文字列を抽出
        if section_name:
            # if section_name is specified by using -s or -r option,
            # 
            if a_ish.array[i].getName() in section_name:
                if raw:
                    print_raw(r,
                                   ish.array[i].PointerToRawData,
                                   ish.array[i].SizeOfRawData)
                else:
                    print_str(
                        r[a_ish.array[i].PointerToRawData:a_ish.array[i].PointerToRawData
                          + a_ish.array[i].SizeOfRawData],
                        str_min)
        else:
            if raw:
                print_raw(r,
                               a_ish.array[i].PointerToRawData,
                               a_ish.array[i].SizeOfRawData
                )
            else:
                print_str(
                    r[a_ish.array[i].PointerToRawData:a_ish.array[i].PointerToRawData
                      + a_ish.array[i].SizeOfRawData],
                    str_min
                )



def main():

    # set options using argparse library
    parser = argparse.ArgumentParser(description="Analyse PE excutable format and Extract string literals")

    # 文字列抽出に関するオプションは競合するのでグループ化する
    search_group = parser.add_mutually_exclusive_group()
    
    parser.add_argument("FILE",
                        help="FILE to analyze")
    
    parser.add_argument("-v", "--verbose",
                        help="show information of each header or section.\n\
                        does not extract string literals.",
                        action="store_true")
    parser.add_argument("-l", "--length", metavar='STRINGS_MIN',
                        help="change string_min length", type=int)

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
    # PEヘッダの位置を取得
    ptr_pe_header = idh.e_lfanew
    # IMAGE_NT_HEADERS32を取得
    inh = IMAGE_NT_HEADERS32(r,ptr_pe_header)
    # IMAGE_NT_HEADERS32中のメンバ構造体を変数に保存
    ifh = inh.FileHeader
    ioh = inh.OptionalHeader
    # セクションテーブルのバイナリ上でのアドレスを取得
    section_table = ptr_pe_header + sizeof(IMAGE_NT_HEADERS32)
    a_ish = aIMAGE_SECTION_HEADER(ifh.NumberOfSections, r, section_table)


    if args.verbose:
        idh.info()
        inh.info()
        ioh.info()
        a_ish.info()


    if args.length:
        STRINGS_MIN = args.length
        
    if args.section:
        search_str_each_section(r, a_ish, args.section, str_min=STRING_MIN)
    elif args.raw:
        search_str_each_section(r, a_ish, args.raw, raw=True, str_min=STRING_MIN)
    elif args.all:
        search_str_each_section(r, a_ish, str_min=STRING_MIN)
    elif not args.verbose:
        search_str_each_section(r, a_ish,
                                is_initialized_data(a_ish, ifh.NumberOfSections),
                                str_min=STRING_MIN)

    fd.close()

    
    
if __name__ == '__main__':
    main()
