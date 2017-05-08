import io
import sys
from winnt_def import *

# read pefile
def main():
    fd = open(argv[1], 'rb')
    r = fd.read()

    # まずはIMAGE_DOS_HEADERから
    iIDH = IMAGE_DOS_HEADER()
    io.BytesIO(r[:sizeof(IMAGE_DOS_HEADER)]).readinto(iIDH)

    # PEヘッダの位置を取得
    pe_head = iIDH.e_lfanew

    # IMAGE_NT_HEADERS32を取得。これで内部の構造体にもうまいこと値が入ってくれるみたい。
    iINH = IMAGE_NT_HEADERS32()
    io.BytesIO(r[pe_head:pe_head+sizeof(iINH)]).readinto(iINH)

    
    
