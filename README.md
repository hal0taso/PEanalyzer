# PEanalyzer
PE header analyzer

for self-Educating and SecurityCamp2017.

# usage
```
python3 peanal.py [file]
```
# Overview
次に、各ヘッダーに関して順に説明する。まずはDOS MZヘッダである。DOS MZヘッダはPEファイルフォーマットの先頭にある領域で、winnt.h内ではIMAGE_DOS_HEADERとして定義されている。このIMAGE_DOS_HEADER構造体で重要なのは最初のメンバであるe_magicと最後のメンバであるe_lfanewの２つのみである。e_magicは0x4D,0x5Aという2バイトの値で、ASCII文字になおすと"MZ"である。余談だが、この"MZ"はPEを作ったMark Zbikowiski氏のイニシャルである。この値はファイルがPEファイルかどうかの確認としてよく使われる。e_lfanewは実際のPEのオフセットがどこにあるかを示す。つまり、PEヘッダーであるIMAGE_NT_HEADERがどこに存在するのかを示す。PEファイルフォーマットの各ヘッダの構造体にはe_magicのようなマジックナンバーがいくつか存在しており、今回自作したプログラムでは、今後汎用性を高めていくためと、うまくファイルを読み込めているかの確認を兼ねて各ヘッダのマジックナンバーを照らし合わせることで、読み込んだファイルやデータが正しく解析されているか確かめながら解析した。
次に、PEヘッダについて説明する。PEヘッダはwinnt.hでIMAGE_NT_HEADERSとして定義されており、Signature,FileHeader,OptionalHeaderの3つのメンバから構成される。SignatureはPEヘッダの先頭4バイトを占め、PEファイルの場合は0x50,0x45,0x00,0x00となっており、これはASCII文字で"PE"である。

analyze pe header and extract string literal

# issue
PE（Portable Executable）ファイルフォーマットの構造を調べ、添付の[.NETアプリケーション](./dotNet-A-6/)から文字列を取得する機能を実装してください。具体的には、ファイルの先頭からヘッダを順次参照することで.NETアプリケーションの文字列（String）型リソースを取得するプログラムを作成してください。その際、以下の制限、規則に従ってください。 

- この.NETアプリケーションのみでなく、汎用的に文字列型を取得できるようなプログラム構造にしてください。 
- PEファイルを解析するような他者のコードは利用せず、自分で調べたPEファイルフォーマットの構造に従い、一からパースするプログラムを作ってください。 
- 参考にしたサイトや調べて分かったこと、作成したプログラムの工夫点などはできる限り詳細に記述してください。

---
## todo
### 作成したプログラムのリンク

### 参考にしたサイト、書籍

- リバースエンジニアリングバイブル
- https://www.glamenv-septzen.net/view/708
- http://hp.vector.co.jp/authors/VA050396/index.html
- http://home.a00.itscom.net/hatada/mcc/doc/pe.html

### 大変だったこと

- `IMAGE_OPTIONAL_HEADER32`構造体のサイズが、32bitと64bitで違うため、`IMAGE_FILE_HEADER`構造体中の`SizeOfOptionalHeader`メンバを参照して`IMAGE_NT_HEADERS`構造体のサイズを決める必要がある。(未実装)
- 

### PE File Format 
from http://hp.vector.co.jp/authors/VA050396/index.html

![](./img/pe.png)
