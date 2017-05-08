# PEanalyzer
PE header analyzer

for self-Educating and SecurityCamp2017.

# usage
```
python3 peanal.py [file]
```

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
- 共用体のPythonでの実装(ctypesを使えば良い？？)

### PE File Format 
