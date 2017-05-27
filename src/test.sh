#!/usr/bin/env bash

echo 'TEST: ConsoleApplication1.exe'
echo '======== RUN ========='
echo '====== DEFAULT ======='

diff <(./pe.py ../testfile/ConsoleApplication1.exe) <(strings ../testfile/ConsoleApplication1.exe)

echo '======= ALL ========='

diff <(./pe.py ../testfile/ConsoleApplication1.exe -A) <(strings ../testfile/ConsoleApplication1.exe -a)

echo '======== END ========'


echo 'TEST: ConsoleApplication1.exe'
echo '======== RUN ========='
echo '====== DEFAULT ======='

diff <(./pe.py ../testfile/tstwinapp.exe) <(strings ../testfile/tstwinapp.exe)

echo '======= ALL ========='

diff <(./pe.py ../testfile/tstwinapp.exe -A) <(strings ../testfile/tstwinapp.exe -a)

echo '======== END ========'

