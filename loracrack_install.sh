#!/bin/bash

# belépés a saját könyvtárba
cd ~
# github repo klónozása
git clone https://github.com/applied-risk/Loracrack.git
# Openssl 1.0.2 letöltése
wget https://openssl.org/source/openssl-1.0.2.tar.gz
# Openssl kicsomagolása
tar xvf openssl-1.0.2.tar.gz
# belépés az Openssl könyvtárába
cd openssl-1.0.2/
# Openssl patch letöltése
wget https://web.archive.org/web/20210920011739/http://www.linuxfromscratch.org/patches/blfs/7.7/openssl-1.0.2-fix_parallel_build-1.patch
# megfelelő mappák létrehozása a működéshez
mkdir -p /home/kali/usr
mkdir -p /home/kali/etc/ssl
# javítás alkalmazása
patch -Np1 -i ./openssl-1.0.2-fix_parallel_build-1.patch && 
./config --prefix=/home/kali/usr --openssldir=/home/kali/etc/ssl --libdir=lib shared zlib-dynamic && 
make
# Openssl lefordítása
make MANDIR=/home/kali/usr/share/man MANSUFFIX=ssl install &&
install -dv -m755 /home/kali/usr/share/doc/openssl-1.0.2  &&
cp -vfr doc/* /home/kali/usr/share/doc/openssl-1.0.2
# átlépés a Loracrack könyvtárába
cd ~/Loracrack
# a Makefile módosítása, hogy a megfelelő openssl-t használja
sed -i 's/-Lincludes\/openssl-1.0.2q\/ -Iincludes\/openssl-1.0.2q\/include\//-L\/home\/kali\/usr\/lib\/ -I\/home\/kali\/usr\/include\//g' Makefile
# Loracrack lefordítása
make
# megfelelő környezeti változó exportálása
export LD_LIBRARY_PATH=/home/kali/usr/lib/
# amennyiben szeretnénk, hogy ne kelljen minden terminál indításkor exportálni, tegyük permanensé
echo 'export LD_LIBRARY_PATH=/home/kali/usr/lib/' >> ~/.zshrc
# a Loracrack innentől kezdve működőképes