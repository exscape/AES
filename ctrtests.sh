#!/bin/bash

# Automated tests that encrypts and decrypts a few files, then checks
# if the decrypted files match the original files.

SIZES="8 15 16 20 31 32 33 49 63 64 65 $((5*1024*1024)) $((8*1024*1024)) $((8*1024*1024+3)) $((13*1024*1024+10))"

cd ctrtests

for SIZE in $SIZES; 
	do 
		../bin/ctr -e plain_${SIZE} -o cipher_${SIZE};
		../bin/ctr -d cipher_${SIZE} -o decrypted_${SIZE};
		diff -q plain_${SIZE} decrypted_${SIZE} >/dev/null
		if [[ "$?" == "1" ]]; then
			echo "ERROR: $SIZE bytes"
		else
			echo "PASS: $SIZE bytes"
		fi
	done

cd ..
