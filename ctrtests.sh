#!/bin/bash

# Automated tests that encrypts and decrypts a few files, then checks
# if the decrypted files match the original files.

#SIZES="$(echo {1..129})"
SIZES="$(echo {1..129}) 304 494928 5949285 39821 393827 847427 9284 1024 1025 $((5*1024*1024)) $((8*1024*1024)) $((8*1024*1024+3)) $((13*1024*1024+10))"

cd ctrtests

for SIZE in $SIZES; 
	do 
		if [[ ! -f "plain_${SIZE}" ]]; then
			dd if=/dev/urandom of=./plain_${SIZE} bs=$SIZE count=1 > /dev/null
		fi
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
