all: tests bench ctr

clean:
	rm bin/keytest

tests:
	gcc -m64 -std=gnu99 -o bin/tests keyschedule.c aes.c tests.c debug.c misc.c -O0 -Wall -Werror -ggdb3

bench:
	gcc -m64 -std=gnu99 -o bin/bench keyschedule.c aes.c bench.c debug.c misc.c -O3 -Wall -Werror -msse -msse2 -msse3 -mfpmath=sse -march=nocona
	
ctr:
	gcc -m64 -std=gnu99 -o bin/ctr keyschedule.c aes.c ctr.c debug.c misc.c -O0 -Wall -Werror -ggdb3 
#	gcc -m64 -std=gnu99 -o bin/ctr keyschedule.c aes.c ctr.c debug.c misc.c -O3 -Wall -Werror -msse -msse2 -msse3 -mfpmath=sse -march=nocona
