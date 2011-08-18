OPTFLAGS=-O3 -msse -msse2 -msse3 -mfpmath=sse -march=nocona

all: tests bench ctr
	@grep -iE 'FIXME|TODO' * | grep -v '^Makefile'

deb: tests_debug bench_debug ctr_debug

clean:
	rm bin/{ctr,tests,bench}

tests:
	gcc -m64 -std=gnu99 -o bin/tests keyschedule.c aes.c tests.c debug.c misc.c -Wall -Werror ${OPTFLAGS}

bench:
	gcc -m64 -std=gnu99 -o bin/bench keyschedule.c aes.c bench.c debug.c misc.c -Wall -Werror ${OPTFLAGS}
	
ctr:
	gcc -m64 -std=gnu99 -o bin/ctr keyschedule.c aes.c ctr.c debug.c misc.c -Wall -Werror ${OPTFLAGS} && bash ctrtests.sh

tests_debug:
	gcc -m64 -std=gnu99 -o bin/tests keyschedule.c aes.c tests.c debug.c misc.c -Wall -Werror -O0 -ggdb3

bench_debug:
	gcc -m64 -std=gnu99 -o bin/bench keyschedule.c aes.c bench.c debug.c misc.c -Wall -Werror -O0 -ggdb3
	
ctr_debug:
	gcc -m64 -std=gnu99 -o bin/ctr keyschedule.c aes.c ctr.c debug.c misc.c -Wall -Werror -O0 -ggdb3 && bash ctrtests.sh
