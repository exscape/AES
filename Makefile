all: tests

clean:
	rm bin/keytest

tests:
	gcc -m64 -std=gnu99 -o bin/tests keyschedule.c aes.c tests.c debug.c -O0 -Wall -Werror

bench:
	gcc -m64 -std=gnu99 -o bin/bench keyschedule.c aes.c bench.c debug.c -O3 -Wall -Werror
