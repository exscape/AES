all: keytest

clean:
	rm bin/keytest

keytest:
	gcc -m64 -std=gnu99 -o bin/tests keyschedule.c aes.c tests.c debug.c -O0 -Wall -Werror
