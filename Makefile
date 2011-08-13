all: keytest

clean:
	rm bin/keytest

keytest:
	gcc -m32 -std=gnu99 -o bin/tests keyschedule.c tests.c debug.c -O0 -Wall -Werror
