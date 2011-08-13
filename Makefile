all: keytest

clean:
	rm bin/keytest

keytest:
	gcc -m32 -std=gnu99 -o bin/keytest keyschedule.c key_exp_test.c debug.c -O0 -Wall -Werror
