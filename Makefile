all: keytest

clean:
	rm bin/keytest

keytest:
	gcc -o bin/keytest keyschedule.c key_exp_test.c -O0 -Wall -Werror
