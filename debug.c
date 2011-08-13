#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

// For debugging
void print_hex(const unsigned char *s, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%.2x ", s[i]);
    }
    printf("\n");
}
