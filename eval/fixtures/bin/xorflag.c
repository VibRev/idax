#include <stdio.h>
/* "FLAG{xor_ok}" xored with 0x5a; plaintext is not in the binary */
static const unsigned char enc[] = {0x1c,0x16,0x1b,0x1d,0x21,0x22,0x35,0x28,0x5,0x35,0x31,0x27,0x0};
static void reveal(char *out) {
    int i;
    for (i = 0; enc[i]; i++) out[i] = (char)(enc[i] ^ 0x5a);
    out[i] = 0;
}
int main(void) {
    char buf[32];
    reveal(buf);
    puts(buf);
    return 0;
}
