#include <stdio.h>
/* "admin:hunter2" with each byte +7; decoder subtracts 7 */
static const unsigned char enc[] = {0x68,0x6b,0x74,0x70,0x75,0x41,0x6f,0x7c,0x75,0x7b,0x6c,0x79,0x39,0x0};
static void decode(char *out) {
    int i;
    for (i = 0; enc[i]; i++) out[i] = (char)(enc[i] - 7);
    out[i] = 0;
}
int main(void) {
    char cred[32];
    decode(cred);
    puts(cred);
    return 0;
}
