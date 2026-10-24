#include <stdio.h>
#include <string.h>
static int check(const char *s) { return strcmp(s, "s3cret_42") == 0; }
int main(int argc, char **argv) {
    if (argc > 1 && check(argv[1])) { puts("access granted"); return 0; }
    puts("denied");
    return 1;
}
