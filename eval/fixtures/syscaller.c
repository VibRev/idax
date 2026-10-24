#include <stdlib.h>
#include <stdio.h>
static void log_msg(const char *m) { puts(m); }
static int add(int a, int b) { return a + b; }
static void spawn_shell(void) { system("/bin/sh -c id"); }  /* the only system() caller */
static int mul(int a, int b) { return a * b; }
int main(int argc, char **argv) {
    log_msg("start");
    if (argc > 99) spawn_shell();
    printf("%d\n", add(mul(argc, 3), 1));
    return 0;
}
