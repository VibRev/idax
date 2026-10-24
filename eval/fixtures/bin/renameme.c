#include <stdio.h>
static int secret_adder(int a, int b) { return a + b + 1; }
int main(int argc, char **argv) { printf("%d\n", secret_adder(argc, 7)); return 0; }
