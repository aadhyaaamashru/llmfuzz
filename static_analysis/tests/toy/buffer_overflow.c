/* GROUND TRUTH: bug, CWE-120/787 (stack buffer overflow via strcpy) at line 8 */
#include <string.h>
#include <stdio.h>

void copy_name(const char *input) {
    char name[16];
    strcpy(name, input);   /* BUG: input may exceed 16 bytes */
    printf("%s\n", name);
}

int main(int argc, char **argv) {
    if (argc > 1) copy_name(argv[1]);
    return 0;
}
