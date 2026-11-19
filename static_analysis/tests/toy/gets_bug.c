/* GROUND TRUTH: bug, CWE-242 (inherently dangerous gets()) at line 7 */
#include <stdio.h>

void read_line(void) {
    char buf[64];
    gets(buf);   /* BUG: gets() cannot be bounded */
    printf("%s\n", buf);
}

int main(void) {
    read_line();
    return 0;
}
