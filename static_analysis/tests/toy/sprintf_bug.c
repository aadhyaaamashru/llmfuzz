/* GROUND TRUTH: bug, CWE-787 (unbounded sprintf into fixed buffer) at line 7 */
#include <stdio.h>

void format_id(int id, const char *suffix) {
    char out[8];
    sprintf(out, "%d-%s", id, suffix);   /* BUG: out may overflow */
    printf("%s\n", out);
}

int main(int argc, char **argv) {
    if (argc > 1) format_id(1, argv[1]);
    return 0;
}
