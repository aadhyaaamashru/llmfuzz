/* GROUND TRUTH: NO bug — bounded copy. Should produce ZERO findings
   (false-positive check). */
#include <string.h>
#include <stdio.h>

void copy_name(const char *input) {
    char name[16];
    strncpy(name, input, sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    printf("%s\n", name);
}

int main(int argc, char **argv) {
    if (argc > 1) copy_name(argv[1]);
    return 0;
}
