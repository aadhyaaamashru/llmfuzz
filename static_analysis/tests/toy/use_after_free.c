/* GROUND TRUTH: bug, CWE-416 (use-after-free) at line 8.
   NOTE: pattern-only rules MISS this — it needs dataflow (CodeQL) + the LLM.
   Kept here on purpose to show the blind spot the later stages fill. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = malloc(16);
    free(p);
    printf("%s\n", p);   /* BUG: p used after free */
    return 0;
}
