/* GROUND TRUTH: bug, CWE-120 (memcpy with attacker-controlled length) at line 7 */
#include <string.h>
#include <stdlib.h>

char *clone(const char *src, unsigned long n) {
    char *dst = malloc(32);
    memcpy(dst, src, n);   /* BUG: n not validated against 32 */
    return dst;
}
