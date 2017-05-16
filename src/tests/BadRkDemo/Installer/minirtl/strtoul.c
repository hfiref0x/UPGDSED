#include "rtltypes.h"

unsigned long strtoul_a(char *s)
{
    unsigned long long  a = 0;
    char                c;

    if (s == 0)
        return 0;

    while (*s != 0) {
        c = *s;
        if (_isdigit_a(c))
            a = (a*10)+(c-'0');
        else
            break;

        if (a > 0xffffffff)
            return 0xffffffff;

        s++;
    }
    return (unsigned long)a;
}

unsigned long strtoul_w(wchar_t *s)
{
    unsigned long long	a = 0;
    wchar_t			c;

    if (s == 0)
        return 0;

    while (*s != 0) {
        c = *s;
        if (_isdigit_w(c))
            a = (a * 10) + (c - L'0');
        else
            break;

        if (a > 0xffffffff)
            return 0xffffffff;

        s++;
    }
    return (unsigned long)a;
}
