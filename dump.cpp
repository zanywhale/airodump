#include "dump.h"
#include <stdint.h>
#include <stdio.h>

dumping::dumping(){}

void dumping::dumpCode(const char *buf, int len)
{
    int i;

    printf("%7s", "offset ");
    for (i = 0; i < 16; i++)
    {
        printf("%02x ", i);

        if (!(i % 16 - 7))
            printf("- ");
    }
    printf("\n\r");

    for (i = 0; i < len; i++)
    {
        if (!(i % 16))
            printf("0x%04x ", i);

        printf("%02x ", buf[i]&0xff);

        if (!(i % 16 - 7))
            printf("- ");

        if (!(i % 16 - 15))
        {
            putchar(' ');

            printf("\n\r");
        }
    }
    printf("\n\r");
}
