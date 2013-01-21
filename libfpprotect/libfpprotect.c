#include <stdio.h>

void foo() __attribute__ ((constructor));
void foo()
{
	puts("libfpprotect");
}
