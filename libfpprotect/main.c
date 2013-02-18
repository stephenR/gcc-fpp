#include <stdio.h>

typedef void (*function_pointer_t)();

void foo(){
	puts("foo");
}

int main(__attribute((unused)) int argc,__attribute__((unused)) const char *argv[])
{
	function_pointer_t p = &foo;
	//char **x = ((char **) &p);
	//*x = (char *) &foo;
	(*p)();
	return 0;
}
