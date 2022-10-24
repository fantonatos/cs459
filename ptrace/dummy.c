#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NUM 1000

int
main()
{
    FILE* files[NUM] = { NULL };

    for (int i = 0; i < NUM; i++) {
	files[i] = fopen("/dev/null", "r");
	fclose(files[i]);
    }

    /* Comment these out and compile to generate a whitelist
     without fork and exec. */
    // fork();
    // char *argv = NULL;
    // execv("/bin/sh", &argv);

    return 0;
}
