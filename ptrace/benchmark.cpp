/* Copyright 2021 Fotis Antonatos. See LICENSE */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#include <string>

#define NUM_WRITE 1

int
main(int argc, char **argv)
{
	std::string command;
	struct timeval start, end;
	
	for (int i = 1; i < argc; i++)
		command = std::string(command + " " + argv[i]);
	char c[500] = {'A'};

	gettimeofday(&start, NULL);
	
	for (int i = 0; i < NUM_WRITE; i++)
		read(0, c, 500);

	gettimeofday(&end, NULL);

	long delta = ((end.tv_sec - start.tv_sec)*1000000L+end.tv_usec) - start.tv_usec;

	printf("\nExecution Time: %ld μs\n", delta);
	printf("%lf microseconds per write\n", (double) delta / (double) NUM_WRITE);

	return 0;
}
