#define _POSIX_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/types.h>

char* wlf = "whitelist.txt";
#define MAX_SYSCALL 1000
bool syscall_allowed[MAX_SYSCALL] = { false };
bool enforcing = false;

/* Handles Ctrl+C and dumps the allowed syscalls to a file.
   They can be loaded later and used to create access controlls for a process */
void
save_table()
{
    if (enforcing)
	return;

    FILE* fp = fopen(wlf, "w");

    if (fp == NULL)
	perror("fopen"), exit(1);

    // Write the syscall numbers that are permitted
    for (int i = 0; i < MAX_SYSCALL; i++)
	if (syscall_allowed[i])
	    fprintf(fp, "%d\n", i);

    printf("Saved whitelist in %s\n", wlf);
    exit(0);
}

void
load_table(void)
{
    FILE* fp = fopen(wlf, "r");

    if (fp == NULL)
	perror("fopen"), exit(1);

    /* Reads the permitted syscall numbers from the syscall table file */

    for (int i = 0; i < MAX_SYSCALL; i++) {
	int num;
	fscanf(fp, "%d", &num);
	syscall_allowed[num] = true;
    }

    fclose(fp);
}

void
dbgLogTable()
{
    printf("System call whitelist:\n");
    for (int i = 0; i < MAX_SYSCALL; i++)
	if (syscall_allowed[i])
	    printf("Allow %d\n", i);
}

int
main(int argc, char** argv)
{
    if (argc < 3) {
	printf("Usage: %s <analyze|enforce> <program> <args>\n", argv[0]);
    }

    char* mode_str = argv[1];
    char* exe = argv[2];
    char** args = argv + 2;

    if (strcmp(mode_str, "analyze") == 0) {
	enforcing = false;
    } else if (strcmp(mode_str, "enforce") == 0) {
	enforcing = true;
    } else {
	printf("Invalid mode: %s\n", mode_str);
	exit(1);
    }

    printf("Running in %s mode\n", enforcing ? "enforce" : "analyze");
    if (enforcing) {
	// Load the syscall table from the file
	load_table();
        dbgLogTable();
    } else {
	// Set up the signal handler to save the syscall table
	signal(SIGINT, (void (*)(int))save_table);
    }

    printf("Launching %s\n", exe);

    pid_t pid = fork();
    if (pid == 0) {
	// Child process
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	execvp(exe, args);
    }

    if (pid < 0) {
	perror("fork");
	return 1;
    }

    // Parent process
    waitpid(pid, 0, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    for (;;) {
	// Wait for next syscall
	if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0)
	    break;
	if (waitpid(pid, 0, 0) < 0)
	    break;

	// Get syscall arguments
	struct user_regs_struct regs;
	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
	    break;
	}
	long syscall = regs.orig_eax;

	if (!enforcing) {
	    // Updating the syscall table
	    //printf("Allowing syscall %ld\n", syscall);
	    syscall_allowed[syscall] = true;
	} else {
	    if (syscall_allowed[syscall] == false) {
		// Child process is trying to use a blocked syscall
		// Kills child and all its children
		printf(
		  "Blocked syscall %ld, killing process %d\n", syscall, pid);

		kill(pid, SIGKILL);
		return 0;
	    }
	}

	// Run system call and stop on exit
	if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0)
	    break;
	if (waitpid(pid, 0, 0) < 0)
	    break;
    }

    if (!enforcing)
	save_table();
}
