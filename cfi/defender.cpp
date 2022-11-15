/*      Ptrace-based Control Flow Integrity
*/

#define _POSIX_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

using namespace std;

bool enforcing = false;
string wlf = "cfi-whitelist.txt";
vector<uint32_t> addrs;

/* Handles Ctrl+C and dumps the allowed syscalls to a file.
   They can be loaded later and used to create access controlls for a process */
void save_table() {
  if (enforcing)
    return;

  ofstream whitelist;
  whitelist.open(wlf);

  if (whitelist.is_open()) {
    for (auto &eip : addrs) {
      whitelist << hex << eip << endl;
    }
  }
  whitelist.close();
  cout << "Saved CFI profile to " << wlf << endl;
  exit(0);
}

void load_table(void) {
  ifstream whitelist(wlf);
  if (whitelist.is_open()) {
    string line;
    while (getline(whitelist, line)) {
      uint32_t eip;
      stringstream ss(line);
      ss >> hex >> eip;

      addrs.push_back(eip);
    }
  }
  whitelist.close();
  cout << "Loaded CFI profile from " << wlf << endl;
}

void dbgLogTable() {
  printf("CFI Rule List:\n");
  for (auto& eip : addrs)
    printf("[EIP] %x\n", eip);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    printf("Usage: %s <analyze|enforce> <program> <args>\n", argv[0]);
    return 1;
  }

  char *mode_str = argv[1];
  char *exe = argv[2];
  char **args = argv + 2;

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
    //dbgLogTable();
  } else {
    // Set up the signal handler to save the syscall table
    signal(SIGINT, (void (*)(int)) save_table);
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
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
      break;
    if (waitpid(pid, 0, 0) < 0)
      break;

    // Get syscall arguments
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
      break;
    }
    uint32_t eip = regs.eip;

    if (!enforcing) {
      // Add this address to the learned range.
      addrs.push_back(eip);
    } else {
      // If this instruction pointer is outside the allowed control flow
      // the process will be killed.
      bool found = false;
      for (auto& i : addrs) {
        if (i == eip) {
          found = true;
          break;
        }
      }

      if (!found) {
        fprintf(stderr, 
          "Address 0x%x is outside the allowed control flow, killing process %d.\n",
          eip, pid);

        kill(pid, SIGKILL);
      }
    }
  }

  if (!enforcing)
    save_table();
}
