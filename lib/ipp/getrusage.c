
// gcc -o getrusage getrusage.c -lproc

#include <stdio.h>
#include <proc/readproc.h>

int main() {
  struct proc_t usage;
  look_up_our_self(&usage);
  printf("usage: %lu\n", usage.vsize);
}
