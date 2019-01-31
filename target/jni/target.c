#include <stdio.h>
#include <stdlib.h>
int main(int argc, char const* argv[]) {
  int x = 1;
  while (x) {
    printf("%s\n", "Sleep ...");
    sleep(10);
  }
  return 0;
}
