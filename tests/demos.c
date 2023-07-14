#include <string.h>
#include <stdio.h>

#include "utils.h"

int main(int argc, char **argv) {
  int err = 0;

  if (argc != 2) {
    err++;
  } else {
    if (!strcmp(argv[1], "kty04")) {
      kty04_test();
    } else if (!strcmp(argv[1], "ps16")) {
      ps16_test();
    /* } else if (!strcmp(argv[1], "dl21seq")) { */
      /* dl21seq_test(); */
    } else {
      err++;
    }
  }

  if (err) {
    printf("Usage: %s [kty04|ps16]\n", argv[0]);
    return -1;
  }

  return 0;
}
