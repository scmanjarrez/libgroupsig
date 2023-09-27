#include <string.h>
#include <stdio.h>

#include "utils.h"

void load_hw() {
  int v = 1;

#if defined(PYNQZ2)
  int Status;
  FILE *bptr;
  char* bitstream_file = "/home/xilinx/RoT_demo_4.0_Z2/bit/SPIRS_RoT.bit";
  if ((bptr = fopen(bitstream_file, "r"))) {
    fclose(bptr);
  } else {
    printf("\n   Bitstream doesn't exist. Bye ...\n\n");
    exit(ERROR);
  }
  if (v >= 1) printf("\n   Loading Bitstream ...");
  Status = PYNQ_loadBitstream(bitstream_file);
  if (Status != SUCCESS) {
    printf("LoadBitstream Failure\n");
    return ERROR;
  }
  if (v >= 1) printf(" done \n");
#endif
}

int main(int argc, char **argv) {
  int err = 0;

#ifdef HW
  load_hw()
#endif

  if (argc != 2) {
    err++;
  } else {
    if (!strcmp(argv[1], "kty04")) {
      kty04_test();
    } else if (!strcmp(argv[1], "ps16")) {
      ps16_test();
    /* } else if (!strcmp(argv[1], "dl21seq")) { */
      /* dl21seq_test(); */
    } else if (!strcmp(argv[1], "kty04_benchmark")) {
      kty04_benchmark();
    /* } else if (!strcmp(argv[1], "dl21seq")) { */
      /* dl21seq_test(); */
    } else if (!strcmp(argv[1], "ps16_benchmark")) {
      ps16_benchmark();
    /* } else if (!strcmp(argv[1], "dl21seq")) { */
      /* dl21seq_test(); */
    } else {
      err++;
    }
  }

  if (err) {
    printf("Usage: %s [kty04|ps16|kty04_benchmark|ps16_benchmark]\n", argv[0]);
    return -1;
  }

  return 0;
}
