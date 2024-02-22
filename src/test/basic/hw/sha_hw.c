#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#include "file_hw.h"

typedef unsigned char byte_t;

byte_t* hash_message(byte_t *m, int m_len) {
  byte_t *hash = NULL;
  hash = malloc(256*sizeof(byte_t));
  if(!hash) {
    fprintf(stderr, "Error allocating memory\n");
    return NULL;
  }
  SHA256(m, m_len, hash);
  return hash;
}

int load_hw(){
#if defined(PYNQZ2)
  int Status;
  FILE *bptr;
  char* bitstream_file = "/home/xilinx/RoT_demo_4.0_Z2/bit/SPIRS_RoT.bit";

  printf("Before bitstream open\n");
  if ((bptr = fopen(bitstream_file, "r"))) {
    fclose(bptr);
  } else {
    printf("Bitstream doesn't exist\n");
    exit(ERROR);
  }
  printf("After bitstream open\n");

  printf("Before bitstream load\n");
  Status = PYNQ_loadBitstream(bitstream_file);
  if (Status != SUCCESS) {
    printf("Bitstream couldn't be loaded\n");
    exit(ERROR);
  }
  printf("After bitstream load\n");
#endif
  return 0;
}

int main() {
  load_hw();
  printf("SIZE_INPUT: %d\n", SIZE_INPUT);
  printf("SIZE_OUTPUT: %d\n", SIZE_OUTPUT);
  byte_t msg[] = {'h', 'e', 'l', 'l', 'o'};
  /* byte_t msg[] = "F9TeZz2oY9kziDmsLx2biDp5RE7uups7HVxrwYpgUBv3eaKtAa3sg6ib47FdY4t"; */
  size_t len = strlen(msg);
  printf("Message size: %dB\n", len);
  byte_t *hashed = (byte_t *) hash_message(msg, len);
  printf("Hash SW: ");
  for (size_t i = 0; i < SIZE_OUTPUT; i++)
    printf("%02X ", (unsigned int) hashed[i]);
  printf("\n");

  byte_t *hashed_hw = (byte_t *) hash_message_hw(msg, len);
  printf("Hash HW: ");
  for (size_t i = 0; i < SIZE_OUTPUT; i++)
   printf("%02X ", (unsigned int) hashed_hw[i]);
  printf("\n");
  return 0;
}
