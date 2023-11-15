/****************************************************************************************/
/*
 *  file_hw.c
 *
 *  Created on: 28/03/2023
 *  Authors: macarena@imse-cnm.csic.es and sergio.galan@csic.es
 */
/****************************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef HW3
#include "sha3_hw.h"
#include "params3.h"
#else
#include "sha2_hw.h"
#include "params.h"
#endif
#include "mmio.h"
#include "file_hw.h"
#if defined(PYNQ)
  #include <pynq_api.h>
#endif

unsigned char* ull_to_bytes(unsigned long long* ulls, int len) {
  int num_bytes = len * sizeof(unsigned long long);
  unsigned char* result = calloc(num_bytes, sizeof(unsigned char));
  unsigned char* aux_ptr = result;

  for (int i = 0; i < len; i++) {
    unsigned long long ull = ulls[i];
    for (int j = 0; j < sizeof(unsigned long long); j++) {
      *(aux_ptr++) = (ull >> ((sizeof(unsigned long long) - j - 1) * 8)) & 0xFF;
    }
  }
  return result;
}

unsigned char* ui_to_bytes(unsigned int* uis, int len) {
  int num_bytes = len * sizeof(unsigned int);
  unsigned char* result = calloc(num_bytes, sizeof(unsigned char));
  unsigned char* aux_ptr = result;

  for (int i = 0; i < len; i++) {
    unsigned int ui = uis[i];
    for (int j = 0; j < sizeof(unsigned int); j++) {
      *(aux_ptr++) = (ui >> ((sizeof(unsigned int) - j - 1) * 8)) & 0xFF;
    }
  }
  return result;
}

unsigned long long* bytes_to_ull(unsigned char *bytes, int len) {
  int len_ull = len/sizeof(unsigned long long);
  if(len%sizeof(unsigned long long)) {
    len_ull++;
  }
  int counter_ull = len_ull - 1;
  int j = 0;
  unsigned long long *ret = calloc(len_ull, sizeof(unsigned long long));
  for(int i = len - 1; i > -1; i--) {
    ret[counter_ull] +=  ((unsigned long long) bytes[i]) << (8 * j);
    j++;
    if(j == sizeof(unsigned long long)) {
      counter_ull--;
      j = 0;
    }
  }
  return ret;
}


unsigned int* bytes_to_uint(unsigned char *bytes, int len) {
  int len_uint = len/sizeof(unsigned int);
  if(len%sizeof(unsigned int)) {
    len_uint++;
  }
  int counter_uint = len_uint - 1;
  int j = 0;
  unsigned int *ret = calloc(len_uint, sizeof(unsigned int));
  for(int i = len - 1; i > -1; i--) {
    ret[counter_uint] +=  ((unsigned int) bytes[i])<< (8 * j);
    j++;
    if(j == sizeof(unsigned int)) {
      counter_uint--;
      j = 0;
    }
  }
  return ret;
}


unsigned char* hash_message_hw(unsigned char* msg, int msg_len){
  int v = 1;
  MMIO_WINDOW ms2xl;
  createMMIOWindow(&ms2xl, MS2XL_BASEADDR, MS2XL_LENGTH);

  unsigned char* in = malloc(sizeof(unsigned char) * SIZE_INPUT);
  unsigned char out_hw[SIZE_OUTPUT];

  for (int i = 0; i < msg_len; i++) in[i] = msg[i];
  unsigned long long length_byte = 8 * msg_len;

  int DBG = 0;
  if (DBG) printf("Data to be sent to sha256_hw:\nin=%s\nmsg_len=%lld\n",
                  in, length_byte);
#ifdef HW3
  sha3_hw(in, out_hw, length_byte, ms2xl, DBG);
#else
  sha2_hw(in, out_hw, length_byte, ms2xl, DBG);
#endif

  unsigned char * hashed_msg;
  hashed_msg = malloc(sizeof(unsigned char) * SIZE_OUTPUT);
  memcpy(hashed_msg, out_hw, SIZE_OUTPUT);
  return hashed_msg;
}
