#include <openssl/bn.h>
#include <openssl/rand.h>

#include "utils.h"


uint64_t TIMES[N_BENCH];
uint64_t **TIMES_JOIN;
int MEMBERS = 10;
int ITER = 5;
char *PATH = ".";


int multi_mgrkey(char *scheme) {
  if (!strcmp(scheme, "klap20") || !strcmp(scheme, "gl19"))
    return 1;
  return 0;
}

int group1_implemented(char *scheme) {
  // This group implements 'open' function
  if (!strcmp(scheme, "dl21") || !strcmp(scheme, "dl21seq") || !strcmp(scheme, "gl19"))
    return 0;
  return 1;
}

int group2_implemented(char *scheme) {
  // This group implements 'open_verify' function
  if (!strcmp(scheme, "klap20") || !strcmp(scheme, "ps16"))
    return 1;
  return 0;
}

int group3_implemented(char *scheme) {
  // This group implements 'reveal, trace, claim, claim_verify,
  // prove_equality, prove_equality_verify' functions
  if (!strcmp(scheme, "cpy06") || !strcmp(scheme, "kty04"))
    return 1;
  return 0;
}

int group4_implemented(char *scheme) {
  // This group implements 'blind, convert, unblind' functions
  if (!strcmp(scheme, "gl19"))
    return 1;
  return 0;
}

int group5_implemented(char *scheme) {
  // This group implements 'identify, link, verify_link' functions
  if (!strcmp(scheme, "dl21") || !strcmp(scheme, "dl21seq"))
    return 1;
  return 0;
}

int group6_implemented(char *scheme) {
  // This group implements 'seqlink, verify_seqlink' functions
  if (!strcmp(scheme, "dl21seq"))
    return 1;
  return 0;
}

void random_seed() {
  /* Set seed */
  unsigned char buffer[2048];
  FILE* fd = fopen("/dev/urandom", "r");
  fread(buffer, 1, 2048, fd);
  fclose(fd);
  RAND_seed(buffer, 2048);
  srand(time(0));
}
