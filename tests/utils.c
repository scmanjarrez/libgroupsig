#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include "utils.h"


const char* correct_value(int val) {
  if (val == 1)
    return "✔";
  return "𐄂";
}

void check_randomness() {
  /* Setting seed */
  unsigned char buffer[2048];
  FILE* fd = fopen("/dev/urandom", "r");
  fread(buffer, 1, 2048, fd);
  fclose(fd);

  RAND_seed(buffer, 2048);
  BIGNUM *rnd = BN_new();
  int bits = 10, _rc = 255;
  printf("##### Testing OpenSSL randomness\n");
  for (int i=0; i<5; i++) {
    printf("Iteration[%d] rc: ", i);
    _rc = BN_rand(rnd, bits, -1, false);
    printf("%d ", _rc);
    char *chr = BN_bn2dec(rnd);

    printf("BIGNUM: %s\n", chr);
    free(chr);
  }
  BN_free(rnd);
}


void print_time(char *prefix, clock_t start, clock_t end) {
  printf("%stime: %.8f sec\n", prefix,
         ((double) (end - start)) / CLOCKS_PER_SEC);
}

void print_exp_rc(char *prefix, int value) {
  printf("%src expected (v:%d==e:%d)?: %s\n",
         prefix, value, IOK, correct_value(value == IOK));
}

void print_exp_ptr(char *prefix, void *pointer) {
  printf("%s expected?: %s\n", prefix, correct_value(pointer != NULL));
}

void print_exp_ret(char *prefix, uint32_t value, int expected) {
  printf("%sreturn expected (v:%d==e:%d)?: %s\n",
         prefix, value, expected, correct_value(value == expected));
}

void print_to_str(char *prefix, char *str) {
  printf("%s to_string:\n%s\n", prefix, str);
}


int b_write_csv(int num_members, clock_t* times, uint8_t scheme){
  FILE *fpt;

  fpt = fopen("MyFile.csv", "a");
  fprintf(fpt,"%d,%u,", num_members, scheme);
  for (int i = 0; i < B_NUM; i++){
    fprintf(fpt,"%ld", times[i]);
    if (i != (B_NUM - 1)){
      fprintf(fpt,",");
    }
  }
  fprintf(fpt,"\n");
  fclose(fpt);
  return 0;
}


groupsig_key_t* new_member_key( groupsig_key_t *grpkey,
                          groupsig_key_t *mgrkey,
                          gml_t *gml,
                          crl_t *crl){

  uint8_t rc=255;
  groupsig_key_t *memkey = NULL;

  if (grpkey->scheme == GROUPSIG_KTY04_CODE){



    memkey = groupsig_mem_key_init(grpkey->scheme);


    print_exp_ptr("memkey", memkey);
    print_to_str("memkey", groupsig_mem_key_to_string(memkey));
    print_to_str("grpkey", groupsig_grp_key_to_string(grpkey));

    printf("\n##### Testing msg_init\n");
    message_t *msg0, *msg1;
    msg0 = message_init();
    msg1 = message_init();

    print_exp_ptr("msg0", msg0);
    print_exp_ptr("msg1", msg1);


    printf("\n##### Testing join_mem (0)\n");

    rc = groupsig_join_mem(&msg0, memkey, 0, NULL, grpkey);

    print_exp_rc("", rc);

    printf("\n##### Testing join_mgr (1)\n");

    rc = groupsig_join_mgr(&msg1, gml, mgrkey, 1, msg0, grpkey);
    groupsig_mem_key_free(memkey); memkey = NULL;

    memkey = groupsig_mem_key_import(grpkey->scheme, msg1->bytes, msg1->length);

    print_exp_rc("", rc);

    message_free(msg0); msg0 = NULL;
    message_free(msg1); msg1 = NULL;

  } else if (grpkey->scheme == GROUPSIG_PS16_CODE){



    uint8_t rc=255;

    message_t *msg0_mem1, *msg1_mem1, *msg2_mem1, *msg3_mem1, *msg4_mem1;

    msg0_mem1 = message_init();
    msg1_mem1 = message_init();
    msg2_mem1 = message_init();
    msg3_mem1 = message_init();
    msg4_mem1 = message_init();

    memkey = groupsig_mem_key_init(grpkey->scheme);

    groupsig_join_mgr(&msg1_mem1, gml, mgrkey, 0, msg0_mem1, grpkey);
    groupsig_join_mem(&msg2_mem1, memkey, 1, msg1_mem1, grpkey);
    groupsig_join_mgr(&msg3_mem1, gml, mgrkey, 2, msg2_mem1, grpkey);
    groupsig_join_mem(&msg4_mem1, memkey, 3, msg3_mem1, grpkey);

    print_exp_rc("", rc);

    message_free(msg0_mem1); msg0_mem1 = NULL;
    message_free(msg1_mem1); msg1_mem1 = NULL;
    message_free(msg2_mem1); msg2_mem1 = NULL;
    message_free(msg3_mem1); msg3_mem1 = NULL;
    message_free(msg4_mem1); msg4_mem1 = NULL;



    } else {
      printf("ERROR: KEY NOT MATCHED SCHEME");
    }

    print_to_str("memkey", groupsig_mem_key_to_string(memkey));
    return memkey;

  }

groupsig_signature_t* new_member_signature(char* str, groupsig_key_t *memkey, groupsig_key_t *grpkey){
  message_t *msg = message_from_string(str);
  groupsig_signature_t *sig;
  int rc;

  print_to_str("memkey", groupsig_mem_key_to_string(memkey));
  print_to_str("grpkey", groupsig_grp_key_to_string(grpkey));
  sig = groupsig_signature_init(memkey->scheme);
  rc = groupsig_sign(sig, msg, memkey, grpkey, UINT_MAX);

  print_exp_rc("A:", rc);

  message_free(msg); msg = NULL;
  return sig;
}

uint8_t verify_member_signature(groupsig_signature_t *sig,  char *str, groupsig_key_t *grpkey){
  uint8_t ret = 0, rc = 0;
  message_t *msg = message_from_string(str);
  rc = groupsig_verify(&ret, sig, msg, grpkey);
  print_exp_rc("", rc);

  message_free(msg); msg = NULL;
  return ret;
}

groupsig_proof_t* prove_equality(groupsig_signature_t *sig0, groupsig_signature_t *sig1, groupsig_key_t *memkey, groupsig_key_t *grpkey){
  groupsig_proof_t *proof;
  groupsig_signature_t *sigs[2];
  uint8_t rc = 255;

  proof = groupsig_proof_init(grpkey->scheme);

  sigs[0] = sig0;
  sigs[1] = sig1;

  rc = groupsig_prove_equality(proof, memkey, grpkey, sigs, 2);
  print_exp_rc("", rc);

  return proof;

}

uint8_t verify_proof_equality(groupsig_proof_t *proof, groupsig_signature_t *sig0, groupsig_signature_t *sig1, groupsig_key_t *grpkey){
  uint8_t ret = 255, rc = 255;

  groupsig_signature_t *sigs[2];
  sigs[0] = sig0;
  sigs[1] = sig1;

  rc = groupsig_prove_equality_verify(&ret, proof, grpkey, sigs, 2);
  print_exp_rc("", rc);

  return ret;
}


uint8_t trace_signature(groupsig_signature_t *sig, groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml, crl_t *crl){
  uint8_t ret = 255, rc = 255;
  rc = groupsig_trace(&ret, sig, grpkey, crl, mgrkey, gml);
  print_exp_rc("", rc);

  return ret;
}


uint64_t open_signature(groupsig_proof_t **proof_p, groupsig_signature_t *sig, groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml, crl_t *crl){
  uint8_t ret = 255, rc = 255;
  uint64_t idx = -1;

  *proof_p = groupsig_proof_init(grpkey->scheme);
  printf("Z: 0x: %p\n", *proof_p);
  rc = groupsig_open(&idx, *proof_p, crl, sig, grpkey, mgrkey, gml);
  print_exp_rc("", rc);

  print_exp_ptr("A: proof_op", *proof_p);
  printf("Ap: 0x: %p\n", proof_p);
  printf("Av: 0x: %p\n", *proof_p);
  return idx;
}

uint8_t open_verify(groupsig_proof_t *proof, groupsig_signature_t *sig, groupsig_key_t *grpkey){
  uint8_t ret = 255, rc = 255;
  print_exp_ptr("D: proof_op:", proof);
  printf("Dv: 0x: %p\n", proof);
  rc = groupsig_open_verify(&ret, proof, sig, grpkey);
  print_exp_rc("", rc);
  print_exp_ret("", (uint32_t) ret, 1);
  return ret;
}

char* reveal_signature(groupsig_key_t *memkey,  gml_t *gml, crl_t *crl, int i){
  uint8_t ret = 255, rc = 255;
  trapdoor_t *trapdoor = NULL;
  trapdoor = trapdoor_init(memkey->scheme);
  rc = groupsig_reveal(trapdoor, crl, gml, i);
  print_exp_rc("", rc);

  char *str_aux;
  str_aux = bigz_get_str16(*(bigz_t *)trapdoor->trap);
  trapdoor_free(trapdoor);
  return str_aux;
}

groupsig_proof_t* claim_signatures(groupsig_signature_t *sig, groupsig_key_t *memkey, groupsig_key_t* grpkey){
  groupsig_proof_t *proof;
  uint8_t rc = 255;
  proof = groupsig_proof_init(grpkey->scheme);

  rc = groupsig_claim(proof, memkey, grpkey, sig);
  print_exp_rc("", rc);

  return proof;
}

uint8_t claim_verify_signatures(groupsig_proof_t *proof, groupsig_signature_t *sig, groupsig_key_t* grpkey){
  uint8_t ret = 255, rc = 255;
  rc = groupsig_claim_verify(&ret, proof, sig, grpkey);
  print_exp_rc("", rc);

  return ret;
}


/* void dl21seq_test(void); */
