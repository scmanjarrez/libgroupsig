#ifndef UTILS_H
#define UTILS_H

#define IOK 0
#define IERROR 1

#include <time.h>
#include <stdint.h>

#ifndef TESTSCHEMES
#define TESTSCHEMES
#include "ps16.h"
#include "kty04.h"
#endif

#define B_NUM 17
#define B_GRP_INIT 0
#define B_NEW_GRPKEY 1
#define B_NEW_MGRKEY 2
#define B_NEW_GML 3
#define B_NEW_CRL 4
#define B_GRP_SETUP 5
#define B_NEW_MEMKEY 6
#define B_NEW_SIGN 7
#define B_NEW_SIGN_VERIFY 8
#define B_PROVE_EQ 9
#define B_PROVE_EQ_VERIFY 10
#define B_TRACE 11
#define B_OPEN 12
#define B_OPEN_VERIFY 13
#define B_REVEAL 14
#define B_CLAIM 15
#define B_CLAIM_VERIFY 16

const char* correct_value(int val);

void print_time(char *prefix, clock_t start, clock_t end);

void print_exp_rc(char *prefix, int value);

void print_exp_ptr(char *prefix, void *pointer);

void print_exp_ret(char *prefix, uint32_t value, int expected);

void print_to_str(char *prefix, char *str);

void kty04_test(void);

void ps16_test(void);

void kty04_benchmark(void);

void ps16_benchmark(void);

int b_write_csv(int num_members, clock_t* times, uint8_t scheme);

groupsig_key_t* new_member_key( groupsig_key_t *grpkey,
                          groupsig_key_t *mgrkey,
                          gml_t *gml, 
                          crl_t *crl);

groupsig_signature_t* new_member_signature(char* str, groupsig_key_t *memkey, groupsig_key_t *grpkey);

uint8_t verify_member_signature(groupsig_signature_t *sig,  char *str, groupsig_key_t *grpkey);

groupsig_proof_t* prove_equality(groupsig_signature_t *sig0, groupsig_signature_t *sig1, groupsig_key_t *memkey, groupsig_key_t *grpkey);

uint8_t verify_proof_equality(groupsig_proof_t *proof, groupsig_signature_t *sig0, groupsig_signature_t *sig1, groupsig_key_t *grpkey);

uint8_t trace_signature(groupsig_signature_t *sig, groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml, crl_t *crl);

uint64_t open_signature(groupsig_proof_t **proof_p, groupsig_signature_t *sig, groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml, crl_t *crl);

uint8_t open_verify(groupsig_proof_t *proof, groupsig_signature_t *sig, groupsig_key_t *grpkey);

char* reveal_signature(groupsig_key_t *memkey,  gml_t *gml, crl_t *crl, int i);

groupsig_proof_t* claim_signatures(groupsig_signature_t *sig, groupsig_key_t *memkey, groupsig_key_t* grpkey);

uint8_t claim_verify_signatures(groupsig_proof_t *proof, groupsig_signature_t *sig, groupsig_key_t* grpkey);

#endif
