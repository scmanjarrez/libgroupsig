#include "groupsig.h"

const char* correct_value(int val)
{
  if (val == 1) {
    return "✔";
  } else {
    return "𐄂";
  }
}

void print_gml(byte_t *bytes, uint32_t size) {
  printf("### printing gml ###\n");
  printf("gml (size): %d\n", size);
  printf("gml (bytes): ");
  if (size != sizeof(uint64_t)) {
    int i = 0;
    for (i = sizeof(uint64_t); i < size; i++)
      {
        if (i > sizeof(uint64_t)) printf(":");
        printf("%02X", bytes[i]);
      }
    printf("\n");
  } else {
    printf("empty\n");
  }
}

int main () {
  clock_t start, end;
  int rc = 255;
  uint8_t code = GROUPSIG_KTY04_CODE;

  printf("\n##### Testing mgr_key_init\n");
  groupsig_key_t *mgrkey;
  start = clock();
  mgrkey = groupsig_mgr_key_init(code);
  end = clock();
  printf("mgr_key_to_string:\n%s", groupsig_mgr_key_to_string(mgrkey));
  printf("mgr_key_init time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing grp_key_init\n");
  groupsig_key_t *grpkey;
  start = clock();
  grpkey = groupsig_grp_key_init(code);
  end = clock();
  printf("grp_key_to_string:\n%s", groupsig_grp_key_to_string(grpkey));
  printf("grp_key_init time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing gml_init\n");
  gml_t *gml;
  start = clock();
  gml = gml_init(code);
  end = clock();
  printf("gml_init time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  /* printf("\n***** Testing gml_entry_init *****\n"); */
  /* gml_entry_t *entry; */
  /* entry = gml_entry_init(code); */

  /* printf("\n***** Testing gml_insert *****\n"); */
  /* rc = gml_insert(gml, entry); */
  /* printf("gml_insert rc: %d\n", rc); */
  /* printf("gml->n: %ld\n", gml->n); */

  /* printf("\n***** Testing gml_export *****\n"); */
  /* byte_t *bytes, *bytes2; */
  /* uint32_t size, size2; */
  /* gml_export(&bytes, &size, gml); */
  /* /\* gml_entry_to_string(gml->entries[0]); *\/ */
  /* print_gml(bytes, size); */

  /* printf("\n***** Testing gml_import *****\n"); */
  /* gml_t *gml2; */
  /* gml2 = gml_import(code, bytes, size); */

  /* printf("\n***** Testing gml_export (after import) *****\n"); */
  /* gml_export(&bytes2, &size2, gml2); */
  /* print_gml(bytes2, size2); */

  printf("\n##### Testing crl_init\n");
  crl_t *crl;
  start = clock();
  crl = crl_init(code);
  end = clock();
  printf("crl_init time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing groupsig_setup\n");
  start = clock();
  rc = groupsig_setup(code, grpkey, mgrkey, gml);
  end = clock();
  printf("setup rc: %d\n", rc);
  printf("setup time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing mem_key_init\n");
  groupsig_key_t *memkey;
  start = clock();
  memkey = groupsig_mem_key_init(grpkey->scheme);
  end = clock();
  printf("mem_key_to_string:\n%s", groupsig_mem_key_to_string(memkey));
  printf("mem_key_init time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing msg_init\n");
  message_t *m1, *m2;
  start = clock();
  m1 = message_init();
  end = clock();
  printf("msg1_init time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);
  start = clock();
  m2 = message_init();
  end = clock();
  printf("msg2_init time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing join_mem\n");
  start = clock();
  rc = groupsig_join_mem(&m1, memkey, 0, NULL, grpkey);
  end = clock();
  printf("join_mem rc: %d\n", rc);
  printf("join_mem time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing join_mgr\n");
  start = clock();
  rc = groupsig_join_mgr(&m2, gml, mgrkey, 1, m1, grpkey);
  end = clock();
  printf("join_mgr rc: %d\n", rc);
  printf("join_mgr time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing mem_key_import\n");
  start = clock();
  memkey = groupsig_mem_key_import(code, m2->bytes, m2->length);
  end = clock();
  printf("mem_key_to_string:\n%s", groupsig_mem_key_to_string(memkey));
  printf("mem_key_import time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing sign & verify - correct message\n");
  message_t *msg1;
  groupsig_signature_t *sig1;
  msg1 = message_from_string((char *) "Hello, World!");
  start = clock();
  sig1 = groupsig_signature_init(grpkey->scheme);
  end = clock();
  printf("signature_init time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);
  start = clock();
  rc = groupsig_sign(sig1, msg1, memkey, grpkey, UINT_MAX);
  end = clock();
  printf("sign rc: %d\n", rc);
  printf("sign time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  uint8_t ret1 = 255;
  start = clock();
  rc = groupsig_verify(&ret1, sig1, msg1, grpkey);
  end = clock();
  printf("verify rc: %d\n", rc);
  printf("verify return (1): %d\n", ret1);
  printf("verify correct?: %s\n", correct_value(ret1==1));
  printf("verify time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing sign & verify - incorrect message\n");
  message_t *msg2;
  groupsig_signature_t *sig2;
  msg2 = message_from_string((char *) "Hello, Worlds!");
  start = clock();
  sig2 = groupsig_signature_init(grpkey->scheme);
  end = clock();
  printf("signature_init time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);
  start = clock();
  rc = groupsig_sign(sig2, msg2, memkey, grpkey, UINT_MAX);
  end = clock();
  printf("sign rc: %d\n", rc);
  printf("sign time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  // verify using incorrect signature (sig1)
  uint8_t ret2 = 255;
  start = clock();
  rc = groupsig_verify(&ret2, sig1, msg2, grpkey);
  end = clock();
  printf("verify rc: %d\n", rc);
  printf("verify return (0): %d\n", ret2);
  printf("verify expected?: %s\n", correct_value(ret2==0));
  printf("verify time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing proof_init\n");
  groupsig_signature_t *sigs[1];
  groupsig_proof_t *proof1;
  start = clock();
  proof1 = groupsig_proof_init(grpkey->scheme);
  end = clock();
  printf("proof_init time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing prove_equality\n");
  sigs[0] = sig1;
  start = clock();
  rc = groupsig_prove_equality(proof1, memkey, grpkey, sigs, 1);
  end = clock();
  printf("prove_equality rc: %d\n", rc);
  printf("prove_equality time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing prove_equality_verify - correct signature\n");
  uint8_t ret3 = 255;
  start = clock();
  rc = groupsig_prove_equality_verify(&ret3, proof1, grpkey, sigs, 1);
  end = clock();
  printf("prove_equality_verify rc: %d\n", rc);
  printf("prove_equality_verify return (1): %d\n", ret3);
  printf("prove_equality_verify expected?: %s\n", correct_value(ret3==1));
  printf("prove_equality_verify time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing prove_equality_verify - incorrect signature\n");
  sigs[0] = sig2;
  uint8_t ret4 = 255;
  start = clock();
  rc = groupsig_prove_equality_verify(&ret4, proof1, grpkey, sigs, 1);
  end = clock();
  printf("prove_equality_verify rc: %d\n", rc);
  printf("prove_equality_verify return (0): %d\n", ret4);
  printf("prove_equality_verify expected?: %s\n", correct_value(ret4==0));
  printf("prove_equality_verify time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing trace - not revealed user\n");
  sigs[0] = sig1;
  uint8_t ret5 = 255;
  start = clock();
  rc = groupsig_trace(&ret5, sig1, grpkey, crl, mgrkey, gml);
  end = clock();
  printf("trace rc: %d\n", rc);
  printf("trace return (0): %d\n", ret5);
  printf("trace expected?: %s\n", correct_value(ret5==0));
  printf("trace time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing open\n");
  uint64_t idx = 255;
  start = clock();
  rc = groupsig_open(&idx, proof1, crl, sig1, grpkey, mgrkey, gml);
  end = clock();
  printf("open rc: %d\n", rc);
  printf("open index: %lu\n", idx);
  printf("open time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing trapdoor_init\n");
  trapdoor_t *trapdoor = NULL;
  start = clock();
  trapdoor = trapdoor_init(memkey->scheme);
  end = clock();
  printf("trapdoor_init time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing reveal\n");
  start = clock();
  rc = groupsig_reveal(trapdoor, crl, gml, 0);
  end = clock();
  printf("reveal rc: %d\n", rc);
  char *str_aux;
  str_aux = bigz_get_str16(*(bigz_t *)trapdoor->trap);
  printf("reveal trapdoor->trap: %s\n", str_aux);
  printf("reveal time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing trace - revealed user\n");
  uint8_t ret6 = 255;
  start = clock();
  rc = groupsig_trace(&ret6, sig1, grpkey, crl, mgrkey, gml);
  end = clock();
  printf("trace rc: %d\n", rc);
  printf("trace return (1): %d\n", ret6);
  printf("trace expected?: %s\n", correct_value(ret6==1));
  printf("trace time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing claim\n");
  groupsig_proof_t *proof2;
  start = clock();
  proof2 = groupsig_proof_init(grpkey->scheme);
  end = clock();
  printf("proof_init time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);
  start = clock();
  rc = groupsig_claim(proof2, memkey, grpkey, sig1);
  end = clock();
  printf("claim rc: %d\n", rc);
  printf("clain time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing claim_verify - correct signature\n");
  uint8_t ret7 = 255;
  start = clock();
  rc = groupsig_claim_verify(&ret7, proof2, sig1, grpkey);
  end = clock();
  printf("claim verify rc: %d\n", rc);
  printf("claim verify return (1): %d\n", ret7);
  printf("claim_verify expected?: %s\n", correct_value(ret7==1));
  printf("claim_verify time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  printf("\n##### Testing claim_verify - incorrect signature\n");
  uint8_t ret8 = 255;
  start = clock();
  rc = groupsig_claim_verify(&ret8, proof2, sig2, grpkey);
  end = clock();
  printf("claim_verify rc: %d\n", rc);
  printf("claim_verify return (0): %d\n", ret8);
  printf("claim_verify expected?: %s\n", correct_value(ret8==0));
  printf("claim_verify time: %.8f sec\n", ((double) (end - start)) / CLOCKS_PER_SEC);

  groupsig_mgr_key_free(mgrkey); mgrkey = NULL;
  groupsig_grp_key_free(grpkey); grpkey = NULL;
  groupsig_mem_key_free(memkey); memkey = NULL;
  gml_free(gml); gml = NULL;
  crl_free(crl); crl = NULL;
  message_free(m2); m2 = NULL;
  message_free(m1); m1 = NULL;
  trapdoor_free(trapdoor);
  groupsig_proof_free(proof1);
  groupsig_proof_free(proof2);
  groupsig_signature_free(sig1); sig1 = NULL;
  return 0;
}
