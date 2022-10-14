#include "groupsig.h"

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
  int rc = 255;
  uint8_t code = GROUPSIG_KTY04_CODE;

  printf("***** Testing mgr_key_init *****\n");
  groupsig_key_t *mgrkey;
  mgrkey = groupsig_mgr_key_init(code);
  printf("mgr_key_to_string:\n%s", groupsig_mgr_key_to_string(mgrkey));

  printf("\n***** Testing grp_key_init *****\n");
  groupsig_key_t *grpkey;
  grpkey = groupsig_grp_key_init(code);
  printf("grp_key_to_string:\n%s", groupsig_grp_key_to_string(grpkey));

  printf("\n***** Testing gml_init *****\n");
  gml_t *gml;
  gml = gml_init(code);

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

  printf("\n***** Testing crl_init *****\n");
  crl_t *crl;
  crl = crl_init(code);
  // TODO crl export and import

  printf("\n***** Testing groupsig_setup *****\n");
  rc = groupsig_setup(code, grpkey, mgrkey, gml);
  printf("groupsig_setup rc: %d\n", rc);

  printf("\n***** Testing mem_key_init *****\n");
  groupsig_key_t *memkey;
  memkey = groupsig_mem_key_init(grpkey->scheme);
  printf("mem_key_to_string:\n%s", groupsig_mem_key_to_string(memkey));

  printf("\n***** Testing msg_init *****\n");
  message_t *m1, *m2;
  m1 = message_init();
  m2 = message_init();

  printf("\n***** Testing join_mem *****\n");
  rc = groupsig_join_mem(&m1, memkey, 0, NULL, grpkey);
  printf("join_mem rc: %d\n", rc);

  printf("\n***** Testing join_mgr *****\n");
  rc = groupsig_join_mgr(&m2, gml, mgrkey, 1, m1, grpkey);
  printf("join_mgr rc: %d\n", rc);

  printf("\n***** Testing mem_key_import *****\n");
  memkey = groupsig_mem_key_import(code, m2->bytes, m2->length);
  printf("mem_key_to_string:\n%s", groupsig_mem_key_to_string(memkey));

  printf("\n***** Testing sign & verify - correct message *****\n");
  message_t *msg1;
  groupsig_signature_t *sig1;
  msg1 = message_from_string((char *) "Hello, World!");
  sig1 = groupsig_signature_init(grpkey->scheme);
  rc = groupsig_sign(sig1, msg1, memkey, grpkey, UINT_MAX);
  printf("sign rc: %d\n", rc);

  uint8_t ret1 = 255;
  rc = groupsig_verify(&ret1, sig1, msg1, grpkey);
  printf("verify rc: %d\n", rc);
  printf("verify return (1): %d\n", ret1);
  printf("verify expected?: %d\n", ret1==1);

  printf("\n***** Testing sign & verify - incorrect message *****\n");
  message_t *msg2;
  groupsig_signature_t *sig2;
  msg2 = message_from_string((char *) "Hello, Worlds!");
  sig2 = groupsig_signature_init(grpkey->scheme);
  rc = groupsig_sign(sig2, msg2, memkey, grpkey, UINT_MAX);
  printf("sign rc: %d\n", rc);

  // verify using incorrect signature (sig1)
  uint8_t ret2 = 255;
  rc = groupsig_verify(&ret2, sig1, msg2, grpkey);
  printf("verify rc: %d\n", rc);
  printf("verify return (0): %d\n", ret2);
  printf("verify expected?: %d\n", ret2==0);

  printf("\n***** Testing proof_init *****\n");
  groupsig_signature_t *sigs[1];
  groupsig_proof_t *proof1;
  proof1 = groupsig_proof_init(grpkey->scheme);

  printf("\n***** Testing prove_equality *****\n");
  sigs[0] = sig1;
  rc = groupsig_prove_equality(proof1, memkey, grpkey, sigs, 1);
  printf("prove_equality rc: %d\n", rc);

  printf("\n***** Testing prove_equality_verify - correct signature *****\n");
  uint8_t ret3 = 255;
  rc = groupsig_prove_equality_verify(&ret3, proof1, grpkey, sigs, 1);
  printf("prove_equality_verify rc: %d\n", rc);
  printf("prove_equality_verify return (1): %d\n", ret3);
  printf("prove_equality_verify expected?: %d\n", ret3==1);

  printf("\n***** Testing prove_equality_verify - incorrect signature *****\n");
  sigs[0] = sig2;
  uint8_t ret4 = 255;
  rc = groupsig_prove_equality_verify(&ret4, proof1, grpkey, sigs, 1);
  printf("prove_equality_verify rc: %d\n", rc);
  printf("prove_equality_verify return (0): %d\n", ret4);
  printf("prove_equality_verify expected?: %d\n", ret4==0);

  printf("\n***** Testing trace - not revealed user *****\n");
  sigs[0] = sig1;
  uint8_t ret5 = 255;
  rc = groupsig_trace(&ret5, sig1, grpkey, crl, mgrkey, gml);
  printf("trace rc: %d\n", rc);
  printf("trace return (0): %d\n", ret5);
  printf("trace expected?: %d\n", ret5==0);

  printf("\n***** Testing open *****\n");
  uint64_t idx = 255;
  rc = groupsig_open(&idx, proof1, crl, sig1, grpkey, mgrkey, gml);
  printf("open rc: %d\n", rc);
  printf("open index: %lu\n", idx);

  printf("\n***** Testing trapdoor_init *****\n");
  trapdoor_t *trapdoor = NULL;
  trapdoor = trapdoor_init(memkey->scheme);

  printf("\n***** Testing reveal *****\n");
  rc = groupsig_reveal(trapdoor, crl, gml, 0);
  printf("reveal rc: %d\n", rc);
  char *str_aux;
  str_aux = bigz_get_str16(*(bigz_t *)trapdoor->trap);
  printf("reveal trapdoor->trap: %s\n", str_aux);

  printf("\n***** Testing trace - revealed user *****\n");
  uint8_t ret6 = 255;
  rc = groupsig_trace(&ret6, sig1, grpkey, crl, mgrkey, gml);
  printf("trace rc: %d\n", rc);
  printf("trace return (1): %d\n", ret6);
  printf("trace expected?: %d\n", ret6==1);

  printf("\n***** Testing claim *****\n");
  groupsig_proof_t *proof2;
  proof2 = groupsig_proof_init(grpkey->scheme);
  rc = groupsig_claim(proof2, memkey, grpkey, sig1);
  printf("claim rc: %d\n", rc);

  printf("\n***** Testing claim_verify - correct signature *****\n");
  uint8_t ret7 = 255;
  rc = groupsig_claim_verify(&ret7, proof2, sig1, grpkey);
  printf("claim verify rc: %d\n", rc);
  printf("claim verify return (1): %d\n", ret7);
  printf("claim_verify expected?: %d\n", ret7==1);

  printf("\n***** Testing claim_verify - incorrect signature *****\n");
  uint8_t ret8 = 255;
  rc = groupsig_claim_verify(&ret8, proof2, sig2, grpkey);
  printf("claim_verify rc: %d\n", rc);
  printf("claim_verify return (0): %d\n", ret8);
  printf("claim_verify expected?: %d\n", ret8==0);

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
