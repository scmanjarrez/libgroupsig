#include <openssl/bn.h>
#include <openssl/rand.h>
#include <time.h>
#include <stdbool.h>

#include "groupsig.h"
#include "kty04.h"
#include "utils.h"

void kty04_test() {
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
  }

  clock_t start, end;
  int rc = 255;
  uint8_t code = GROUPSIG_KTY04_CODE;

  printf("\n##### Testing mgr_key_init\n");
  groupsig_key_t *mgrkey;
  start = clock();
  mgrkey = groupsig_mgr_key_init(code);
  end = clock();
  print_exp_ptr("mgrkey", mgrkey);
  print_to_str("mgrkey", groupsig_mgr_key_to_string(mgrkey));
  print_time("", start, end);

  printf("\n##### Testing grp_key_init\n");
  groupsig_key_t *grpkey;
  start = clock();
  grpkey = groupsig_grp_key_init(code);
  end = clock();
  print_exp_ptr("grpkey", grpkey);
  print_to_str("grpkey", groupsig_grp_key_to_string(grpkey));
  print_time("", start, end);

  printf("\n##### Testing gml_init\n");
  gml_t *gml;
  start = clock();
  gml = gml_init(code);
  end = clock();
  print_exp_ptr("gml", gml);
  print_time("", start, end);

  printf("\n##### Testing crl_init\n");
  crl_t *crl;
  start = clock();
  crl = crl_init(code);
  end = clock();
  print_exp_ptr("crl", crl);
  print_time("", start, end);

  printf("\n##### Testing groupsig_setup\n");
  start = clock();
  rc = groupsig_setup(code, grpkey, mgrkey, gml);
  end = clock();
  print_exp_rc("", rc);
  print_time("", start, end);

  printf("\n##### Testing mem_key_init\n");
  groupsig_key_t *memkey;
  start = clock();
  memkey = groupsig_mem_key_init(grpkey->scheme);
  end = clock();
  print_exp_ptr("memkey", memkey);
  print_to_str("memkey", groupsig_mem_key_to_string(memkey));
  print_time("", start, end);

  printf("\n##### Testing msg_init\n");
  message_t *msg0, *msg1;
  start = clock();
  msg0 = message_init();
  end = clock();
  print_exp_ptr("msg0", msg0);
  print_time("", start, end);

  start = clock();
  msg1 = message_init();
  end = clock();
  print_exp_ptr("msg1", msg1);
  print_time("", start, end);

  printf("\n##### Testing join_mem (0)\n");
  start = clock();
  rc = groupsig_join_mem(&msg0, memkey, 0, NULL, grpkey);
  end = clock();
  print_exp_rc("", rc);
  print_time("", start, end);

  printf("\n##### Testing join_mgr (1)\n");
  start = clock();
  rc = groupsig_join_mgr(&msg1, gml, mgrkey, 1, msg0, grpkey);
  end = clock();
  print_exp_rc("", rc);
  print_time("", start, end);

  printf("\n##### Testing grp_key_export & grp_key_import\n");
  byte_t *bytes_grpkey = NULL;
  uint32_t size_grpkey;
  int len0;
  len0 = groupsig_grp_key_get_size(grpkey);
  start = clock();
  rc = groupsig_grp_key_export(&bytes_grpkey, &size_grpkey, grpkey);
  end = clock();
  print_exp_rc("export ", rc);
  print_exp_ret("export ", size_grpkey, len0);
  print_time("export ", start, end);

  groupsig_key_t *grpkey_imp;
  start = clock();
  grpkey_imp = groupsig_grp_key_import(code, bytes_grpkey, size_grpkey);
  end = clock();
  print_exp_ptr("grpkey_imp", grpkey_imp);
  print_to_str("grpkey", groupsig_grp_key_to_string(grpkey));
  print_to_str("grpkey_imp", groupsig_grp_key_to_string(grpkey_imp));
  print_time("", start, end);

  printf("\n##### Testing mgr_key_export & mgr_key_import\n");
  byte_t *bytes_mgrkey = NULL;
  uint32_t size_mgrkey;
  int len1;
  len1 = groupsig_mgr_key_get_size(mgrkey);
  start = clock();
  rc = groupsig_mgr_key_export(&bytes_mgrkey, &size_mgrkey, mgrkey);
  end = clock();
  print_exp_rc("export ", rc);
  print_exp_ret("export ", size_mgrkey, len1);
  print_time("export ", start, end);

  groupsig_key_t *mgrkey_imp;
  start = clock();
  mgrkey_imp = groupsig_mgr_key_import(code, bytes_mgrkey, size_mgrkey);
  end = clock();
  print_exp_ptr("mgrkey_imp", mgrkey_imp);
  print_to_str("mgrkey", groupsig_mgr_key_to_string(mgrkey));
  print_to_str("mgrkey_imp", groupsig_mgr_key_to_string(mgrkey_imp));
  print_time("", start, end);

  printf("\n##### Testing mem_key_export & mem_key_import\n");
  // Msg1 is the memkey...
  memkey = groupsig_mem_key_import(code, msg1->bytes, msg1->length);

  byte_t *bytes_memkey = NULL;
  uint32_t size_memkey;
  int len2;
  len2 = groupsig_mem_key_get_size(memkey);
  start = clock();
  rc = groupsig_mem_key_export(&bytes_memkey, &size_memkey, memkey);
  end = clock();
  print_exp_rc("export ", rc);
  print_exp_ret("export ", size_memkey, len2);
  print_time("export ", start, end);

  groupsig_key_t *memkey_imp;
  start = clock();
  memkey_imp = groupsig_mem_key_import(code, bytes_memkey, size_memkey);
  end = clock();
  print_exp_ptr("memkey_imp", memkey_imp);
  print_to_str("memkey", groupsig_mem_key_to_string(memkey));
  print_to_str("memkey_imp", groupsig_mem_key_to_string(memkey_imp));
  print_time("", start, end);

  printf("\n##### Testing gml_export & gml_import\n");
  byte_t *bytes_gml = NULL;
  uint32_t size_gml;
  start = clock();
  rc = gml_export(&bytes_gml, &size_gml, gml);
  end = clock();
  print_exp_rc("export ", rc);
  print_time("export ", start, end);

  gml_t *gml_imp;
  start = clock();
  gml_imp = gml_import(code, bytes_gml, size_gml);
  end = clock();
  print_exp_ptr("gml_imp", gml_imp);
  print_time("import ", start, end);

  printf("\n##### Testing sign & verify - correct message\n");
  message_t *msg2;
  groupsig_signature_t *sig0;
  msg2 = message_from_string((char *) "Hello, World!");
  start = clock();
  sig0 = groupsig_signature_init(grpkey_imp->scheme);
  end = clock();
  print_exp_ptr("sig0", sig0);
  print_time("init ", start, end);

  start = clock();
  rc = groupsig_sign(sig0, msg2, memkey_imp, grpkey_imp, UINT_MAX);
  end = clock();
  print_exp_rc("sign ", rc);
  print_time("sign ", start, end);

  uint8_t ret0 = 255;
  start = clock();
  rc = groupsig_verify(&ret0, sig0, msg2, grpkey_imp);
  end = clock();
  print_exp_rc("verify ", rc);
  print_exp_ret("verify ", ret0, 1);
  print_time("verify ", start, end);

  printf("\n##### Testing sign & verify - incorrect message\n");
  message_t *msg3;
  groupsig_signature_t *sig1;
  msg3 = message_from_string((char *) "Hello, Worlds!");
  start = clock();
  sig1 = groupsig_signature_init(grpkey_imp->scheme);
  end = clock();
  print_exp_ptr("sig1", sig1);
  print_time("init ", start, end);

  start = clock();
  rc = groupsig_sign(sig1, msg3, memkey_imp, grpkey_imp, UINT_MAX);
  end = clock();
  print_exp_rc("sign ", rc);
  print_time("sign ", start, end);

  // verify using incorrect signature (sig0)
  uint8_t ret1 = 255;
  start = clock();
  rc = groupsig_verify(&ret1, sig0, msg3, grpkey_imp);
  end = clock();
  print_exp_rc("verify ", rc);
  print_exp_ret("verify ", ret1, 0);
  print_time("verify ", start, end);

  printf("\n##### Testing proof_init\n");
  groupsig_signature_t *sigs[1];
  groupsig_proof_t *proof0;
  start = clock();
  proof0 = groupsig_proof_init(grpkey_imp->scheme);
  end = clock();
  print_exp_ptr("proof0", proof0);
  print_time("", start, end);

  printf("\n##### Testing prove_equality\n");
  sigs[0] = sig0;
  start = clock();
  rc = groupsig_prove_equality(proof0, memkey_imp, grpkey_imp, sigs, 1);
  end = clock();
  print_exp_rc("", rc);
  print_time("", start, end);

  printf("\n##### Testing prove_equality_verify - correct signature\n");
  uint8_t ret2 = 255;
  start = clock();
  rc = groupsig_prove_equality_verify(&ret2, proof0, grpkey_imp, sigs, 1);
  end = clock();
  print_exp_rc("", rc);
  print_exp_ret("", ret2, 1);
  print_time("", start, end);

  printf("\n##### Testing prove_equality_verify - incorrect signature\n");
  sigs[0] = sig1;
  uint8_t ret3 = 255;
  start = clock();
  rc = groupsig_prove_equality_verify(&ret3, proof0, grpkey_imp, sigs, 1);
  end = clock();
  print_exp_rc("", rc);
  print_exp_ret("", ret3, 0);
  print_time("", start, end);

  printf("\n##### Testing trace - not revealed user\n");
  sigs[0] = sig0;
  uint8_t ret4 = 255;
  start = clock();
  rc = groupsig_trace(&ret4, sig0, grpkey_imp, crl, mgrkey_imp, gml_imp);
  end = clock();
  print_exp_rc("", rc);
  print_exp_ret("", ret4, 0);
  print_time("", start, end);

  printf("\n##### Testing open\n");
  uint64_t idx = 255;
  start = clock();
  rc = groupsig_open(&idx, proof0, crl, sig0, grpkey_imp, mgrkey_imp, gml_imp);
  end = clock();
  print_exp_rc("", rc);
  printf("index: %lu\n", idx);
  print_time("", start, end);

  printf("\n##### Testing trapdoor_init\n");
  trapdoor_t *trapdoor = NULL;
  start = clock();
  trapdoor = trapdoor_init(memkey_imp->scheme);
  end = clock();
  print_exp_ptr("trapdoor", trapdoor);
  print_time("", start, end);

  printf("\n##### Testing reveal\n");
  start = clock();
  rc = groupsig_reveal(trapdoor, crl, gml_imp, 0);
  end = clock();
  print_exp_rc("", rc);
  char *str_aux;
  str_aux = bigz_get_str16(*(bigz_t *)trapdoor->trap);
  printf("trapdoor->trap: %s\n", str_aux);
  print_time("", start, end);

  printf("\n##### Testing trace - revealed user\n");
  uint8_t ret5 = 255;
  start = clock();
  rc = groupsig_trace(&ret5, sig0, grpkey_imp, crl, mgrkey_imp, gml_imp);
  end = clock();
  print_exp_rc("", rc);
  print_exp_ret("", ret5, 1);
  print_time("", start, end);

  printf("\n##### Testing claim\n");
  groupsig_proof_t *proof1;
  proof1 = groupsig_proof_init(grpkey_imp->scheme);

  start = clock();
  rc = groupsig_claim(proof1, memkey_imp, grpkey_imp, sig0);
  end = clock();
  print_exp_rc("", rc);
  print_time("", start, end);

  printf("\n##### Testing claim_verify - correct signature\n");
  uint8_t ret6 = 255;
  start = clock();
  rc = groupsig_claim_verify(&ret6, proof1, sig0, grpkey_imp);
  end = clock();
  print_exp_rc("", rc);
  print_exp_ret("", ret6, 1);
  print_time("", start, end);

  printf("\n##### Testing claim_verify - incorrect signature\n");
  uint8_t ret7 = 255;
  start = clock();
  rc = groupsig_claim_verify(&ret7, proof1, sig1, grpkey_imp);
  end = clock();
  print_exp_rc("", rc);
  print_exp_ret("", ret7, 0);
  print_time("", start, end);

  groupsig_mgr_key_free(mgrkey_imp); mgrkey_imp = NULL;
  groupsig_mgr_key_free(mgrkey); mgrkey = NULL;
  groupsig_grp_key_free(grpkey_imp); grpkey_imp = NULL;
  groupsig_grp_key_free(grpkey); grpkey = NULL;
  groupsig_mem_key_free(memkey_imp); memkey_imp = NULL;
  groupsig_mem_key_free(memkey); memkey = NULL;
  gml_free(gml_imp); gml_imp = NULL;
  gml_free(gml); gml = NULL;
  crl_free(crl); crl = NULL;
  message_free(msg3); msg3 = NULL;
  message_free(msg2); msg2 = NULL;
  message_free(msg1); msg1 = NULL;
  message_free(msg0); msg0 = NULL;
  trapdoor_free(trapdoor);
  groupsig_proof_free(proof1);
  groupsig_proof_free(proof0);
  groupsig_signature_free(sig1); sig1 = NULL;
  groupsig_signature_free(sig0); sig0 = NULL;
}
