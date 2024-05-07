#include <time.h>
#include "groupsig.h"
#include "kty04.h"
#include "utils.h"


void kty04_test() {
  check_randomness();
  clock_t start, end;
  int rc = 255;
  uint8_t code = GROUPSIG_KTY04_CODE;

  printf("##### Testing groupsig_init\n");
  start = clock();
  rc = groupsig_init(code, time(NULL));
  end = clock();
  print_exp_rc("", rc);
  print_time("", start, end);

  printf("##### Testing grp_key_init\n");
  groupsig_key_t *grpkey;
  start = clock();
  grpkey = groupsig_grp_key_init(code);
  end = clock();
  print_exp_ptr("grpkey", grpkey);
  print_to_str("grpkey", groupsig_grp_key_to_string(grpkey));
  print_time("", start, end);

  printf("\n##### Testing mgr_key_init\n");
  groupsig_key_t *mgrkey;
  start = clock();
  mgrkey = groupsig_mgr_key_init(code);
  end = clock();
  print_exp_ptr("mgrkey", mgrkey);
  print_to_str("mgrkey", groupsig_mgr_key_to_string(mgrkey));
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

  printf("\n##### Testing msg_init\n");
  message_t *msg0_mem0, *msg1_mem0;
  start = clock();
  msg0_mem0 = message_init();
  end = clock();
  //print_exp_ptr("msg0_mem0", msg0_mem0);
  print_time("", start, end);
  msg1_mem0 = message_init();

  printf("\n##### Testing mem_key_init\n");
  groupsig_key_t *memkey0;
  start = clock();
  memkey0 = groupsig_mem_key_init(grpkey->scheme);
  end = clock();
  print_exp_ptr("memkey0", memkey0);
  print_to_str("memkey0", groupsig_mem_key_to_string(memkey0));
  print_time("", start, end);

  printf("\n##### Testing join_mem (0)\n");
  start = clock();
  rc = groupsig_join_mem(&msg0_mem0, memkey0, 0, NULL, grpkey);
  end = clock();
  print_exp_rc("", rc);
  print_time("", start, end);

  printf("\n##### Testing join_mgr (1)\n");
  start = clock();
  rc = groupsig_join_mgr(&msg1_mem0, gml, mgrkey, 1, msg0_mem0, grpkey);
  end = clock();
  print_exp_rc("", rc);
  print_time("", start, end);

  message_t *msg0_mem1, *msg1_mem1;
  msg0_mem1 = message_init();
  msg1_mem1 = message_init();
  groupsig_key_t *memkey1;
  memkey1 = groupsig_mem_key_init(grpkey->scheme);
  groupsig_join_mem(&msg0_mem1, memkey1, 0, NULL, grpkey);
  groupsig_join_mgr(&msg1_mem1, gml, mgrkey, 1, msg0_mem1, grpkey);

  printf("\n##### Testing grp_key_export & grp_key_import\n");
  byte_t *bytes_grpkey = NULL;
  uint32_t size_grpkey;
  int len_grpkey;
  len_grpkey = groupsig_grp_key_get_size(grpkey);
  start = clock();
  rc = groupsig_grp_key_export(&bytes_grpkey, &size_grpkey, grpkey);
  end = clock();
  print_exp_rc("export ", rc);
  print_exp_ret("export ", size_grpkey, len_grpkey);
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
  int len_mgrkey;
  len_mgrkey = groupsig_mgr_key_get_size(mgrkey);
  start = clock();
  rc = groupsig_mgr_key_export(&bytes_mgrkey, &size_mgrkey, mgrkey);
  end = clock();
  print_exp_rc("export ", rc);
  print_exp_ret("export ", size_mgrkey, len_mgrkey);
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
  // Msg1 is the memkey0...
  memkey0 = groupsig_mem_key_import(code, msg1_mem0->bytes, msg1_mem0->length);
  memkey1 = groupsig_mem_key_import(code, msg1_mem1->bytes, msg1_mem1->length);

  byte_t *bytes_memkey = NULL;
  uint32_t size_memkey;
  int len_memkey;
  len_memkey = groupsig_mem_key_get_size(memkey0);
  start = clock();
  rc = groupsig_mem_key_export(&bytes_memkey, &size_memkey, memkey0);
  end = clock();
  print_exp_rc("export ", rc);
  print_exp_ret("export ", size_memkey, len_memkey);
  print_time("export ", start, end);

  groupsig_key_t *memkey0_imp;
  start = clock();
  memkey0_imp = groupsig_mem_key_import(code, bytes_memkey, size_memkey);
  end = clock();
  print_exp_ptr("memkey0_imp", memkey0_imp);
  print_to_str("memkey0", groupsig_mem_key_to_string(memkey0));
  print_to_str("memkey0_imp", groupsig_mem_key_to_string(memkey0_imp));
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

  printf("\n##### Testing sign & verify (u0) - correct message\n");
  message_t *text0;
  groupsig_signature_t *sig0;
  text0 = message_from_string((char *) "Hello, World!");
  start = clock();
  sig0 = groupsig_signature_init(grpkey_imp->scheme);
  end = clock();
  print_exp_ptr("sig0", sig0);
  print_time("init ", start, end);

  start = clock();
  rc = groupsig_sign(sig0, text0, memkey0_imp, grpkey_imp, UINT_MAX);
  end = clock();
  print_exp_rc("sign ", rc);
  print_to_str("sig0", groupsig_signature_to_string(sig0));
  print_time("sign ", start, end);

  uint8_t ret0 = 255;
  start = clock();
  rc = groupsig_verify(&ret0, sig0, text0, grpkey_imp);
  end = clock();
  print_exp_rc("verify ", rc);
  print_exp_ret("verify ", (uint32_t) ret0, 1);
  print_time("verify ", start, end);

  printf("\n##### Testing sign & verify (u0) - incorrect message\n");
  message_t *text1;
  groupsig_signature_t *sig1;
  text1 = message_from_string((char *) "Hello, Worlds!");
  start = clock();
  sig1 = groupsig_signature_init(grpkey_imp->scheme);
  end = clock();
  print_exp_ptr("sig1", sig1);
  print_time("init ", start, end);

  start = clock();
  rc = groupsig_sign(sig1, text1, memkey0_imp, grpkey_imp, UINT_MAX);
  end = clock();
  print_exp_rc("sign ", rc);
  print_time("sign ", start, end);

  // verify using incorrect signature (sig0)
  uint8_t ret1 = 255;
  start = clock();
  rc = groupsig_verify(&ret1, sig0, text1, grpkey_imp);
  end = clock();
  print_exp_rc("verify ", rc);
  print_exp_ret("verify ", (uint32_t) ret1, 0);
  print_time("verify ", start, end);

  printf("\n##### Testing sign & verify (u1) - correct message\n");
  groupsig_signature_t *sig2;
  sig2 = groupsig_signature_init(grpkey_imp->scheme);
  end = clock();
  print_exp_ptr("sig2", sig2);
  print_time("init ", start, end);

  start = clock();
  rc = groupsig_sign(sig2, text0, memkey1, grpkey_imp, UINT_MAX);
  end = clock();
  print_exp_rc("sign ", rc);
  print_time("sign ", start, end);

  uint8_t ret2 = 255;
  start = clock();
  rc = groupsig_verify(&ret2, sig2, text0, grpkey_imp);
  end = clock();
  print_exp_rc("verify ", rc);
  print_exp_ret("verify ", (uint32_t) ret2, 1);
  print_time("verify ", start, end);

  printf("\n##### Testing sign & verify (u1) - incorrect message\n");
  groupsig_signature_t *sig3;
  sig3 = groupsig_signature_init(grpkey_imp->scheme);
  end = clock();
  print_exp_ptr("sig3", sig3);
  print_time("init ", start, end);

  start = clock();
  rc = groupsig_sign(sig3, text1, memkey1, grpkey_imp, UINT_MAX);
  end = clock();
  print_exp_rc("sign ", rc);
  print_time("sign ", start, end);

  // verify using incorrect signature (sig0)
  uint8_t ret3 = 255;
  start = clock();
  rc = groupsig_verify(&ret3, sig0, text1, grpkey_imp);
  end = clock();
  print_exp_rc("verify ", rc);
  print_exp_ret("verify ", (uint32_t) ret3, 0);
  print_time("verify ", start, end);

  printf("\n##### Testing proof_init\n");
  groupsig_proof_t *proof_cl;
  start = clock();
  proof_cl = groupsig_proof_init(grpkey_imp->scheme);
  end = clock();
  print_exp_ptr("proof_cl", proof_cl);
  print_time("", start, end);

  printf("\n##### Testing claim\n");
  start = clock();
  rc = groupsig_claim(proof_cl, memkey0_imp, grpkey_imp, sig0);
  end = clock();
  print_exp_rc("", rc);
  print_time("", start, end);

  printf("\n##### Testing claim_verify - proof of claimed signature\n");
  uint8_t ret4 = 255;
  start = clock();
  rc = groupsig_claim_verify(&ret4, proof_cl, sig0, grpkey_imp);
  end = clock();
  print_exp_rc("", rc);
  print_exp_ret("", (uint32_t) ret4, 1);
  print_time("", start, end);

  printf("\n##### Testing claim_verify - proof of unclaimed signature\n");
  uint8_t ret5 = 255;
  start = clock();
  rc = groupsig_claim_verify(&ret5, proof_cl, sig1, grpkey_imp);
  end = clock();
  print_exp_rc("", rc);
  print_exp_ret("", (uint32_t) ret5, 0);
  print_time("", start, end);

  printf("\n##### Testing prove_equality\n");
  groupsig_proof_t *proof_peq;
  proof_peq = groupsig_proof_init(grpkey_imp->scheme);
  groupsig_signature_t *sigs[2];
  sigs[0] = sig0;
  sigs[1] = sig1;
  start = clock();
  rc = groupsig_prove_equality(proof_peq, memkey0_imp, grpkey_imp, sigs, 2);
  end = clock();
  print_exp_rc("", rc);
  print_time("", start, end);

  printf("\n##### Testing prove_equality_verify - correct signatures\n");
  uint8_t ret6 = 255;
  start = clock();
  rc = groupsig_prove_equality_verify(&ret6, proof_peq, grpkey_imp, sigs, 2);
  end = clock();
  print_exp_rc("", rc);
  print_exp_ret("", (uint32_t) ret6, 1);
  print_time("", start, end);

  printf("\n##### Testing prove_equality_verify - incorrect signatures\n");
  sigs[0] = sig1;
  uint8_t ret7 = 255;
  start = clock();
  rc = groupsig_prove_equality_verify(&ret7, proof_peq, grpkey_imp, sigs, 2);
  end = clock();
  print_exp_rc("", rc);
  print_exp_ret("", (uint32_t) ret7, 0);
  print_time("", start, end);

  printf("\n##### Testing open (u1)\n");
  uint64_t mem1_idx = 255;
  groupsig_proof_t *proof_op;
  proof_op = groupsig_proof_init(grpkey_imp->scheme);
  start = clock();
  rc = groupsig_open(&mem1_idx, proof_op, crl, sig2, grpkey_imp, mgrkey_imp, gml_imp);
  end = clock();
  print_exp_rc("", rc);
  printf("index: %lu\n", mem1_idx);
  print_exp_ret("index ", mem1_idx, 1);
  print_time("", start, end);

  printf("\n##### Testing trapdoor_init\n");
  trapdoor_t *trapdoor_mem1 = NULL;
  start = clock();
  trapdoor_mem1 = trapdoor_init(memkey1->scheme);
  end = clock();
  print_exp_ptr("trapdoor_mem1", trapdoor_mem1);
  print_time("", start, end);

  printf("\n##### Testing reveal\n");
  start = clock();
  rc = groupsig_reveal(trapdoor_mem1, crl, gml_imp, mem1_idx);
  end = clock();
  print_exp_rc("", rc);
  char *str_aux;
  str_aux = bigz_get_str16(*(bigz_t *)trapdoor_mem1->trap);
  printf("trapdoor_mem1->trap: %s\n", str_aux);
  print_time("", start, end);

  printf("\n##### Testing trace - revealed user\n");
  uint8_t ret8 = 255;
  start = clock();
  rc = groupsig_trace(&ret8, sig2, grpkey_imp, crl, mgrkey_imp, gml_imp);
  end = clock();
  print_exp_rc("", rc);
  print_exp_ret("", (uint32_t) ret8, 1);
  print_time("", start, end);

  printf("\n##### Testing trace - not revealed user\n");
  uint8_t ret9 = 255;
  start = clock();
  rc = groupsig_trace(&ret9, sig0, grpkey_imp, crl, mgrkey_imp, gml_imp);
  end = clock();
  print_exp_rc("", rc);
  print_exp_ret("", (uint32_t) ret9, 0);
  print_time("", start, end);

  groupsig_mgr_key_free(mgrkey_imp); mgrkey_imp = NULL;
  groupsig_mgr_key_free(mgrkey); mgrkey = NULL;
  groupsig_grp_key_free(grpkey_imp); grpkey_imp = NULL;
  groupsig_grp_key_free(grpkey); grpkey = NULL;
  groupsig_mem_key_free(memkey1); memkey1 = NULL;
  groupsig_mem_key_free(memkey0_imp); memkey0_imp = NULL;
  groupsig_mem_key_free(memkey0); memkey0 = NULL;
  gml_free(gml_imp); gml_imp = NULL;
  gml_free(gml); gml = NULL;
  crl_free(crl); crl = NULL;
  message_free(text1); text1 = NULL;
  message_free(text0); text0 = NULL;
  message_free(msg1_mem1); msg1_mem1 = NULL;
  message_free(msg1_mem0); msg1_mem0 = NULL;
  message_free(msg0_mem1); msg0_mem1 = NULL;
  message_free(msg0_mem0); msg0_mem0 = NULL;
  trapdoor_free(trapdoor_mem1); trapdoor_mem1 = NULL;
  groupsig_proof_free(proof_cl); proof_cl = NULL;
  groupsig_proof_free(proof_peq); proof_peq = NULL;
  groupsig_proof_free(proof_op); proof_op = NULL;
  groupsig_signature_free(sig3); sig3 = NULL;
  groupsig_signature_free(sig2); sig2 = NULL;
  groupsig_signature_free(sig1); sig1 = NULL;
  groupsig_signature_free(sig0); sig0 = NULL;
}

void kty04_benchmark_members(int num_members){
  check_randomness();

  clock_t start, end;
  clock_t times[B_NUM];
  memset(times, 0, B_NUM * sizeof(clock_t));
  int rc = 255;
  uint8_t code = GROUPSIG_KTY04_CODE;

  printf("\n##### Testing mgr_key_init\n");
  groupsig_key_t *mgrkey;
  start = clock();
  mgrkey = groupsig_mgr_key_init(code);
  end = clock();
  print_time("", start, end);
  times[B_NEW_MGRKEY] = end - start;

  printf("\n##### Testing grp_key_init\n");
  groupsig_key_t *grpkey;
  start = clock();
  grpkey = groupsig_grp_key_init(code);
  end = clock();
  print_time("", start, end);
  times[B_NEW_GRPKEY] = end - start;

  printf("\n##### Testing gml_init\n");
  gml_t *gml;
  start = clock();
  gml = gml_init(code);
  end = clock();
  print_time("", start, end);
  times[B_NEW_GML] = end - start;

  printf("\n##### Testing crl_init\n");
  crl_t *crl;
  start = clock();
  crl = crl_init(code);
  end = clock();
  print_exp_ptr("crl", crl);
  print_time("", start, end);
  times[B_NEW_CRL] = end - start;

  printf("\n##### Testing groupsig_setup\n");
  start = clock();
  rc = groupsig_setup(code, grpkey, mgrkey, gml);

  end = clock();
  print_exp_rc("", rc);
  print_time("", start, end);
  times[B_GRP_SETUP] = end - start;

  start = clock();
  groupsig_key_t **member_keys = (groupsig_key_t**) calloc(num_members, sizeof(groupsig_key_t*));

  for(int i = 0; i < num_members; i++){
    member_keys[i] = new_member_key(grpkey, mgrkey, gml, crl);
  }

  end = clock();
  times[B_NEW_MEMKEY] = end - start;

  char *test_message = "Message to Sign";

  printf("\n##### Testing sign & verify - correct message\n");
  start = clock();
  groupsig_signature_t **signatures = (groupsig_signature_t**) calloc(num_members, sizeof(groupsig_signature_t*));
  for(int i = 0; i < num_members; i++){
    signatures[i] = new_member_signature(test_message, member_keys[i], grpkey);
  }
  end = clock();
  print_time("sign ", start, end);
  times[B_NEW_SIGN] = end - start;

  uint8_t ret0 = 255;
  start = clock();

  for(int i = 0; i < num_members; i++){
    if (verify_member_signature(signatures[i], test_message, grpkey) != 1){ // 1 Signature Correct 0 otherwise
      printf("verify wrong: %d\n", i);
    }
  }
  end = clock();
  print_time("verify ", start, end);
  times[B_NEW_SIGN_VERIFY] = end - start;

  groupsig_signature_t **signatures2 = (groupsig_signature_t**) calloc(num_members, sizeof(groupsig_signature_t*));
  for(int i = 0; i < num_members; i++){
    signatures2[i] = new_member_signature(test_message, member_keys[i], grpkey);
  }

  printf("\n##### Testing prove_equality\n");
  start = clock();
  groupsig_proof_t **proofs_equality = (groupsig_proof_t**) calloc(num_members, sizeof(groupsig_proof_t*));
  for(int i = 0; i < num_members; i++){
    proofs_equality[i] = prove_equality(signatures[i], signatures2[i], member_keys[i], grpkey);
  }
  end = clock();
  print_time("", start, end);
  times[B_PROVE_EQ] = end - start;

  printf("\n##### Testing prove_equality_verify\n");
  start = clock();
  for(int i = 0; i < num_members; i++){
    if (verify_proof_equality(proofs_equality[i], signatures[i], signatures2[i], grpkey) != 1){
      printf("verify equality wrong: %d\n", i);
    }
    //groupsig_proof_free(proofs[i]);
  }
  end = clock();
  print_time("", start, end);
  times[B_PROVE_EQ_VERIFY] = end - start;

  printf("\n##### Testing trace - not revealed user\n");
  start = clock();
  for(int i = 0; i < num_members; i++){
    if (trace_signature(signatures[i], grpkey, mgrkey, gml, crl) != 0){
      printf("trace_signature is revealed: %d\n", i);
    }
  }
  end = clock();
  print_time("", start, end);
  times[B_TRACE] = end - start;

  printf("\n##### Testing open\n");
  uint64_t idx = 255;
  start = clock();
  groupsig_proof_t **proofs_open = (groupsig_proof_t**) calloc(num_members, sizeof(groupsig_proof_t*));
  for(int i = 0; i < num_members; i++){
    idx = open_signature(&proofs_open[i], signatures[i], grpkey, mgrkey, gml, crl);
    if (idx != i){
      printf("ERROR open signature");
    }
  }
  end = clock();
  print_time("", start, end);
  times[B_OPEN] = end - start;

  printf("\n##### Testing reveal\n");
  start = clock();
  for(int i = 0; i < num_members; i++){
    free(reveal_signature(member_keys[i], gml, crl, i));
  }
  end = clock();
  print_time("", start, end);
  times[B_REVEAL] = end - start;

  printf("\n##### Testing trace - revealed user\n");
  start = clock();
  for(int i = 0; i < num_members; i++){
    if (trace_signature(signatures[i], grpkey, mgrkey, gml, crl) == 0){
      printf("trace_signature is revealed: %d\n", i);
    }
  }
  end = clock();
  print_time("", start, end);
  times[B_TRACE] = end - start;

  printf("\n##### Testing claim\n");
  start = clock();
  groupsig_proof_t **proofs_claim = (groupsig_proof_t**) calloc(num_members, sizeof(groupsig_proof_t*));
  for(int i = 0; i < num_members; i++){
    proofs_claim[i] = claim_signatures(signatures[i], member_keys[i], grpkey);
  }

  end = clock();

  print_time("", start, end);
  times[B_CLAIM] = end - start;

  printf("\n##### Testing claim_verify - correct signature\n");
  start = clock();
  for(int i = 0; i < num_members; i++){
    claim_verify_signatures(proofs_claim[i], signatures[i], grpkey);
  }
  end = clock();

  print_time("", start, end);
  times[B_CLAIM_VERIFY] = end - start;

  printf("FREE MEMORY\n");

  groupsig_mgr_key_free(mgrkey); mgrkey = NULL;
  groupsig_grp_key_free(grpkey); grpkey = NULL;
  gml_free(gml); gml = NULL;
  crl_free(crl); crl = NULL;

  for(int i = 0; i < num_members; i++){
    groupsig_mem_key_free(member_keys[i]); member_keys[i] = NULL;
    groupsig_proof_free(proofs_equality[i]); proofs_equality[i] = NULL;
    groupsig_proof_free(proofs_open[i]); proofs_open[i] = NULL;
    groupsig_proof_free(proofs_claim[i]); proofs_claim[i] = NULL;
    groupsig_signature_free(signatures[i]); signatures[i] = NULL;
    groupsig_signature_free(signatures2[i]); signatures2[i] = NULL;
  }

  free(proofs_equality);
  free(proofs_open);
  free(proofs_claim);
  free(member_keys);
  free(signatures);
  free(signatures2);

  b_write_csv(num_members, times, GROUPSIG_KTY04_CODE);
}

void kty04_benchmark_members_sigverif(int num_members){
  check_randomness();

  clock_t start, end;
  clock_t times[B_NUM];
  memset(times, 0, B_NUM * sizeof(clock_t));
  int rc = 255;
  uint8_t code = GROUPSIG_KTY04_CODE;

  printf("\n##### Testing mgr_key_init\n");
  groupsig_key_t *mgrkey;
  start = clock();
  mgrkey = groupsig_mgr_key_init(code);
  end = clock();
  print_time("", start, end);
  times[B_NEW_MGRKEY] = end - start;

  printf("\n##### Testing grp_key_init\n");
  groupsig_key_t *grpkey;
  start = clock();
  grpkey = groupsig_grp_key_init(code);
  end = clock();
  print_time("", start, end);
  times[B_NEW_GRPKEY] = end - start;

  printf("\n##### Testing gml_init\n");
  gml_t *gml;
  start = clock();
  gml = gml_init(code);
  end = clock();
  print_time("", start, end);
  times[B_NEW_GML] = end - start;

  printf("\n##### Testing crl_init\n");
  crl_t *crl;
  start = clock();
  crl = crl_init(code);
  end = clock();
  print_exp_ptr("crl", crl);
  print_time("", start, end);
  times[B_NEW_CRL] = end - start;

  printf("\n##### Testing groupsig_setup\n");
  start = clock();
  rc = groupsig_setup(code, grpkey, mgrkey, gml);

  end = clock();
  print_exp_rc("", rc);
  print_time("", start, end);
  times[B_GRP_SETUP] = end - start;

  start = clock();
  groupsig_key_t **member_keys = (groupsig_key_t**) calloc(num_members, sizeof(groupsig_key_t*));

  for(int i = 0; i < num_members; i++){
    member_keys[i] = new_member_key(grpkey, mgrkey, gml, crl);
  }

  end = clock();
  times[B_NEW_MEMKEY] = end - start;

  char *test_message = "Message to Sign";

  printf("\n##### Testing sign & verify - correct message\n");
  start = clock();
  groupsig_signature_t **signatures = (groupsig_signature_t**) calloc(num_members, sizeof(groupsig_signature_t*));
  for(int i = 0; i < num_members; i++){
    signatures[i] = new_member_signature(test_message, member_keys[i], grpkey);
  }
  end = clock();
  print_time("sign ", start, end);
  times[B_NEW_SIGN] = end - start;

  uint8_t ret0 = 255;
  start = clock();

  for(int i = 0; i < num_members; i++){
    if (verify_member_signature(signatures[i], test_message, grpkey) != 1){ // 1 Signature Correct 0 otherwise
      printf("verify wrong: %d\n", i);
    }
  }
  end = clock();
  print_time("verify ", start, end);
  times[B_NEW_SIGN_VERIFY] = end - start;

  printf("FREE MEMORY\n");

  groupsig_mgr_key_free(mgrkey); mgrkey = NULL;
  groupsig_grp_key_free(grpkey); grpkey = NULL;
  gml_free(gml); gml = NULL;
  crl_free(crl); crl = NULL;

  for(int i = 0; i < num_members; i++){
    groupsig_mem_key_free(member_keys[i]); member_keys[i] = NULL;
    groupsig_signature_free(signatures[i]); signatures[i] = NULL;

  }

  free(member_keys);
  free(signatures);

  b_write_csv(num_members, times, GROUPSIG_KTY04_CODE);
}

void kty04_benchmark() {
  for (int i=1; i < 100; i ++){
    printf("Testing benchmark %d member\n", i );
    for (int j = 0; j < TEST_REPS; j ++){
      kty04_benchmark_members(i);
      kty04_benchmark_members_sigverif(i);
    }
  }
}
