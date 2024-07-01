#include "utils.h"


const char* status(int val) {
  if (!val)
    return "✔";
  return "✗";
}

void check_ptr(char *prefix, char *msg, void *ptr) {
  if (!ptr) {
    fprintf(stderr, "Test %s (%s - pointer): initialization => %s\n",
            prefix, msg, status(!ptr));
    exit(1);
  }
}

void check_size(char *prefix, char *msg, int ret, int exp) {
  if (ret != exp) {
    fprintf(stderr, "Test %s (%s - return size): expected:%d, value:%d => %s\n",
            prefix, msg, exp, ret, status(ret != exp));
    exit(1);
  }
}

void check_rc(char *prefix, char *msg, int rc) {
  if (rc != IOK) {
    fprintf(stderr, "Test %s (%s - return code): expected:%d, value:%d => %s\n",
            prefix, msg, IOK, rc, status(rc != IOK));
  }
}

void check_ret(char *prefix, char *msg, uint8_t ret, uint8_t exp) {
  printf("Test %s (%s - return value): expected:%d, value:%d => %s\n",
         prefix, msg, exp, ret, status(ret != exp));
}

void test_init(char *prefix, char *scheme, groupsig_t **gsig, groupsig_key_t **gkey,
               groupsig_key_t **mgkey1, groupsig_key_t **mgkey2, gml_t **gml, crl_t **crl) {
  *gsig = groupsig_get_groupsig_from_str(scheme);
  check_ptr(prefix, "get_groupsig_from_str", *gsig);
  int multi = multi_mgrkey(scheme);

  uint8_t code = (*gsig)->desc->code;
  int rc = groupsig_init(code, time(NULL));
  check_rc(prefix, "test_init", rc);

  groupsig_key_t *_gkey = groupsig_grp_key_init(code);
  check_ptr(prefix, "grp_key_init", _gkey);

  groupsig_key_t *_mgkey1 = groupsig_mgr_key_init(code);
  check_ptr(prefix, "mgr_key_init1", _mgkey1);

  groupsig_key_t *_mgkey2;
  if (multi) {
    _mgkey2 = groupsig_mgr_key_init(code);
    check_ptr(prefix, "mgr_key_init2", _mgkey2);
  }

  if ((*gsig)->desc->has_gml) {
    *gml = gml_init(code);
    check_ptr(prefix, "gml_init", *gml);
  }

  if ((*gsig)->desc->has_crl) {
    *crl = crl_init(code);
    check_ptr(prefix, "crl_init", *crl);
  }

  rc = groupsig_setup(code, _gkey, _mgkey1, *gml);
  check_rc(prefix, "setup1", rc);
  if (multi) {
    rc = groupsig_setup(code, _gkey, _mgkey2, *gml);
    check_rc(prefix, "setup2", rc);
  }

  byte_t *_gkey_b = NULL;
  uint32_t _gkey_sz;
  int _gkey_len = groupsig_grp_key_get_size(_gkey);
  rc = groupsig_grp_key_export(&_gkey_b, &_gkey_sz, _gkey);
  check_rc(prefix, "grp_key_export", rc);
  check_size(prefix, "grp_key_export", _gkey_sz, _gkey_len);
  *gkey = groupsig_grp_key_import(code, _gkey_b, _gkey_sz);
  check_ptr(prefix, "grp_key_import", *gkey);

  byte_t *_mgkey1_b = NULL;
  uint32_t _mgkey1_sz;
  int _mgkey1_len = groupsig_mgr_key_get_size(_mgkey1);
  rc = groupsig_mgr_key_export(&_mgkey1_b, &_mgkey1_sz, _mgkey1);
  check_rc(prefix, "mgr_key_export1", rc);
  check_size(prefix, "mgr_key_export1", _mgkey1_sz, _mgkey1_len);
  *mgkey1 = groupsig_mgr_key_import(code, _mgkey1_b, _mgkey1_sz);
  check_ptr(prefix, "mgr_key_import1", *mgkey1);

  if (multi) {
    byte_t *_mgkey2_b = NULL;
    uint32_t _mgkey2_sz;
    int _mgkey2_len = groupsig_mgr_key_get_size(_mgkey2);
    rc = groupsig_mgr_key_export(&_mgkey2_b, &_mgkey2_sz, _mgkey2);
    check_rc(prefix, "mgr_key_export2", rc);
    check_size(prefix, "mgr_key_export2", _mgkey2_sz, _mgkey2_len);
    *mgkey2 = groupsig_mgr_key_import(code, _mgkey2_b, _mgkey2_sz);
    check_ptr(prefix, "mgr_key_import2", *mgkey2);
  }

  groupsig_grp_key_free(_gkey);
  groupsig_mgr_key_free(_mgkey1);
  if (multi)
    groupsig_mgr_key_free(_mgkey2);
}

void test_registration(char *_prefix, int _prefix_idx, groupsig_t *gsig, groupsig_key_t *gkey,
                       groupsig_key_t *mgkey, gml_t *gml, groupsig_key_t **mkey) {
  uint8_t start, seq;
  uint8_t code = gsig->desc->code;
  char prefix[20];
  snprintf(prefix, 20, "%s%d", _prefix, _prefix_idx);

  groupsig_key_t *_mkey = groupsig_mem_key_init(code);
  int rc = gsig->get_joinstart(&start);
  check_rc(prefix, "joinstart", rc);
  rc = gsig->get_joinseq(&seq);
  check_rc(prefix, "joinseq", rc);

  message_t *msg1 = message_init();
  message_t *msg2 = message_init();
  int phase = 0;
  if (start == 1 && seq == 1) { // kty04
    rc = groupsig_join_mem(&msg2, _mkey, 0, msg1, gkey);
    check_rc(prefix, "join_mem", rc);

    rc = groupsig_join_mgr(&msg1, gml, mgkey, 1, msg2, gkey);
    check_rc(prefix, "join_mgr", rc);
    message_free(msg2); msg2 = message_init();

    _mkey = groupsig_mem_key_import(code, msg1->bytes, msg1->length);
  } else {
    if (start) {
      rc = groupsig_join_mem(&msg2, _mkey, phase, msg1, gkey);
      check_rc(prefix, "join_mem", rc);
      phase++;
    }
    while (phase < seq) {
      rc = groupsig_join_mgr(&msg1, gml, mgkey, phase, msg2, gkey);
      check_rc(prefix, "join_mgr", rc);
      if (msg2) {
        message_free(msg2); msg2 = message_init();
      }
      phase++;
      rc = groupsig_join_mem(&msg2, _mkey, phase, msg1, gkey);
      check_rc(prefix, "join_mem", rc);
      if (msg1) {
        message_free(msg1); msg1 = message_init();
      }
      phase++;
    }
  }

  byte_t *_mkey_b = NULL;
  uint32_t _mkey_sz;
  int _mkey_len = groupsig_mem_key_get_size(_mkey);
  rc = groupsig_mem_key_export(&_mkey_b, &_mkey_sz, _mkey);
  check_rc(prefix, "mem_key_export", rc);
  check_size(prefix, "mem_key_export", _mkey_sz, _mkey_len);
  *mkey = groupsig_mem_key_import(code, _mkey_b, _mkey_sz);
  check_ptr(prefix, "mem_key_import", *mkey);

  if (msg1)
    message_free(msg1);
  if (msg2)
    message_free(msg2);
  groupsig_mem_key_free(_mkey);
}

void test_gml(char *_prefix, int _prefix_idx, groupsig_key_t *gkey, gml_t **gml) {
  gml_t *_gml = *gml;
  byte_t *_gml_b = NULL;
  uint32_t _gml_sz;
  char prefix[20];
  snprintf(prefix, 20, "%s%d", _prefix, _prefix_idx);

  int rc = gml_export(&_gml_b, &_gml_sz, _gml);
  check_rc(prefix, "gml_export", rc);

  *gml = gml_import(gkey->scheme, _gml_b, _gml_sz);
  check_ptr(prefix, "gml_import", *gml);
  gml_free(_gml);
}


void test_signing(char *scheme, char *prefix, groupsig_key_t *gkey, groupsig_key_t *mkey) {
  message_t *msg1;
  message_t *msg2;
  if (!strcmp(scheme, "dl21") || !strcmp(scheme, "dl21seq")) {
    msg1 = message_from_string((char *) "{\"scope\": \"scp\", \"message\": \"Hello, World!\"}");
    msg2 = message_from_string((char *) "{\"scope\": \"scp\", \"message\": \"World, Hello!\"}");
  } else {
    msg1 = message_from_string((char *) "Hello, World!");
    msg2 = message_from_string((char *) "World, Hello!");
  }
  check_ptr(prefix, "message_from_string1", msg1);
  check_ptr(prefix, "message_from_string2", msg2);

  groupsig_signature_t *_sig1 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init1", _sig1);

  // Test1 (sign+verify): check signature after being exported/imported: ok
  int rc = groupsig_sign(_sig1, msg1, mkey, gkey, UINT_MAX);
  check_rc(prefix, "sign", rc);

  byte_t *_sig_b = NULL;
  uint32_t _sig_sz;
  int _sig_len = groupsig_signature_get_size(_sig1);
  rc = groupsig_signature_export(&_sig_b, &_sig_sz, _sig1);
  check_rc(prefix, "signature_export", rc);
  check_size(prefix, "signature_export", _sig_sz, _sig_len);
  groupsig_signature_t *sig1 = groupsig_signature_import(gkey->scheme, _sig_b, _sig_sz);
  check_ptr(prefix, "signature_import", sig1);

  uint8_t ret = 255;
  rc = groupsig_verify(&ret, sig1, msg1, gkey);
  check_rc(prefix, "verify1", rc);
  check_ret(prefix, "verify1", ret, 1);

  // Test2 (verify): incorrect argument (different message): error
  ret = 255;
  rc = groupsig_verify(&ret, sig1, msg2, gkey);
  check_rc(prefix, "verify2", rc);
  check_ret(prefix, "verify2", ret, 0);

  message_free(msg1);
  message_free(msg2);
  groupsig_signature_free(_sig1);
  groupsig_signature_free(sig1);
}

void test_group1(char *scheme, char *prefix, groupsig_key_t *gkey, groupsig_key_t *mgkey,
                 gml_t *gml, groupsig_key_t *mkey, int _index) {
  message_t *msg = message_from_string((char *) "Hello, World!");
  check_ptr(prefix, "message_from_string", msg);

  groupsig_signature_t *sig = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init", sig);

  int rc = groupsig_sign(sig, msg, mkey, gkey, UINT_MAX);
  check_rc(prefix, "sign", rc);

  uint64_t index;
  groupsig_proof_t *proof;
  if (strcmp(scheme, "bbs04")) {
    proof = groupsig_proof_init(gkey->scheme);
    check_ptr(prefix, "proof_init", proof);

    rc = groupsig_open(&index, proof, NULL, sig, gkey, mgkey, gml);
  } else
    rc = groupsig_open(&index, NULL, NULL, sig, gkey, mgkey, gml);
  check_rc(prefix, "open", rc);
  check_ret(prefix, "open", index, _index);

  message_free(msg);
  groupsig_signature_free(sig);
  if (strcmp(scheme, "bbs04"))
    groupsig_proof_free(proof);
}

void test_group2(char *prefix, groupsig_key_t *gkey, groupsig_key_t *mgkey,
                 gml_t *gml, groupsig_key_t *mkey, int _index) {
  message_t *msg = message_from_string((char *) "Hello, World!");
  check_ptr(prefix, "message_from_string", msg);

  groupsig_signature_t *sig = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init", sig);

  int rc = groupsig_sign(sig, msg, mkey, gkey, UINT_MAX);
  check_rc(prefix, "sign", rc);

  groupsig_proof_t *proof = groupsig_proof_init(gkey->scheme);
  check_ptr(prefix, "proof_init", proof);

  uint64_t index;
  rc = groupsig_open(&index, proof, NULL, sig, gkey, mgkey, gml);
  check_rc(prefix, "open", rc);
  check_ret(prefix, "open", index, _index);

  uint8_t ret = 255;
  rc = groupsig_open_verify(&ret, proof, sig, gkey);
  check_rc(prefix, "open_verify", rc);
  check_ret(prefix, "open_verify", ret, 1);

  message_free(msg);
  groupsig_signature_free(sig);
  groupsig_proof_free(proof);
}

void test_group3(char *prefix, groupsig_key_t *gkey, groupsig_key_t *mgkey,
                 gml_t *gml, crl_t *crl, groupsig_key_t *mkey1, groupsig_key_t *mkey2, int _index) {
  message_t *msg1 = message_from_string((char *) "Hello, World!");
  check_ptr(prefix, "message_from_string1", msg1);
  message_t *msg2 = message_from_string((char *) "World, Hello!");
  check_ptr(prefix, "message_from_string2", msg2);

  groupsig_signature_t *sig1 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init1", sig1);
  groupsig_signature_t *sig2 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init2", sig2);
  groupsig_signature_t *sig3 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init3", sig3);

  // sig1, user1 + msg1
  int rc = groupsig_sign(sig1, msg1, mkey1, gkey, UINT_MAX);
  check_rc(prefix, "sign1", rc);
  // sig2, user1 + msg2
  rc = groupsig_sign(sig2, msg2, mkey1, gkey, UINT_MAX);
  check_rc(prefix, "sign2", rc);
  // sig3, user2 + msg1
  rc = groupsig_sign(sig3, msg1, mkey2, gkey, UINT_MAX);
  check_rc(prefix, "sign3", rc);

  groupsig_proof_t *proof = groupsig_proof_init(gkey->scheme);
  check_ptr(prefix, "proof_init1", proof);

  uint64_t index;
  rc = groupsig_open(&index, proof, NULL, sig3, gkey, mgkey, gml);
  check_rc(prefix, "open", rc);
  check_ret(prefix, "open", index, _index);

  trapdoor_t *trap = trapdoor_init(gkey->scheme);
  rc = groupsig_reveal(trap, crl, gml, index);
  check_rc(prefix, "reveal", rc);
  check_ptr(prefix, "reveal", trap);

  // Test1 (trace): revealed user: ok
  uint8_t ret = 255;
  rc = groupsig_trace(&ret, sig3, gkey, crl, mgkey, gml);
  check_rc(prefix, "trace1", rc);
  check_ret(prefix, "trace1", ret, 1);

  // Test2 (trace): not revealed user: error
  ret = 255;
  rc = groupsig_trace(&ret, sig1, gkey, crl, mgkey, gml);
  check_rc(prefix, "trace2", rc);
  check_ret(prefix, "trace2", ret, 0);

  groupsig_proof_free(proof);
  proof = groupsig_proof_init(gkey->scheme);
  check_ptr(prefix, "proof_init2", proof);

  // Test1 (claim+claim_verify): claim+claim_verify signatures issued by same user: ok
  rc = groupsig_claim(proof, mkey1, gkey, sig1);
  check_rc(prefix, "claim1", rc);

  ret = 255;
  rc = groupsig_claim_verify(&ret, proof, sig1, gkey);
  check_rc(prefix, "claim_verify1", rc);
  check_ret(prefix, "claim_verify1", ret, 1);

  // Test2 (claim_verify): signature in claim different to argument: error
  ret = 255;
  rc = groupsig_claim_verify(&ret, proof, sig2, gkey);
  check_rc(prefix, "claim_verify2", rc);
  check_ret(prefix, "claim_verify2", ret, 0);

  // Test3 (claim_verify): signature in claim different to argument (different user): error
  ret = 255;
  rc = groupsig_claim_verify(&ret, proof, sig3, gkey);
  check_rc(prefix, "claim_verify3", rc);
  check_ret(prefix, "claim_verify3", ret, 0);

  // Test4 (claim+claim_verify): claim+claim_verify signature issued by another user: error
  groupsig_proof_free(proof);
  proof = groupsig_proof_init(gkey->scheme);
  check_ptr(prefix, "proof_init3", proof);

  rc = groupsig_claim(proof, mkey1, gkey, sig3);
  check_rc(prefix, "claim3", rc);

  ret = 255;
  rc = groupsig_claim_verify(&ret, proof, sig2, gkey);
  check_rc(prefix, "claim_verify4", rc);
  check_ret(prefix, "claim_verify4", ret, 0);

  // Test1 (prove_equality+prove_equality_verify): two signatures from the same user (itself): ok
  groupsig_proof_free(proof);
  proof = groupsig_proof_init(gkey->scheme);
  check_ptr(prefix, "proof_init4", proof);

  groupsig_signature_t *sigs[2];
  sigs[0] = sig1;
  sigs[1] = sig2;
  rc = groupsig_prove_equality(proof, mkey1, gkey, sigs, 2);
  check_rc(prefix, "prove_equality1", rc);

  ret = 255;
  rc = groupsig_prove_equality_verify(&ret, proof, gkey, sigs, 2);
  check_rc(prefix, "prove_equality_verify1", rc);
  check_ret(prefix, "prove_equality_verify1", ret, 1);

  // Test2 (prove_equality_verify): swapped order of signatures: error
  sigs[0] = sig2;
  sigs[1] = sig1;
  ret = 255;
  rc = groupsig_prove_equality_verify(&ret, proof, gkey, sigs, 2);
  check_rc(prefix, "prove_equality_verify2", rc);
  check_ret(prefix, "prove_equality_verify2", ret, 0);

  // Test2 (prove_equality_verify): same signature: error
  sigs[0] = sig1;
  sigs[1] = sig1;
  ret = 255;
  rc = groupsig_prove_equality_verify(&ret, proof, gkey, sigs, 2);
  check_rc(prefix, "prove_equality_verify3", rc);
  check_ret(prefix, "prove_equality_verify3", ret, 0);

  // Test3 (prove_equality_verify): one signature from another user: error
  sigs[0] = sig1;
  sigs[1] = sig3;
  ret = 255;
  rc = groupsig_prove_equality_verify(&ret, proof, gkey, sigs, 2);
  check_rc(prefix, "prove_equality_verify4", rc);
  check_ret(prefix, "prove_equality_verify4", ret, 0);

  // Test3 (prove_equality+prove_equality_verify): two signatures from another user: error
  groupsig_proof_free(proof);
  proof = groupsig_proof_init(gkey->scheme);
  check_ptr(prefix, "proof_init5", proof);

  sigs[0] = sig1;
  sigs[1] = sig2;
  rc = groupsig_prove_equality(proof, mkey2, gkey, sigs, 2);
  check_rc(prefix, "prove_equality2", rc);

  ret = 255;
  rc = groupsig_prove_equality_verify(&ret, proof, gkey, sigs, 2);
  check_rc(prefix, "prove_equality_verify5", rc);
  check_ret(prefix, "prove_equality_verify5", ret, 0);

  message_free(msg1);
  message_free(msg2);
  groupsig_signature_free(sig1);
  groupsig_signature_free(sig2);
  groupsig_signature_free(sig3);
  groupsig_proof_free(proof);
  trapdoor_free(trap);
}

void test_group4(char *prefix, groupsig_key_t *gkey, groupsig_key_t *mgkey,
                 groupsig_key_t *mkey1, groupsig_key_t *mkey2) {
  message_t *msg1 = message_from_string((char *) "Hello, World!");
  check_ptr(prefix, "message_from_string1", msg1);
  message_t *msg2 = message_from_string((char *) "World, Hello!");
  check_ptr(prefix, "message_from_string2", msg2);

  groupsig_signature_t *sig1 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init1", sig1);
  groupsig_signature_t *sig2 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init2", sig2);
  groupsig_signature_t *sig3 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init3", sig3);

  // sig1, user1 + msg1
  int rc = groupsig_sign(sig1, msg1, mkey1, gkey, UINT_MAX);
  check_rc(prefix, "sign1", rc);
  // sig2, user1 + msg2
  rc = groupsig_sign(sig2, msg2, mkey1, gkey, UINT_MAX);
  check_rc(prefix, "sign2", rc);
  // sig3, user2 + msg1
  rc = groupsig_sign(sig3, msg1, mkey2, gkey, UINT_MAX);
  check_rc(prefix, "sign3", rc);

  groupsig_key_t *bkey = groupsig_bld_key_random(gkey->scheme, gkey);
  check_ptr(prefix, "bld_key_random", bkey);
  groupsig_key_t* pkey;
  rc = groupsig_bld_key_pub(bkey, &pkey);
  check_rc(prefix, "bld_key_pub", rc);
  check_ptr(prefix, "bld_key_pub", pkey);

  groupsig_blindsig_t *bsig1 = groupsig_blindsig_init(gkey->scheme);
  check_ptr(prefix, "blindsig_init1", bsig1);
  rc = groupsig_blind(bsig1, &bkey, gkey, sig1, msg1);
  check_rc(prefix, "blind1", rc);
  groupsig_blindsig_t *bsig2 = groupsig_blindsig_init(gkey->scheme);
  check_ptr(prefix, "blindsig_init2", bsig2);
  rc = groupsig_blind(bsig2, &bkey, gkey, sig2, msg2);
  check_rc(prefix, "blind2", rc);
  groupsig_blindsig_t *bsig3 = groupsig_blindsig_init(gkey->scheme);
  check_ptr(prefix, "blindsig_init3", bsig3);
  rc = groupsig_blind(bsig3, &bkey, gkey, sig3, msg1);
  check_rc(prefix, "blind3", rc);

  // Test1: two signatures by the same user: ok
  groupsig_blindsig_t *bsigs[2], *csigs[2];
  bsigs[0] = bsig1;
  bsigs[1] = bsig2;
  csigs[0] = groupsig_blindsig_init(gkey->scheme);
  check_ptr(prefix, "blindsig_init4", csigs[0]);
  csigs[1] = groupsig_blindsig_init(gkey->scheme);
  check_ptr(prefix, "blindsig_init5", csigs[1]);

  rc = groupsig_convert(csigs, bsigs, 2, gkey, mgkey, pkey, NULL);
  check_rc(prefix, "convert1", rc);

  identity_t *nym1 = identity_init(gkey->scheme);
  check_ptr(prefix, "identity_init1", nym1);
  identity_t *nym2 = identity_init(gkey->scheme);
  check_ptr(prefix, "identity_init2", nym2);

  rc = groupsig_unblind(nym1, sig1, csigs[0], gkey, bkey, msg1);
  check_rc(prefix, "unblind1", rc);
  rc = groupsig_unblind(nym2, sig2, csigs[1], gkey, bkey, msg2);
  check_rc(prefix, "unblind2", rc);

  uint8_t ret = identity_cmp(nym1, nym2);
  check_ret(prefix, "identity_cmp1", ret, 0);

  // Test2: two signatures, one from another user: error
  groupsig_blindsig_free(csigs[0]);
  groupsig_blindsig_free(csigs[1]);
  identity_free(nym1);
  identity_free(nym2);

  bsigs[0] = bsig1;
  bsigs[1] = bsig3;
  csigs[0] = groupsig_blindsig_init(gkey->scheme);
  check_ptr(prefix, "blindsig_init6", csigs[0]);
  csigs[1] = groupsig_blindsig_init(gkey->scheme);
  check_ptr(prefix, "blindsig_init7", csigs[1]);

  rc = groupsig_convert(csigs, bsigs, 2, gkey, mgkey, pkey, NULL);
  check_rc(prefix, "convert2", rc);

  nym1 = identity_init(gkey->scheme);
  check_ptr(prefix, "identity_init3", nym1);
  nym2 = identity_init(gkey->scheme);
  check_ptr(prefix, "identity_init4", nym2);

  rc = groupsig_unblind(nym1, sig1, csigs[0], gkey, bkey, msg1);
  check_rc(prefix, "unblind3", rc);
  rc = groupsig_unblind(nym2, sig3, csigs[1], gkey, bkey, msg1);
  check_rc(prefix, "unblind4", rc);

  ret = 255;
  ret = identity_cmp(nym1, nym2);
  check_ret(prefix, "identity_cmp2", ret, 1);

  // Test3: non transitivity of conversion
  groupsig_blindsig_free(csigs[0]);
  groupsig_blindsig_free(csigs[1]);
  identity_free(nym1);
  identity_free(nym2);

  bsigs[0] = bsig1;
  bsigs[1] = bsig3;
  csigs[0] = groupsig_blindsig_init(gkey->scheme);
  check_ptr(prefix, "blindsig_init8", csigs[0]);
  csigs[1] = groupsig_blindsig_init(gkey->scheme);
  check_ptr(prefix, "blindsig_init9", csigs[1]);

  rc = groupsig_convert(&csigs[0], &bsigs[0], 1, gkey, mgkey, pkey, NULL);
  check_rc(prefix, "convert3", rc);
  rc = groupsig_convert(&csigs[1], &bsigs[1], 1, gkey, mgkey, pkey, NULL);
  check_rc(prefix, "convert4", rc);

  nym1 = identity_init(gkey->scheme);
  check_ptr(prefix, "identity_init5", nym1);
  nym2 = identity_init(gkey->scheme);
  check_ptr(prefix, "identity_init6", nym2);

  rc = groupsig_unblind(nym1, sig1, csigs[0], gkey, bkey, msg1);
  check_rc(prefix, "unblind5", rc);
  rc = groupsig_unblind(nym2, sig3, csigs[1], gkey, bkey, msg1);
  check_rc(prefix, "unblind6", rc);

  ret = 255;
  ret = identity_cmp(nym1, nym2);
  check_ret(prefix, "identity_cmp3", ret, 1);

  message_free(msg1);
  message_free(msg2);
  groupsig_signature_free(sig1);
  groupsig_signature_free(sig2);
  groupsig_signature_free(sig3);
  groupsig_blindsig_free(csigs[0]);
  groupsig_blindsig_free(csigs[1]);
  groupsig_blindsig_free(bsig1);
  groupsig_blindsig_free(bsig2);
  groupsig_blindsig_free(bsig3);
  groupsig_bld_key_free(bkey);
  groupsig_bld_key_free(pkey);
  identity_free(nym1);
  identity_free(nym2);
}

void test_group5(char *prefix, groupsig_key_t *gkey, groupsig_key_t *mgkey,
                 groupsig_key_t *mkey1, groupsig_key_t *mkey2) {
  message_t *msg1 = message_from_string((char *) "{\"scope\": \"scp1\", \"message\": \"Hello, World!\"}");
  check_ptr(prefix, "message_from_string1", msg1);
  message_t *msg2 = message_from_string((char *) "{\"scope\": \"scp1\", \"message\": \"World, Hello!\"}");
  check_ptr(prefix, "message_from_string2", msg2);
  message_t *msg3 = message_from_string((char *) "{\"scope\": \"scp2\", \"message\": \"Hello, World!\"}");
  check_ptr(prefix, "message_from_string3", msg3);

  groupsig_signature_t *sig1 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init1", sig1);
  groupsig_signature_t *sig2 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init2", sig2);
  groupsig_signature_t *sig3 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init3", sig3);
  groupsig_signature_t *sig4 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init4", sig4);
  groupsig_signature_t *sig5 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init5", sig5);

  // sig1, user1 + msg1
  int rc = groupsig_sign(sig1, msg1, mkey1, gkey, UINT_MAX);
  check_rc(prefix, "sign1", rc);
  // sig2, user1 + msg2
  rc = groupsig_sign(sig2, msg2, mkey1, gkey, UINT_MAX);
  check_rc(prefix, "sign2", rc);
  // sig3, user1 + msg3 (different scope)
  rc = groupsig_sign(sig3, msg3, mkey1, gkey, UINT_MAX);
  check_rc(prefix, "sign3", rc);
  // sig4, user1 + msg1
  rc = groupsig_sign(sig4, msg1, mkey1, gkey, UINT_MAX);
  check_rc(prefix, "sign4", rc);
  // sig5, user2 + msg1
  rc = groupsig_sign(sig5, msg1, mkey2, gkey, UINT_MAX);
  check_rc(prefix, "sign5", rc);

  groupsig_proof_t *proof = groupsig_proof_init(gkey->scheme);
  check_ptr(prefix, "proof_init1", proof);

  message_t *msgs[2];
  groupsig_signature_t *sigs[2];

  // Test1 (link+verify_link): two signatures, same message: ok
  msgs[0] = msg1;
  msgs[1] = msg1;
  sigs[0] = sig1;
  sigs[1] = sig4;

  rc = groupsig_link(&proof, gkey, mkey1, msg1, sigs, msgs, 2);
  check_rc(prefix, "link1", rc);

  uint8_t ret = 255;
  rc = groupsig_verify_link(&ret, gkey, proof, msg1, sigs, msgs, 2);
  check_rc(prefix, "verify_link1", rc);
  check_ret(prefix, "verify_link1", ret, 1);

  // Test2 (verify_link): different message passed in the argument: error
  ret = 255;
  rc = groupsig_verify_link(&ret, gkey, proof, msg2, sigs, msgs, 2);
  check_rc(prefix, "verify_link2", rc);
  check_ret(prefix, "verify_link2", ret, 0);

  // Test3 (verify_link): different messages in the list: error
  msgs[1] = msg2;
  ret = 255;
  rc = groupsig_verify_link(&ret, gkey, proof, msg1, sigs, msgs, 2);
  check_rc(prefix, "verify_link3", rc);
  check_ret(prefix, "verify_link3", ret, 0);

  // Test4 (verify_link): different signatures in the list (same user, different message): error
  msgs[1] = msg1;
  sigs[1] = sig2;
  ret = 255;
  rc = groupsig_verify_link(&ret, gkey, proof, msg1, sigs, msgs, 2);
  check_rc(prefix, "verify_link4", rc);
  check_ret(prefix, "verify_link4", ret, 0);

  // Test5 (verify_link): different signatures in the list (different user): error
  sigs[1] = sig5;
  ret = 255;
  rc = groupsig_verify_link(&ret, gkey, proof, msg1, sigs, msgs, 2);
  check_rc(prefix, "verify_link5", rc);
  check_ret(prefix, "verify_link5", ret, 0);

  // Test6 (link): two signatures from different users: error
  groupsig_proof_free(proof);
  proof = groupsig_proof_init(gkey->scheme);
  check_ptr(prefix, "proof_init2", proof);

  msgs[0] = msg1;
  msgs[1] = msg1;
  sigs[0] = sig1;
  sigs[1] = sig5;

  rc = groupsig_link(&proof, gkey, mkey1, msg1, sigs, msgs, 2);
  check_ret(prefix, "link2 (FAIL)", rc, IFAIL);

  // Test7 (link): two signatures from same user but different scope: error
  groupsig_proof_free(proof);
  proof = groupsig_proof_init(gkey->scheme);
  check_ptr(prefix, "proof_init3", proof);

  msgs[0] = msg1;
  msgs[1] = msg1;
  sigs[0] = sig1;
  sigs[1] = sig3;

  rc = groupsig_link(&proof, gkey, mkey1, msg1, sigs, msgs, 2);
  check_ret(prefix, "link3 (FAIL)", rc, IFAIL);

  message_free(msg1);
  message_free(msg2);
  message_free(msg3);
  groupsig_signature_free(sig1);
  groupsig_signature_free(sig2);
  groupsig_signature_free(sig3);
  groupsig_signature_free(sig4);
  groupsig_signature_free(sig5);
  groupsig_proof_free(proof);
}

void test_group6(char *prefix, groupsig_key_t *gkey, groupsig_key_t *mgkey,
                 groupsig_key_t *mkey1, groupsig_key_t *mkey2) {
  message_t *msg1 = message_from_string((char *) "{\"scope\": \"scp1\", \"message\": \"Hello, World!\"}");
  check_ptr(prefix, "message_from_string1", msg1);
  message_t *msg2 = message_from_string((char *) "{\"scope\": \"scp1\", \"message\": \"World, Hello!\"}");
  check_ptr(prefix, "message_from_string2", msg2);
  message_t *msg3 = message_from_string((char *) "{\"scope\": \"scp2\", \"message\": \"Hello, World!\"}");
  check_ptr(prefix, "message_from_string3", msg3);

  groupsig_signature_t *sig1 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init1", sig1);
  groupsig_signature_t *sig2 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init2", sig2);
  groupsig_signature_t *sig3 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init3", sig3);
  groupsig_signature_t *sig4 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init4", sig4);
  groupsig_signature_t *sig5 = groupsig_signature_init(gkey->scheme);
  check_ptr(prefix, "signature_init5", sig5);

  // sig1, user1 + msg1
  int rc = groupsig_sign(sig1, msg1, mkey1, gkey, 1);
  check_rc(prefix, "sign1", rc);
  // sig2, user1 + msg2
  rc = groupsig_sign(sig2, msg2, mkey1, gkey, 2);
  check_rc(prefix, "sign2", rc);
  // sig3, user1 + msg3 (different scope)
  rc = groupsig_sign(sig3, msg3, mkey1, gkey, 3);
  check_rc(prefix, "sign3", rc);
  // sig4, user1 + msg1
  rc = groupsig_sign(sig4, msg1, mkey1, gkey, 2);
  check_rc(prefix, "sign4", rc);
  // sig5, user2 + msg1
  rc = groupsig_sign(sig5, msg1, mkey2, gkey, 1);
  check_rc(prefix, "sign5", rc);

  groupsig_proof_t *proof = groupsig_proof_init(gkey->scheme);
  check_ptr(prefix, "proof_init1", proof);

  message_t *msgs[2];
  groupsig_signature_t *sigs[2];

  // Test1 (seqlink+verify_seqlink): two signatures, same message: ok
  // In order to validate a signature as sequential they must be consecutives
  msgs[0] = msg1;
  msgs[1] = msg1;
  sigs[0] = sig1;
  sigs[1] = sig4;

  rc = groupsig_seqlink(&proof, gkey, mkey1, msg1, sigs, msgs, 2);
  check_rc(prefix, "seqlink1", rc);

  uint8_t ret = 255;
  rc = groupsig_verify_seqlink(&ret, gkey, proof, msg1, sigs, msgs, 2);
  check_rc(prefix, "verify_seqlink1", rc);
  check_ret(prefix, "verify_seqlink1", ret, 1);

  // Test2 (verify_seqlink): different message passed in the argument: error
  ret = 255;
  rc = groupsig_verify_seqlink(&ret, gkey, proof, msg2, sigs, msgs, 2);
  check_rc(prefix, "verify_seqlink2", rc);
  check_ret(prefix, "verify_seqlink2", ret, 0);

  // Test3 (verify_seqlink): different messages in the list: error
  msgs[1] = msg2;
  ret = 255;
  rc = groupsig_verify_seqlink(&ret, gkey, proof, msg1, sigs, msgs, 2);
  check_rc(prefix, "verify_seqlink3", rc);
  check_ret(prefix, "verify_seqlink3", ret, 0);

  // Test4 (verify_seqlink): different signatures in the list (same user, different message): error
  msgs[1] = msg1;
  sigs[1] = sig2;
  ret = 255;
  rc = groupsig_verify_seqlink(&ret, gkey, proof, msg1, sigs, msgs, 2);
  check_rc(prefix, "verify_seqlink4", rc);
  check_ret(prefix, "verify_seqlink4", ret, 0);

  // Test5 (verify_seqlink): different signatures in the list (different user): error
  sigs[1] = sig5;
  ret = 255;
  rc = groupsig_verify_seqlink(&ret, gkey, proof, msg1, sigs, msgs, 2);
  check_rc(prefix, "verify_seqlink5", rc);
  check_ret(prefix, "verify_seqlink5", ret, 0);

  // Test6 (seqlink): two signatures from different users: error
  groupsig_proof_free(proof);
  proof = groupsig_proof_init(gkey->scheme);
  check_ptr(prefix, "proof_init2", proof);

  msgs[0] = msg1;
  msgs[1] = msg1;
  sigs[0] = sig1;
  sigs[1] = sig5;

  rc = groupsig_seqlink(&proof, gkey, mkey1, msg1, sigs, msgs, 2);
  check_ret(prefix, "seqlink2 (FAIL)", rc, IFAIL);

  // Test7 (seqlink): two signatures from same user but different scope: error
  groupsig_proof_free(proof);
  proof = groupsig_proof_init(gkey->scheme);
  check_ptr(prefix, "proof_init3", proof);

  msgs[0] = msg1;
  msgs[1] = msg1;
  sigs[0] = sig1;
  sigs[1] = sig3;

  rc = groupsig_seqlink(&proof, gkey, mkey1, msg1, sigs, msgs, 2);
  check_ret(prefix, "seqlink3 (FAIL)", rc, IFAIL);

  // Test8 (seqlink+verify_seqlink): two signatures with swapped order: error
  groupsig_proof_free(proof);
  proof = groupsig_proof_init(gkey->scheme);
  check_ptr(prefix, "proof_init4", proof);

  msgs[0] = msg1;
  msgs[1] = msg1;
  sigs[0] = sig4;
  sigs[1] = sig1;

  rc = groupsig_seqlink(&proof, gkey, mkey1, msg1, sigs, msgs, 2);
  check_rc(prefix, "seqlink4", rc);

  ret = 255;
  rc = groupsig_verify_seqlink(&ret, gkey, proof, msg1, sigs, msgs, 2);
  check_rc(prefix, "verify_seqlink6", rc);
  check_ret(prefix, "verify_seqlink6", ret, 0);

  message_free(msg1);
  message_free(msg2);
  message_free(msg3);
  groupsig_signature_free(sig1);
  groupsig_signature_free(sig2);
  groupsig_signature_free(sig3);
  groupsig_signature_free(sig4);
  groupsig_signature_free(sig5);
  groupsig_proof_free(proof);
}

void test(char *scheme) {
  groupsig_t *gsig;
  groupsig_key_t *gkey, *mgkey1, *mgkey2;
  gml_t *gml;
  crl_t *crl;
  groupsig_key_t **mkeys = malloc(MEMBERS * sizeof(groupsig_key_t *));

  printf("# Testing setup...\n");
  test_init("setup", scheme, &gsig, &gkey, &mgkey1, &mgkey2, &gml, &crl);

  int n1, n2, n3;
  n1 = rand() % MEMBERS;
  do {
    n2 = rand() % MEMBERS;
  } while (n2 == n1);
  do {
    n3 = rand() % MEMBERS;
  } while (n3 == n2);

  printf("# Testing registration...\n");
  for (int i = 0; i < MEMBERS; i++) {
    test_registration("registration", i, gsig, gkey, mgkey1, gml, &mkeys[i]);
    if (gsig->desc->has_gml) {
      test_gml("registration", i, gkey, &gml);
    }
  }

  printf("\n# Testing sign, verify...\n");
  test_signing(scheme, "signing", gkey, mkeys[n1]);

  if (group1_implemented(scheme)) {
    printf("\n# Testing open...\n");
    if (multi_mgrkey(scheme))
      test_group1(scheme, "group1", gkey, mgkey2, gml, mkeys[n2], n2);
    else
      test_group1(scheme, "group1", gkey, mgkey1, gml, mkeys[n2], n2);
  }

  if (group2_implemented(scheme)) {
    printf("\n# Testing open_verify...\n");
    if (multi_mgrkey(scheme))
      test_group2("group2", gkey, mgkey2, gml, mkeys[n3], n3);
    else
      test_group2("group2", gkey, mgkey1, gml, mkeys[n3], n3);
  }

  if (group3_implemented(scheme)) {
    printf("\n# Testing reveal, trace, claim, claim_verify, prove_equality, "
           "prove_equality_verify...\n");
    test_group3("group3", gkey, mgkey1, gml, crl, mkeys[n1], mkeys[n3], n3);
  }

  if (group4_implemented(scheme)) {
    printf("\n# Testing blind, convert, unblind...\n");
    test_group4("group4", gkey, mgkey2, mkeys[n1], mkeys[n2]);
  }

  if (group5_implemented(scheme)) {
    printf("\n# Testing identify, link, verify_link...\n");
    test_group5("group5", gkey, mgkey2, mkeys[n1], mkeys[n2]);
  }

  if (group6_implemented(scheme)) {
    printf("\n# Testing seqlink, verify_seqlink...\n");
    test_group6("group6", gkey, mgkey2, mkeys[n1], mkeys[n2]);
  }
  printf("\n");

  groupsig_grp_key_free(gkey);
  groupsig_mgr_key_free(mgkey1);
  if (multi_mgrkey(scheme))
    groupsig_mgr_key_free(mgkey2);
  for (int i = 0; i < MEMBERS; i++)
    groupsig_mem_key_free(mkeys[i]);
  free(mkeys);
  if (gsig->desc->has_gml)
    gml_free(gml);
  if (gsig->desc->has_crl)
    crl_free(crl);
  groupsig_clear(gsig->desc->code);
}
