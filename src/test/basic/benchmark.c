#include "utils.h"

#define START_T start_t = clock()
#define END_T end_t = clock()
#define SAVE_T(type) TIMES[type] = end_t - start_t


void save_phase(unsigned char type, int phase, clock_t start_t, clock_t end_t, int idx) {
  int time = -1;
  switch (type) {
  case 'm':
    if (!phase)
      time = JOIN_MEM0_T;
    else if (phase == 1)
      time = JOIN_MEM1_T;
    else if (phase == 2)
      time = JOIN_MEM2_T;
    else if (phase == 3)
      time = JOIN_MEM3_T;
    else if (phase == 4)
      time = JOIN_MEM4_T;
    break;
  case 'g':
    if (!phase)
      time = JOIN_MGR0_T;
    else if (phase == 1)
      time = JOIN_MGR1_T;
    else if (phase == 2)
      time = JOIN_MGR2_T;
    else if (phase == 3)
      time = JOIN_MGR3_T;
    break;
  }
  TIMES_JOIN[time][idx] = end_t - start_t;
}

void analyze_init(char *scheme, groupsig_t **gsig, groupsig_key_t **gkey,
                  groupsig_key_t **mgkey1, groupsig_key_t **mgkey2, gml_t **gml, crl_t **crl) {
  *gsig = groupsig_get_groupsig_from_str(scheme);
  int multi = multi_mgrkey(scheme);

  uint8_t code = (*gsig)->desc->code;
  groupsig_init(code, time(NULL));

  groupsig_key_t *_gkey = groupsig_grp_key_init(code);
  groupsig_key_t *_mgkey1 = groupsig_mgr_key_init(code);
  groupsig_key_t *_mgkey2;
  if (multi)
    _mgkey2 = groupsig_mgr_key_init(code);

  if ((*gsig)->desc->has_gml)
    *gml = gml_init(code);

  if ((*gsig)->desc->has_crl)
    *crl = crl_init(code);

  clock_t start_t, end_t;
  START_T;
  groupsig_setup(code, _gkey, _mgkey1, *gml);
  END_T;
  SAVE_T(SETUP1_T);
  if (multi) {
    START_T;
    groupsig_setup(code, _gkey, _mgkey2, *gml);
    END_T;
    SAVE_T(SETUP2_T);
  }

  *gkey = _gkey;
  *mgkey1 = _mgkey1;
  if (multi)
    *mgkey2 = _mgkey2;
}

void analyze_registration(groupsig_t *gsig, groupsig_key_t *gkey,
                          groupsig_key_t *mgkey, gml_t *gml, groupsig_key_t **mkey,
                          int idx) {
  uint8_t start, seq, code;
  gsig->get_joinstart(&start);
  gsig->get_joinseq(&seq);
  code = gsig->desc->code;
  groupsig_key_t *_mkey = groupsig_mem_key_init(code);

  message_t *msg = message_init();
  message_t *msg2 = message_init();
  int phase = 0;
  clock_t start_t, end_t;
  if (start == 1 && seq == 1) { // kty04
    START_T;
    groupsig_join_mem(&msg2, _mkey, 0, msg, gkey);
    END_T;
    save_phase('m', phase, start_t, end_t, idx);

    START_T;
    groupsig_join_mgr(&msg, gml, mgkey, 1, msg2, gkey);
    END_T;
    save_phase('g', phase, start_t, end_t, idx);
    message_free(msg2); msg2 = message_init();

    _mkey = groupsig_mem_key_import(code, msg->bytes, msg->length);
  } else {
    if (start) {
      START_T;
      groupsig_join_mem(&msg2, _mkey, phase, msg, gkey);
      END_T;
      save_phase('m', phase, start_t, end_t, idx);
      phase++;
    }
    while (phase < seq) {
      START_T;
      groupsig_join_mgr(&msg, gml, mgkey, phase, msg2, gkey);
      END_T;
      save_phase('g', phase, start_t, end_t, idx);

      if (msg2) {
        message_free(msg2); msg2 = message_init();
      }
      phase++;

      START_T;
      groupsig_join_mem(&msg2, _mkey, phase, msg, gkey);
      END_T;
      save_phase('m', phase, start_t, end_t, idx);
      if (msg) {
        message_free(msg); msg = message_init();
      }
      phase++;
    }
  }

  *mkey = _mkey;

  if (msg)
    message_free(msg);
  if (msg2)
    message_free(msg2);
}

void analyze_signing(char *scheme, groupsig_key_t *gkey, groupsig_key_t *mkey) {
  message_t *msg;
  if (!strcmp(scheme, "dl21") || !strcmp(scheme, "dl21seq")) {
    msg = message_from_string((char *) "{\"scope\": \"scp\", \"message\": \"Hello, World!\"}");
  } else {
    msg = message_from_string((char *) "Hello, World!");
  }

  groupsig_signature_t *sig = groupsig_signature_init(gkey->scheme);

  clock_t start_t, end_t;
  START_T;
  groupsig_sign(sig, msg, mkey, gkey, UINT_MAX);
  END_T;
  SAVE_T(SIGN_T);

  uint8_t ret;
  START_T;
  groupsig_verify(&ret, sig, msg, gkey);
  END_T;
  SAVE_T(VERIFY_T);

  message_free(msg);
  groupsig_signature_free(sig);
}

void analyze_group1(char *scheme, groupsig_key_t *gkey, groupsig_key_t *mgkey,
                    gml_t *gml, groupsig_key_t *mkey) {
  message_t *msg = message_from_string((char *) "Hello, World!");
  groupsig_signature_t *sig = groupsig_signature_init(gkey->scheme);

  groupsig_sign(sig, msg, mkey, gkey, UINT_MAX);

  uint64_t index;
  groupsig_proof_t *proof;
  clock_t start_t, end_t;
  if (strcmp(scheme, "bbs04")) {
    proof = groupsig_proof_init(gkey->scheme);

    START_T;
    groupsig_open(&index, proof, NULL, sig, gkey, mgkey, gml);
    END_T;
  } else {
    START_T;
    groupsig_open(&index, NULL, NULL, sig, gkey, mgkey, gml);
    END_T;
  }
  if (!index)
    SAVE_T(OPEN_0_T);
  else
    SAVE_T(OPEN_N_T);

  message_free(msg);
  groupsig_signature_free(sig);
  if (strcmp(scheme, "bbs04"))
    groupsig_proof_free(proof);
}

void analyze_group2(groupsig_key_t *gkey, groupsig_key_t *mgkey,
                    gml_t *gml, groupsig_key_t *mkey) {
  message_t *msg = message_from_string((char *) "Hello, World!");
  groupsig_signature_t *sig = groupsig_signature_init(gkey->scheme);
  groupsig_sign(sig, msg, mkey, gkey, UINT_MAX);

  groupsig_proof_t *proof = groupsig_proof_init(gkey->scheme);
  uint64_t index;
  groupsig_open(&index, proof, NULL, sig, gkey, mgkey, gml);

  clock_t start_t, end_t;
  uint8_t ret;
  START_T;
  groupsig_open_verify(&ret, proof, sig, gkey);
  END_T;
  SAVE_T(OPEN_VERIFY_T);

  message_free(msg);
  groupsig_signature_free(sig);
  groupsig_proof_free(proof);
}

void analyze_group3_reveal(groupsig_key_t *gkey, groupsig_key_t *mgkey,
                           gml_t *gml, crl_t *crl, groupsig_key_t *mkey,
                           int idx) {
  message_t *msg = message_from_string((char *) "Hello, World!");
  groupsig_signature_t *sig = groupsig_signature_init(gkey->scheme);
  groupsig_proof_t *proof = groupsig_proof_init(gkey->scheme);
  trapdoor_t *trap = trapdoor_init(gkey->scheme);

  groupsig_sign(sig, msg, mkey, gkey, UINT_MAX);

  clock_t start_t, end_t;
  uint8_t ret;
  if (!idx) {
    START_T;
    groupsig_reveal(trap, crl, gml, idx);
    END_T;
    SAVE_T(REVEAL_0_T);

    START_T;
    groupsig_trace(&ret, sig, gkey, crl, mgkey, gml);
    END_T;
    SAVE_T(TRACE_0_T);
  } else {
    groupsig_reveal(trap, crl, gml, idx);
  }

  message_free(msg);
  groupsig_signature_free(sig);
  groupsig_proof_free(proof);
  trapdoor_free(trap);
}

void analyze_group3_trace(groupsig_key_t *gkey, groupsig_key_t *mgkey,
                          gml_t *gml, crl_t *crl, groupsig_key_t *mkey) {
  message_t *msg = message_from_string((char *) "Hello, World!");
  groupsig_signature_t *sig = groupsig_signature_init(gkey->scheme);
  groupsig_proof_t *proof = groupsig_proof_init(gkey->scheme);
  uint64_t index;
  trapdoor_t *trap = trapdoor_init(gkey->scheme);

  groupsig_sign(sig, msg, mkey, gkey, UINT_MAX);

  clock_t start_t, end_t;
  START_T;
  groupsig_reveal(trap, crl, gml, MEMBERS - 1);
  END_T;
  SAVE_T(REVEAL_N_T);

  uint8_t ret;
  START_T;
  groupsig_trace(&ret, sig, gkey, crl, mgkey, gml);
  END_T;
  SAVE_T(TRACE_N_T);

  message_free(msg);
  groupsig_signature_free(sig);
  groupsig_proof_free(proof);
  trapdoor_free(trap);
}

void analyze_group3(groupsig_key_t *gkey, groupsig_key_t *mgkey,
                    gml_t *gml, crl_t *crl, groupsig_key_t *mkey) {
  message_t *msg = message_from_string((char *) "Hello, World!");

  groupsig_signature_t *sig1 = groupsig_signature_init(gkey->scheme);
  groupsig_signature_t *sig2 = groupsig_signature_init(gkey->scheme);
  groupsig_signature_t *sigs[2];

  groupsig_sign(sig1, msg, mkey, gkey, UINT_MAX);
  groupsig_sign(sig2, msg, mkey, gkey, UINT_MAX);
  sigs[0] = sig1;
  sigs[1] = sig2;

  groupsig_proof_t *proof = groupsig_proof_init(gkey->scheme);

  clock_t start_t, end_t;
  START_T;
  groupsig_claim(proof, mkey, gkey, sig1);
  END_T;
  SAVE_T(CLAIM_T);

  uint8_t ret;
  START_T;
  groupsig_claim_verify(&ret, proof, sig1, gkey);
  END_T;
  SAVE_T(CLAIM_VERIFY_T);

  groupsig_proof_free(proof);
  proof = groupsig_proof_init(gkey->scheme);

  START_T;
  groupsig_prove_equality(proof, mkey, gkey, sigs, 2);
  END_T;
  SAVE_T(PROVE_EQUALITY_T);

  START_T;
  groupsig_prove_equality_verify(&ret, proof, gkey, sigs, 2);
  END_T;
  SAVE_T(PROVE_EQUALITY_VERIFY_T);

  message_free(msg);
  groupsig_signature_free(sig1);
  groupsig_signature_free(sig2);
  groupsig_proof_free(proof);
}

void analyze_group4(groupsig_key_t *gkey, groupsig_key_t *mgkey,
                    groupsig_key_t *mkey) {
  message_t *msg1 = message_from_string((char *) "Hello, World!");
  message_t *msg2 = message_from_string((char *) "World, Hello!");

  groupsig_signature_t *sig1 = groupsig_signature_init(gkey->scheme);
  groupsig_signature_t *sig2 = groupsig_signature_init(gkey->scheme);

  groupsig_sign(sig1, msg1, mkey, gkey, UINT_MAX);
  groupsig_sign(sig2, msg2, mkey, gkey, UINT_MAX);

  groupsig_key_t *bkey = groupsig_bld_key_random(gkey->scheme, gkey);
  groupsig_key_t* pkey;
  groupsig_bld_key_pub(bkey, &pkey);

  groupsig_blindsig_t *bsig1 = groupsig_blindsig_init(gkey->scheme);
  groupsig_blind(bsig1, &bkey, gkey, sig1, msg1);
  groupsig_blindsig_t *bsig2 = groupsig_blindsig_init(gkey->scheme);
  groupsig_blind(bsig2, &bkey, gkey, sig2, msg2);

  groupsig_blindsig_t *bsigs[2], *csigs[2];
  bsigs[0] = bsig1;
  bsigs[1] = bsig2;
  csigs[0] = groupsig_blindsig_init(gkey->scheme);
  csigs[1] = groupsig_blindsig_init(gkey->scheme);

  clock_t start_t, end_t;
  START_T;
  groupsig_convert(csigs, bsigs, 2, gkey, mgkey, pkey, NULL);
  END_T;
  SAVE_T(CONVERT_T);

  identity_t *nym1 = identity_init(gkey->scheme);

  START_T;
  groupsig_unblind(nym1, sig1, csigs[0], gkey, bkey, msg1);
  END_T;
  SAVE_T(UNBLIND_T);

  message_free(msg1);
  message_free(msg2);
  groupsig_signature_free(sig1);
  groupsig_signature_free(sig2);
  groupsig_blindsig_free(csigs[0]);
  groupsig_blindsig_free(csigs[1]);
  groupsig_blindsig_free(bsig1);
  groupsig_blindsig_free(bsig2);
  groupsig_bld_key_free(bkey);
  groupsig_bld_key_free(pkey);
  identity_free(nym1);
}

void analyze_group5(groupsig_key_t *gkey, groupsig_key_t *mgkey,
                    groupsig_key_t *mkey) {
  message_t *msg = message_from_string((char *) "{\"scope\": \"scp1\", \"message\": \"Hello, World!\"}");

  groupsig_signature_t *sig1 = groupsig_signature_init(gkey->scheme);
  groupsig_signature_t *sig2 = groupsig_signature_init(gkey->scheme);

  groupsig_sign(sig1, msg, mkey, gkey, UINT_MAX);
  groupsig_sign(sig2, msg, mkey, gkey, UINT_MAX);

  groupsig_proof_t *proof = groupsig_proof_init(gkey->scheme);

  message_t *msgs[2];
  groupsig_signature_t *sigs[2];
  msgs[0] = msg;
  msgs[1] = msg;
  sigs[0] = sig1;
  sigs[1] = sig2;

  clock_t start_t, end_t;
  START_T;
  groupsig_link(&proof, gkey, mkey, msg, sigs, msgs, 2);
  END_T;
  SAVE_T(LINK_T);

  uint8_t ret;
  START_T;
  groupsig_verify_link(&ret, gkey, proof, msg, sigs, msgs, 2);
  END_T;
  SAVE_T(LINK_VERIFY_T);

  message_free(msg);
  groupsig_signature_free(sig1);
  groupsig_signature_free(sig2);
  groupsig_proof_free(proof);
}

void analyze_group6(groupsig_key_t *gkey, groupsig_key_t *mgkey,
                    groupsig_key_t *mkey) {
  message_t *msg = message_from_string((char *) "{\"scope\": \"scp\", \"message\": \"Hello, World!\"}");

  groupsig_signature_t *sig1 = groupsig_signature_init(gkey->scheme);
  groupsig_signature_t *sig2 = groupsig_signature_init(gkey->scheme);

  groupsig_sign(sig1, msg, mkey, gkey, 1);
  groupsig_sign(sig2, msg, mkey, gkey, 2);

  groupsig_proof_t *proof = groupsig_proof_init(gkey->scheme);

  message_t *msgs[2];
  groupsig_signature_t *sigs[2];

  clock_t start_t, end_t;
  // Test1 (seqlink+verify_seqlink): two signatures, same message: ok
  // In order to validate a signature as sequential they must be consecutives
  msgs[0] = msg;
  msgs[1] = msg;
  sigs[0] = sig1;
  sigs[1] = sig2;

  START_T;
  groupsig_seqlink(&proof, gkey, mkey, msg, sigs, msgs, 2);
  END_T;
  SAVE_T(SEQLINK_T);

  uint8_t ret;
  START_T;
  groupsig_verify_seqlink(&ret, gkey, proof, msg, sigs, msgs, 2);
  END_T;
  SAVE_T(SEQLINK_VERIFY_T);

  message_free(msg);
  groupsig_signature_free(sig1);
  groupsig_signature_free(sig2);
  groupsig_proof_free(proof);
}

void dump_times(char *scheme, int iter) {
  FILE *fp1, *fp2;
  char name1_f[50];
  snprintf(name1_f, 50, "%s/%s_%d" "m_%d" "i.csv", PATH, scheme, MEMBERS, ITER);
  char name2_f[50];
  snprintf(name2_f, 50, "%s/%s_join_%d" "m_%d" "i.csv", PATH, scheme, MEMBERS, ITER);
  char *mode;
  if (!iter)
    mode = "w";
  else
    mode = "a";
  fp1 = fopen(name1_f, mode);
  fp2 = fopen(name2_f, mode);
  if (!iter) {
    fprintf(fp1, "setup1,setup2,sign,verify,open0,openN,open_verify,reveal0,revealN,trace0,traceN,claim,claim_verify,prove_equality,prove_equality_verify,blind,convert,unblind,link,link_verify,seqlink,seqlink_verify\n");
    fprintf(fp2, "join_mem0,join_mgr1,join_mem2,join_mgr3,join_mem4,join_mgr0,join_mem1,join_mgr2,join_mem3\n");
  }
  if (!fp1 || !fp2) {
    fprintf(stderr, "Error: output file could not be opened\n");
    if (fp1) fclose(fp1);
    if (fp2) fclose(fp2);
    exit(1);
  } else {
    for (int i = 0; i < N_BENCH; i++) {
      fprintf(fp1, "%f", (double) TIMES[i] / CLOCKS_PER_SEC);
      if (i < N_BENCH - 1)
        fprintf(fp1, ",");
      else
        fprintf(fp1, "\n");
    }
    fclose(fp1);
    for (int i = 0; i < N_JOIN; i++) {
      for (int j = 0; j < MEMBERS; j++) {
        fprintf(fp2, "%f", (double) TIMES_JOIN[i][j] / CLOCKS_PER_SEC);
        if (j < MEMBERS - 1)
          fprintf(fp2, ";");
        else
          if (i < N_JOIN - 1)
            fprintf(fp2, ",");
          else
            fprintf(fp2, "\n");
      }
    }
    fclose(fp2);
  }
}

void benchmark(char *scheme, int iter) {
  groupsig_t *gsig;
  groupsig_key_t *gkey, *mgkey1, *mgkey2;
  groupsig_key_t **mkeys = malloc(MEMBERS * sizeof(groupsig_key_t *));
  gml_t *gml;
  crl_t *crl;

  printf("# Analyzing %s [%d]\n", scheme, iter);
  analyze_init(scheme, &gsig, &gkey, &mgkey1, &mgkey2, &gml, &crl);

  for (int i = 0; i < MEMBERS; i++)
    analyze_registration(gsig, gkey, mgkey1, gml, &mkeys[i], i);

  analyze_signing(scheme, gkey, mkeys[0]);

  if (group1_implemented(scheme))
    if (multi_mgrkey(scheme)) {
      analyze_group1(scheme, gkey, mgkey2, gml, mkeys[0]);
      analyze_group1(scheme, gkey, mgkey2, gml, mkeys[MEMBERS - 1]);
    } else {
      analyze_group1(scheme, gkey, mgkey1, gml, mkeys[0]);
      analyze_group1(scheme, gkey, mgkey1, gml, mkeys[MEMBERS - 1]);
    }

  if (group2_implemented(scheme))
    if (multi_mgrkey(scheme))
      analyze_group2(gkey, mgkey2, gml, mkeys[0]);
    else
      analyze_group2(gkey, mgkey1, gml, mkeys[0]);

  if (group3_implemented(scheme)) {
    for (int i = 0; i < MEMBERS - 1; i++)
      analyze_group3_reveal(gkey, mgkey1, gml, crl, mkeys[i], i);
    analyze_group3_trace(gkey, mgkey1, gml, crl, mkeys[MEMBERS - 1]);
    analyze_group3(gkey, mgkey1, gml, crl, mkeys[0]);
  }

  if (group4_implemented(scheme)) {
    analyze_group4(gkey, mgkey2, mkeys[0]);
  }

  if (group5_implemented(scheme)) {
    analyze_group5(gkey, mgkey2, mkeys[0]);
  }

  if (group6_implemented(scheme)) {
    analyze_group6(gkey, mgkey2, mkeys[0]);
  }

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

  dump_times(scheme, iter);
}
