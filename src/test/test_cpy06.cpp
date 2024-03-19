/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <iostream>
#include <limits.h>

#include "gtest/gtest.h"

#include "groupsig.h"
#include "gml.h"
#include "crl.h"
#include "cpy06.h"
#include "message.h"

using namespace std;

namespace groupsig {

  // The fixture for testing CPY06 scheme.
  class CPY06Test : public ::testing::Test {
  protected:
    // You can remove any or all of the following functions if their bodies
    // would be empty.
    groupsig_key_t *mgrkey;
    groupsig_key_t *grpkey;
    gml_t *gml;
    crl_t *crl;
    groupsig_key_t **memkey;
    uint32_t n;

    CPY06Test() {

      int rc;

      rc = groupsig_init(GROUPSIG_CPY06_CODE, time(NULL));
      EXPECT_EQ(rc, IOK);

      mgrkey = groupsig_mgr_key_init(GROUPSIG_CPY06_CODE);
      EXPECT_NE(mgrkey, nullptr);

      grpkey = groupsig_grp_key_init(GROUPSIG_CPY06_CODE);
      EXPECT_NE(grpkey, nullptr);

      gml = gml_init(GROUPSIG_CPY06_CODE);
      EXPECT_NE(gml, nullptr);

      crl = crl_init(GROUPSIG_CPY06_CODE);
      EXPECT_NE(crl, nullptr);

      memkey = nullptr;
      n = 0;

    }

    ~CPY06Test() override {
      groupsig_mgr_key_free(mgrkey); mgrkey = NULL;
      groupsig_grp_key_free(grpkey); grpkey = NULL;
      gml_free(gml); gml = NULL;
      crl_free(crl); crl = NULL;
      if (memkey) {
        for (int i=0; i<n; i++) {
          groupsig_mem_key_free(memkey[i]); memkey[i] = NULL;
        }
        free(memkey); memkey = NULL;
      }
      groupsig_clear(GROUPSIG_CPY06_CODE);
    }

    void addMembers(uint32_t n) {

      message_t *m1, *m2, *m3, *m4, *m5;
      int rc;
      uint32_t i;

      memkey = (groupsig_key_t **) malloc(sizeof(groupsig_key_t *)*n);
      memset(memkey,0,sizeof(groupsig_key_t *)*n);
      ASSERT_NE(memkey, nullptr);

      m1 = m2 = m3 = m4 = m5 = nullptr;
      for (i=0; i<n; i++) {

        memkey[i] = groupsig_mem_key_init(grpkey->scheme);
        ASSERT_NE(memkey[i], nullptr);

        // m1 = message_init();
        // ASSERT_NE(m1, nullptr);

        rc = groupsig_join_mem(&m1, memkey[i], 0, nullptr, grpkey);
        ASSERT_EQ(rc, IOK);

        // m2 = message_init();
        // ASSERT_NE(m2, nullptr);

        rc = groupsig_join_mgr(&m2, gml, mgrkey, 1, m1, grpkey);
        ASSERT_EQ(rc, IOK);

	//        memkey[i] = groupsig_mem_key_import(GROUPSIG_CPY06_CODE, m2->bytes, m2->length);

        // m3 = message_init();
        // ASSERT_NE(m3, nullptr);

        rc = groupsig_join_mem(&m3, memkey[i], 2, m2, grpkey);
        ASSERT_EQ(rc, IOK);

        // m4 = message_init();
        // ASSERT_NE(m4, nullptr);

        rc = groupsig_join_mgr(&m4, gml, mgrkey, 3, m3, grpkey);
        ASSERT_EQ(rc, IOK);

        rc = groupsig_join_mem(&m5, memkey[i], 4, m4, grpkey);
        ASSERT_EQ(rc, IOK);

	// // @TODO We'll probably need to delete this once the interactive
	// // join protocol works as it should.
	// rc = groupsig_mem_key_free(memkey[i]);
	// ASSERT_EQ(rc, IOK);	

	if(m1) { message_free(m1); m1 = NULL; }
	if(m2) { message_free(m2); m2 = NULL; }
	if(m3) { message_free(m3); m3 = NULL; }
	if(m4) { message_free(m4); m4 = NULL; }
	if(m5) { message_free(m5); m5 = NULL; }	

      }

      this->n = n;

      // if(m1) { message_free(m1); m1 = NULL; }
      // if(m2) { message_free(m2); m2 = NULL; }
      // if(m3) { message_free(m3); m3 = NULL; }
      // if(m4) { message_free(m4); m4 = NULL; }	      
      // if(m5) { message_free(m5); m5 = NULL; }
	
    }

    // If the constructor and destructor are not enough for setting up
    // and cleaning up each test, you can define the following methods:

    void SetUp() override {
      // Code here will be called immediately after the constructor (right
      // before each test).
    }

    void TearDown() override {
      // Code here will be called immediately after each test (right
      // before the destructor).
    }

    // Class members declared here can be used by all tests in the test suite
    // for CPY06.
  };


  TEST_F(CPY06Test, GetCodeFromStr) {

    int rc;
    uint8_t scheme;

    rc = groupsig_get_code_from_str(&scheme, (char *) GROUPSIG_CPY06_NAME);
    EXPECT_EQ(rc, IOK);

    EXPECT_EQ(scheme, GROUPSIG_CPY06_CODE);

  }

  // Tests that the CPY06 constructor creates the required keys.
  TEST_F(CPY06Test, CreatesGrpAndMgrKeys) {

    /* Scheme is set to CPY06 */
    EXPECT_EQ(grpkey->scheme, GROUPSIG_CPY06_CODE);
    EXPECT_EQ(mgrkey->scheme, GROUPSIG_CPY06_CODE);

  }

  /* groupsig_get_joinstart must return CPY06_JOIN_START */
  TEST_F(CPY06Test, CheckJoinStart) {

    int rc;
    uint8_t start;

    rc = groupsig_get_joinstart(GROUPSIG_CPY06_CODE, &start);
    EXPECT_EQ(rc, IOK);

    EXPECT_EQ(start, CPY06_JOIN_START);

  }

  /* groupsig_get_joinseq must return CPY06_JOIN_SEQ */
  TEST_F(CPY06Test, CheckJoinSeq) {

    int rc;
    uint8_t seq;

    rc = groupsig_get_joinseq(GROUPSIG_CPY06_CODE, &seq);
    EXPECT_EQ(rc, IOK);

    EXPECT_EQ(seq, CPY06_JOIN_SEQ);

  }

  /* Successfully adds a group member */
  TEST_F(CPY06Test, AddsNewMember) {

    int rc;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    addMembers(1);

    EXPECT_EQ(memkey[0]->scheme, GROUPSIG_CPY06_CODE);

  }

  /* Successfully initializes a signature */
  TEST_F(CPY06Test, InitializeSignature) {

    groupsig_signature_t *sig;
    int rc;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    EXPECT_EQ(sig->scheme, GROUPSIG_CPY06_CODE);

    groupsig_signature_free(sig);
    sig = nullptr;

  }

  /* Successfully creates a valid signature */
  TEST_F(CPY06Test, SignVerifyValid) {

    groupsig_signature_t *sig;
    message_t *msg;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Add one member */
    addMembers(1);

    /* Initialize a message with a test string */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Verify the signature */
    b = 2;
    rc = groupsig_verify(&b, sig, msg, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 1 */
    EXPECT_EQ(b, 1);

    /* Free stuff */
    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

  }

  /* Creates a valid signature, but verifies with wrong message */
  TEST_F(CPY06Test, SignVerifyWrongMessage) {

    groupsig_signature_t *sig;
    message_t *msg, *msg2;
    int rc;
    uint8_t b;
    
    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Add one member */
    addMembers(1);

    /* Import the message from the external file into the initialized message object */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Use a wrong message for verification */
    msg2 = message_from_string((char *) "Hello, Worlds!");
    EXPECT_NE(msg2, nullptr);

    /* Verify the signature */
    b = 2;
    rc = groupsig_verify(&b, sig, msg2, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 0 */
    EXPECT_EQ(b, 0);

    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg2);
    EXPECT_EQ(rc, IOK);

  }

  /* Opens a signature */
  TEST_F(CPY06Test, OpenSignature) {

    groupsig_signature_t *sig;
    message_t *msg;
    uint64_t index;
    int rc;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Add one member */
    addMembers(1);

    /* Import the message from the external file into the initialized message object */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Open */
    index = UINT64_MAX;
    rc = groupsig_open(&index, nullptr, nullptr, sig, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* index must be 0 */
    EXPECT_EQ(index, 0);

    /* Free stuff */
    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

  }

  TEST_F(CPY06Test, InitializeProof) {

    groupsig_proof_t *proof;
    int rc;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the proof object */
    proof = groupsig_proof_init(grpkey->scheme);
    EXPECT_NE(proof, nullptr);

    EXPECT_EQ(proof->scheme, GROUPSIG_CPY06_CODE);

    groupsig_proof_free(proof);
    proof = nullptr;

  }

  /* Generate a claim (proof) of a signature and verifies it */
  TEST_F(CPY06Test, ClaimValid) {

    groupsig_signature_t *sig;
    groupsig_proof_t *proof;
    message_t *msg;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Initialize the proof object */
    proof = groupsig_proof_init(grpkey->scheme);
    EXPECT_NE(proof, nullptr);

    /* Add one member */
    addMembers(1);

    /* Import the message from the external file into the initialized message object */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Create claim */
    rc = groupsig_claim(proof, memkey[0], grpkey, sig);
    EXPECT_EQ(rc, IOK);

    /* Verify claim */
    b = 2;
    rc = groupsig_claim_verify(&b, proof, sig, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 1);

    /* Free stuff */
    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);

  }

  /* Generate a claim (proof) of a signature and verifies it with wrong parameters */
  TEST_F(CPY06Test, ClaimWrong) {

    groupsig_signature_t *sig, *sig2, *sig3;
    groupsig_proof_t *proof;
    message_t *msg, *msg2;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Initialize the second group signature object */
    sig2 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig2, nullptr);

    /* Initialize the third group signature object */
    sig3 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig3, nullptr);

    /* Initialize the proof object */
    proof = groupsig_proof_init(grpkey->scheme);
    EXPECT_NE(proof, nullptr);

    /* Add one member */
    addMembers(2);

    /* Import the message from the external file into the initialized message object */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Import the message from the external file into the initialized message object */
    msg2 = message_from_string((char *) "Hello, Worlds!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Sign 2 (same user, different message) */
    rc = groupsig_sign(sig2, msg2, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Sign 3 (different user, same message) */
    rc = groupsig_sign(sig3, msg, memkey[1], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Create claim */
    rc = groupsig_claim(proof, memkey[0], grpkey, sig);
    EXPECT_EQ(rc, IOK);

    /* Verify claim with other signature (different message)*/
    b = 2;
    rc = groupsig_claim_verify(&b, proof, sig2, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 0);

    /* Verify claim with other signature (different user) */
    b = 2;
    rc = groupsig_claim_verify(&b, proof, sig3, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 0);

    /* Free stuff */
    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig3);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);

  }

  /* Trace a revealed user */
  TEST_F(CPY06Test, TraceValid) {

    groupsig_signature_t *sig;
    groupsig_proof_t *proof;
    trapdoor_t *trapdoor;
    message_t *msg;
    int rc;
    uint64_t id;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Initialize the proof object */
    proof = groupsig_proof_init(grpkey->scheme);
    EXPECT_NE(proof, nullptr);

    /* Add one member */
    addMembers(1);

    /* Import the message from the external file into the initialized message object */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Create claim */
    rc = groupsig_claim(proof, memkey[0], grpkey, sig);
    EXPECT_EQ(rc, IOK);

    /* Open */
    id = UINT64_MAX;
    rc = groupsig_open(&id, proof, crl, sig, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(id, 0);

    trapdoor = trapdoor_init(grpkey->scheme);
    EXPECT_NE(trapdoor, nullptr);

    rc = groupsig_reveal(trapdoor, crl, gml, id);
    EXPECT_EQ(rc, IOK);

    b = 2;
    rc = groupsig_trace(&b, sig, grpkey, crl, mgrkey, gml);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 1);

    /* Free stuff */
    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

    rc = trapdoor_free(trapdoor);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);

  }

  /* Trace a not revealed user */
  TEST_F(CPY06Test, TraceWrong) {

    groupsig_signature_t *sig;
    message_t *msg;
    int rc;
    uint64_t id;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Add one member */
    addMembers(1);

    /* Import the message from the external file into the initialized message object */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    b = 2;
    rc = groupsig_trace(&b, sig, grpkey, crl, mgrkey, gml);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 0);

    /* Free stuff */
    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

  }

  /* Generate a claim (proof) of two signatures and verify it */
  TEST_F(CPY06Test, ProveEqualityValid) {

    groupsig_signature_t *sig, *sig2, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, *msg2;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Initialize the other group signature object */
    sig2 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig2, nullptr);

    /* Initialize the proof object */
    proof = groupsig_proof_init(grpkey->scheme);
    EXPECT_NE(proof, nullptr);

    /* Get memory for the array of signatures */
    sigs = (groupsig_signature_t **)malloc(2*sizeof(groupsig_signature_t*));
    EXPECT_NE(sigs, nullptr);

    /* Add one member */
    addMembers(1);

    /* Import the message from the external file into the initialized message object */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Import a different message */
    msg2 = message_from_string((char *) "Hello, Worlds!");
    EXPECT_NE(msg2, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Sign the other message */
    rc = groupsig_sign(sig2, msg2, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    sigs[0] = sig;
    sigs[1] = sig2;

    /* Create claim */
    rc = groupsig_prove_equality(proof, memkey[0], grpkey, sigs, 2);
    EXPECT_EQ(rc, IOK);

    /* Verify claim */
    b = 2;
    rc = groupsig_prove_equality_verify(&b, proof, grpkey, sigs, 2);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 1);

    /* Free stuff */
    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);

    free(sigs);

  }

  /* Generate a claim (proof) of two signatures and verify it with wrong parameters */
  TEST_F(CPY06Test, ProveEqualityWrong) {

    groupsig_signature_t *sig, *sig2, *sig3, **sigs;
    groupsig_proof_t *proof;
    message_t *msg, *msg2;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Initialize the other group signature object */
    sig2 = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig2, nullptr);

    // /* Initialize the other group signature object */
    // sig3 = groupsig_signature_init(grpkey->scheme);
    // EXPECT_NE(sig3, nullptr);    

    /* Initialize the proof object */
    proof = groupsig_proof_init(grpkey->scheme);
    EXPECT_NE(proof, nullptr);

    /* Get memory for the array of signatures */
    sigs = (groupsig_signature_t **)malloc(2*sizeof(groupsig_signature_t*));
    EXPECT_NE(sigs, nullptr);

    /* Add one member */
    addMembers(2);

    /* Import the message from the external file into the initialized message object */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Import a different message */
    msg2 = message_from_string((char *) "Hello, Worlds!");
    EXPECT_NE(msg2, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Sign the other message */
    rc = groupsig_sign(sig2, msg2, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    // /* Create another signature, by other user */
    // rc = groupsig_sign(sig3, msg2, memkey[1], grpkey, UINT_MAX);
    // EXPECT_EQ(rc, IOK);
    

    sigs[0] = sig;
    sigs[1] = sig2;

    /* Create claim */
    rc = groupsig_prove_equality(proof, memkey[0], grpkey, sigs, 2);
    EXPECT_EQ(rc, IOK);

    /* Swapping order of signature */
    sigs[0] = sig2;
    sigs[1] = sig;

    /* Verify claim */
    b = 2;
    rc = groupsig_prove_equality_verify(&b, proof, grpkey, sigs, 2);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 0);

    /* Modifying a signature */
    sigs[0] = sig;
    sigs[1] = sig;

    /* Verify claim */
    b = 2;
    rc = groupsig_prove_equality_verify(&b, proof, grpkey, sigs, 2);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 0);

    /* Create claim for signatures issued by another member */
    sigs[0] = sig;
    sigs[1] = sig2;

    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);

    proof = groupsig_proof_init(grpkey->scheme);
    EXPECT_NE(proof, nullptr);

    /* Create claim */    
    rc = groupsig_prove_equality(proof, memkey[1], grpkey, sigs, 2);
    EXPECT_EQ(rc, IOK);

    /* Verify claim */
    b = 2;
    rc = groupsig_prove_equality_verify(&b, proof, grpkey, sigs, 2);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(b, 0);

    /* Free stuff */
    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig2);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_proof_free(proof);
    EXPECT_EQ(rc, IOK);

    free(sigs);

  }

  /** Group key tests **/

  /* Successfully exports and imports a group key to a string */
  TEST_F(CPY06Test, GrpKeyExportImport) {

    groupsig_key_t *dst;
    byte_t *bytes;
    uint32_t size;
    int rc, len;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Get the size of the string to store the exported key */
    len = groupsig_grp_key_get_size(grpkey);
    EXPECT_NE(len, -1);

    /* Export the group key to a string in b64 */
    bytes = nullptr;
    rc = groupsig_grp_key_export(&bytes, &size, grpkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(len, size);
    EXPECT_NE(bytes, nullptr);

    /* Import the group key */
    dst = groupsig_grp_key_import(GROUPSIG_CPY06_CODE, bytes, size);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_grp_key_free(dst);
    EXPECT_EQ(rc, IOK);

    free(bytes); bytes = nullptr;

  }

  /* Successfully copies a group key */
  TEST_F(CPY06Test, GrpKeyCopy) {

    groupsig_key_t *dst;
    int rc;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    dst = groupsig_grp_key_init(GROUPSIG_CPY06_CODE);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_grp_key_copy(dst, grpkey);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_grp_key_free(dst);
    EXPECT_EQ(rc, IOK);

  }

  /** Manager key tests **/

  /* Successfully exports and imports an issuer key to a string */
  TEST_F(CPY06Test, MgrKeyExportImport) {

    groupsig_key_t *dst;
    byte_t *bytes;
    uint32_t size;
    int rc, len;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Get the size of the string to store the exported key */
    len = groupsig_mgr_key_get_size(mgrkey);
    EXPECT_NE(len, -1);

    /* Export the group key to a string in b64 */
    bytes = nullptr;
    rc = groupsig_mgr_key_export(&bytes, &size, mgrkey);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(len, size);
    EXPECT_NE(bytes, nullptr);

    /* Import the group key */
    dst = groupsig_mgr_key_import(GROUPSIG_CPY06_CODE, bytes, size);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mgr_key_free(dst);
    EXPECT_EQ(rc, IOK);

    free(bytes); bytes = nullptr;

  }

  /* Successfully copies an issuer key */
  TEST_F(CPY06Test, MgrKeyCopy) {

    groupsig_key_t *dst;
    int rc;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    dst = groupsig_mgr_key_init(GROUPSIG_CPY06_CODE);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mgr_key_copy(dst, mgrkey);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_mgr_key_free(dst);
    EXPECT_EQ(rc, IOK);

  }

  /** Member key tests **/

  /* Successfully exports and imports a member key to a string */
  TEST_F(CPY06Test, MemKeyExportImport) {

    groupsig_key_t *dst;
    byte_t *bytes;
    uint32_t size;
    int rc, len;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Add one member */
    addMembers(1);

    /* Get the size of the string to store the exported key */
    len = groupsig_mem_key_get_size(memkey[0]);
    EXPECT_NE(len, -1);

    /* Export the group key to a string in b64 */
    bytes = nullptr;
    size = UINT32_MAX;
    rc = groupsig_mem_key_export(&bytes, &size, memkey[0]);
    EXPECT_EQ(rc, IOK);
    EXPECT_EQ(len, size);
    EXPECT_NE(bytes, nullptr);

    /* Import the group key */
    dst = groupsig_mem_key_import(GROUPSIG_CPY06_CODE, bytes, size);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mem_key_free(dst);
    EXPECT_EQ(rc, IOK);

    free(bytes); bytes = nullptr;

  }

  /* Successfully copies a member key */
  TEST_F(CPY06Test, MemKeyCopy) {

    groupsig_key_t *dst;
    int rc;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Add one member */
    addMembers(1);

    dst = groupsig_mem_key_init(GROUPSIG_CPY06_CODE);
    EXPECT_NE(dst, nullptr);

    rc = groupsig_mem_key_copy(dst, memkey[0]);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_mem_key_free(dst);
    EXPECT_EQ(rc, IOK);

  }

  /** Signature object tests **/

  /* Successfully converts a signature as a string */
  TEST_F(CPY06Test, SignatureToString) {

    groupsig_signature_t *sig;
    message_t *msg;
    char *str;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Add one member */
    addMembers(1);

    /* Initialize a message with a test string */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Verify the src signature */
    b = 2;
    rc = groupsig_verify(&b, sig, msg, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 1 */
    EXPECT_EQ(b, 1);

    str = groupsig_signature_to_string(sig);
    EXPECT_NE(str, nullptr);

    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    free(str); str = nullptr;

  }

  /* Successfully copies a signature */
  TEST_F(CPY06Test, SignatureCopy) {

    groupsig_signature_t *src, *dst;
    message_t *msg;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the src group signature object */
    src = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(src, nullptr);

    /* Initialize the dst group signature object */
    dst = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(dst, nullptr);

    /* Add one member */
    addMembers(1);

    /* Initialize a message with a test string */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(src, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Verify the src signature */
    b = 2;
    rc = groupsig_verify(&b, src, msg, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 1 */
    EXPECT_EQ(b, 1);

    rc = groupsig_signature_copy(dst, src);
    EXPECT_EQ(rc, IOK);

    /* Verify the dst signature */
    b = 2;
    rc = groupsig_verify(&b, dst, msg, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 1 */
    EXPECT_EQ(b, 1);

    rc = groupsig_signature_free(dst);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(src);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

  }

  /* Successfully exports and imports a signature */
  TEST_F(CPY06Test, SignatureExportImport) {

    groupsig_signature_t *sig, *imported;
    message_t *msg;
    byte_t *bytes;
    uint32_t size;
    int rc;
    uint8_t b;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Initialize the group signature object */
    sig = groupsig_signature_init(grpkey->scheme);
    EXPECT_NE(sig, nullptr);

    /* Add one member */
    addMembers(1);

    /* Initialize a message with a test string */
    msg = message_from_string((char *) "Hello, World!");
    EXPECT_NE(msg, nullptr);

    /* Sign */
    rc = groupsig_sign(sig, msg, memkey[0], grpkey, UINT_MAX);
    EXPECT_EQ(rc, IOK);

    /* Export */
    bytes = nullptr;
    rc = groupsig_signature_export(&bytes, &size, sig);
    EXPECT_EQ(rc, IOK);
    EXPECT_NE(bytes, nullptr);

    /* Import */
    imported = groupsig_signature_import(sig->scheme, bytes, size);
    EXPECT_NE(imported, nullptr);

    /* Verify the signature */
    b = 2;
    rc = groupsig_verify(&b, imported, msg, grpkey);
    EXPECT_EQ(rc, IOK);

    /* b must be 1 */
    EXPECT_EQ(b, 1);

    rc = groupsig_signature_free(imported);
    EXPECT_EQ(rc, IOK);

    rc = groupsig_signature_free(sig);
    EXPECT_EQ(rc, IOK);

    rc = message_free(msg);
    EXPECT_EQ(rc, IOK);

    free(bytes); bytes = nullptr;

  }



  /** GML tests **/

  /* Successfully exports and imports a GML */
  TEST_F(CPY06Test, GmlExportImport) {

    byte_t *bytes;
    gml_t *imported;
    int rc;
    uint32_t size;

    rc = groupsig_setup(GROUPSIG_CPY06_CODE, grpkey, mgrkey, gml);
    EXPECT_EQ(rc, IOK);

    /* Add one member */
    addMembers(1);

    /* Export */
    bytes = NULL;
    rc = gml_export(&bytes, &size, gml);
    EXPECT_EQ(rc, IOK);

    /* Import */
    imported = gml_import(GROUPSIG_CPY06_CODE, bytes, size);
    EXPECT_NE(imported, nullptr);

    rc = gml_free(imported);
    EXPECT_NE(rc, IERROR);

    free(bytes); bytes = NULL;

  }


}  // namespace groupsig
