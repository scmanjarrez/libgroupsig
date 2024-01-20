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

#include <stdlib.h>

#include "cpy06.h"
#include "groupsig/cpy06/proof.h"
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/signature.h"
#include "shim/hash.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

int cpy06_prove_equality_verify(uint8_t *ok,
				groupsig_proof_t *proof, 
				groupsig_key_t *grpkey,
				groupsig_signature_t **sigs, 
				uint16_t n_sigs) {

  cpy06_grp_key_t *gkey;
  cpy06_signature_t *sig;
  cpy06_proof_t *cpy06_proof;
  hash_t *hash;
  byte_t *bytes;
  pbcext_element_Fr_t *c;
  pbcext_element_G1_t *g1;
  pbcext_element_GT_t *e, *es, *t5c;
  uint64_t n;
  int rc;
  uint8_t i;
  
  if(!ok || !proof || proof->scheme != GROUPSIG_CPY06_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE ||
     !sigs || !n_sigs) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_prove_equality_verify",
	       __LINE__, LOGERROR);
    return IERROR;
  }

  /* @TODO: The code here can probably simplified/optimized via the crypto/spk.h
     module (as an spk_rep_t proof). Not sure though, so leaving as technical 
     debt. */
  
  e = es = t5c = NULL;
  c = NULL;
  hash = NULL;
  bytes = NULL;
  rc = IOK;
  
  gkey = (cpy06_grp_key_t *) grpkey->key;
  cpy06_proof = (cpy06_proof_t *) proof->proof;
  

  /* Initialize the hashing environment */
  if (!(hash = hash_init(HASH_BLAKE2)))
    GOTOENDRC(IERROR, cpy06_prove_equality_verify);

  /* We have to recover the e(g1,T4)^r objects. To do so, 
     we divide e(g1,T4)^s/T5^c */  
  if (!(e = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_prove_equality_verify);
  if (!(es = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_prove_equality_verify);  
  if (!(t5c = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_prove_equality_verify);  
  
  for (i=0; i<n_sigs; i++) {

    if (sigs[i]->scheme != GROUPSIG_CPY06_CODE) {
      LOG_EINVAL(&logger, __FILE__, "cpy06_prove_equality_verify",
		 __LINE__, LOGERROR);
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);
    }

    sig = (cpy06_signature_t *) sigs[i]->sig;

    if (!(g1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);
    if (pbcext_element_G1_from_string(&g1, BLS12_381_P, 10) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);
    if (pbcext_pairing(e, g1, sig->T4) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);
    if (pbcext_element_GT_pow(es, e, cpy06_proof->s) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);
    if (pbcext_element_GT_pow(t5c, sig->T5, cpy06_proof->c) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);
    if (pbcext_element_GT_div(es, es, t5c) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);    
     
    /* Put the i-th element of the array */
    bytes = NULL;
    if(pbcext_element_GT_to_bytes(&bytes, &n, es) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);

    if(hash_update(hash, bytes, n) == IERROR) 
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);

    mem_free(bytes); bytes = NULL;

    /* Put also the base (the e(g1,T4)'s) into the hash */
    bytes = NULL;
    if(pbcext_element_GT_to_bytes(&bytes, &n, e) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);

    if(hash_update(hash, bytes, n) == IERROR) 
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);
    
    mem_free(bytes); bytes = NULL;

    /* ... and T5 */
    bytes = NULL;
    if(pbcext_element_GT_to_bytes(&bytes, &n, sig->T5) == IERROR)
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);

    if(hash_update(hash, bytes, n) == IERROR) 
      GOTOENDRC(IERROR, cpy06_prove_equality_verify);

    mem_free(bytes); bytes = NULL;
    
  }
  
  /* (2) Calculate c = hash((e(g1,T4)^r)[1] || (e(g1,T4))[1] || ... || 
                            (e(g1,T4)^r)[n] || (e(g1,T4))[n] ) */
  if(hash_finalize(hash) == IERROR)
    GOTOENDRC(IERROR, cpy06_prove_equality_verify);
  
  /* Now, we have to get c as an element */
  if (!(c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_prove_equality_verify);
  if (pbcext_element_Fr_from_hash(c, hash->hash, hash->length) == IERROR)
    GOTOENDRC(IERROR, cpy06_prove_equality_verify);

  /* Compare the obtained c with the c received in the proof, if there is a 
     match, the proof is successful */
  errno = 0;
  if(!pbcext_element_Fr_cmp(c, cpy06_proof->c))
    *ok = 1;
  else
    *ok = 0;

  /* Free resources and exit */
 cpy06_prove_equality_verify_end:

  if (g1) { pbcext_element_G1_free(g1); g1 = NULL; }
  if (e) { pbcext_element_GT_free(e); e = NULL; }
  if (es) { pbcext_element_GT_free(es); es = NULL; }
  if (t5c) { pbcext_element_GT_free(t5c); t5c = NULL; }
  if (c) { pbcext_element_Fr_free(c); c = NULL; }
  if (hash) { hash_free(hash); hash = NULL; }
  if (bytes) { mem_free(bytes); bytes = NULL; }
   
  return rc;
   
}

/* prove_equality_verify.c ends here */
