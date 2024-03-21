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
#include <limits.h>

#include "cpy06.h"
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/mem_key.h"
#include "groupsig/cpy06/signature.h"
//#include "bigz.h"
#include "shim/hash.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

/* Private functions */

int cpy06_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey, 
	       groupsig_key_t *grpkey, unsigned int seed) {

  /* Here we won't follow the typical C programming conventions for naming variables.
     Instead, we will name the variables as in the CPY06 paper (with the exception 
     of doubling a letter when a ' is used, e.g. k' ==> kk). Auxiliar variables 
     that are not specified in the paper but helpful or required for its 
     implementation will be named aux_<name>. */

  pbcext_element_G1_t *g1, *B1, *B2, *B3, *B4;
  pbcext_element_G2_t *g2;
  pbcext_element_GT_t *B5, *B6, *aux_e, *e[3];
  pbcext_element_Fr_t *r1, *r2, *r3, *d1, *d2, *s[3];
  pbcext_element_Fr_t *aux_r1r2, *aux_r3x, *aux_bd1bd2, *aux_br1br2, *aux_bx;
  pbcext_element_Fr_t *br1, *br2, *bd1, *bd2, *bt, *bx, *aux_cmul;
  pbcext_element_G1_t *aux_xbd1, *aux_ybd2;
  hash_t *aux_c;
  byte_t *aux_bytes;
  cpy06_signature_t *cpy06_sig;
  cpy06_grp_key_t *cpy06_grpkey;
  cpy06_mem_key_t *cpy06_memkey;
  uint64_t aux_n;
  int rc;
  
  if(!sig || !msg || 
     !memkey || memkey->scheme != GROUPSIG_CPY06_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;

  cpy06_sig = sig->sig;
  cpy06_grpkey = grpkey->key;
  cpy06_memkey = memkey->key;

  g1 = B1 = B2 = B3 = B4 = NULL;
  g2 = NULL;
  B5 = B6 = aux_e = NULL;
  r1 = r2 = r3 = d1 = d2 = NULL;
  aux_r1r2 = aux_r3x = aux_bd1bd2 = aux_br1br2 = aux_bx = NULL;
  br1 = br2 = bd1 = bd2 = bt = bx = aux_cmul = NULL;
  aux_xbd1 = aux_ybd2 = NULL;
  aux_c = NULL;
  aux_bytes = NULL; 

  /* r1,r2,r3 \in_R Z_p */
  if (!(r1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_random(r1) == IERROR) GOTOENDRC(IERROR, cpy06_sign);
  if (!(r2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_random(r2) == IERROR) GOTOENDRC(IERROR, cpy06_sign);
  if (!(r3 = pbcext_element_Fr_init()) == IERROR) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_random(r3) == IERROR) GOTOENDRC(IERROR, cpy06_sign);

  /* d1 = t*r1 */
  if (!(d1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_mul(d1, cpy06_memkey->t, r1) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* d2 = t*r2 */
  if (!(d2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_mul(d2, cpy06_memkey->t, r2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* T1 = X^r1 */
  if (!(cpy06_sig->T1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G1_mul(cpy06_sig->T1, cpy06_grpkey->x, r1) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* T2 = Y^r2 */
  if (!(cpy06_sig->T2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G1_mul(cpy06_sig->T2, cpy06_grpkey->y, r2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* T3 = A*Z^(r1+r2) */
  if (!(aux_r1r2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_add(aux_r1r2, r1, r2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (!(cpy06_sig->T3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G1_mul(cpy06_sig->T3, cpy06_grpkey->z, aux_r1r2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G1_add(cpy06_sig->T3,
			    cpy06_sig->T3,
			    cpy06_memkey->A) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* T4 = W^r3 */
  if (!(cpy06_sig->T4 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G2_mul(cpy06_sig->T4, cpy06_grpkey->w, r3) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* T5 = e(g1, T4)^x = e(g1, W)^(r3*x) */
  if (!(aux_r3x = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_mul(aux_r3x, r3, cpy06_memkey->x) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (!(cpy06_sig->T5 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_GT_pow(cpy06_sig->T5, cpy06_grpkey->T5, aux_r3x) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* br1, br2,bd1,bd2,bt,bx \in_R Z_p */
  if (!(br1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_random(br1) == IERROR) GOTOENDRC(IERROR, cpy06_sign);
  if (!(br2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_random(br2) == IERROR) GOTOENDRC(IERROR, cpy06_sign);
  if (!(bd1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_random(bd1)) GOTOENDRC(IERROR, cpy06_sign);
  if (!(bd2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_random(bd2) == IERROR) GOTOENDRC(IERROR, cpy06_sign);
  if (!(bt = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_random(bt) == IERROR) GOTOENDRC(IERROR, cpy06_sign);
  if (!(bx = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_random(bx) == IERROR) GOTOENDRC(IERROR, cpy06_sign);

  /* B1 = X^br1 */
  if (!(B1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G1_mul(B1, cpy06_grpkey->x, br1) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* B2 = Y^br2 */
  if (!(B2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G1_mul(B2, cpy06_grpkey->y, br2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  /* B3 = T1^bt/X^bd1 */
  if (!(B3 = pbcext_element_G1_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G1_mul(B3, cpy06_sig->T1, bt) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (!(aux_xbd1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G1_mul(aux_xbd1, cpy06_grpkey->x, bd1) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G1_sub(B3, B3, aux_xbd1) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* B4 = T2^bt/Y^bd2 */
  if (!(B4 = pbcext_element_G1_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G1_mul(B4, cpy06_sig->T2, bt) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (!(aux_ybd2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G1_mul(aux_ybd2, cpy06_grpkey->y, bd2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G1_sub(B4, B4, aux_ybd2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* B5 = e(g1,T4)^bx */
  if (!(g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G1_from_string(&g1, BLS12_381_P, 10) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (!(B5 = pbcext_element_GT_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_pairing(B5, g1, cpy06_sig->T4) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_GT_pow(B5, B5, bx) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* B6 = e(T3,g2)^bt * e(z,g2)^(-bd1-bd2) * e(z,r)^(-br1-br2) * e(g1,g2)^(-bx) */
  
  /* [temp] B6 = e(T3,g2)^bt */
  if (!(g2 = pbcext_element_G2_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_G2_from_string(&g2, BLS12_381_Q, 10) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (!(B6 = pbcext_element_GT_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_pairing(B6, cpy06_sig->T3, g2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_GT_pow(B6, B6, bt) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* aux_e: the rest (with the help of the optimizations is easier...) */
  
  /* (-bd1-bd2) */
  if (!(aux_bd1bd2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_neg(aux_bd1bd2, bd1) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_sub(aux_bd1bd2, aux_bd1bd2, bd2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  /* (-br1-br2) */  
  if (!(aux_br1br2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_neg(aux_br1br2, br1) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_sub(aux_br1br2, aux_br1br2, br2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* -bx */
  if (!(aux_bx = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_neg(aux_bx, bx) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  if (!(aux_e = pbcext_element_GT_init())) GOTOENDRC(IERROR, cpy06_sign);

  /* e = e2^bd1bd2*e3^br1br2*e4^bx */
  e[0] = cpy06_grpkey->e2; e[1] = cpy06_grpkey->e3; e[2] = cpy06_grpkey->e4;
  s[0] = aux_bd1bd2; s[1] = aux_br1br2; s[2] = aux_bx;
  if (pbcext_element_GT_pown(aux_e, e, s, 3) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  if(pbcext_element_GT_mul(B6, B6, aux_e) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  

  /* c = hash(M,T1,T2,T3,T4,T5,B1,B2,B3,B4,B5,B6) \in Zp */
  if(!(aux_c = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, cpy06_sign);

  /* Push the message */
  if(hash_update(aux_c, msg->bytes, msg->length) == IERROR) 
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push T1 */
  aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, cpy06_sig->T1) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push T2 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, cpy06_sig->T2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push T3 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, cpy06_sig->T3) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push T4 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G2_to_bytes(&aux_bytes, &aux_n, cpy06_sig->T4) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push T5 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_GT_to_bytes(&aux_bytes, &aux_n, cpy06_sig->T5) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push B1 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, B1) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
 
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push B2 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, B2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push B3 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, B3) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push B4 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, B4) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push B5 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_GT_to_bytes(&aux_bytes, &aux_n, B5) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Push B6 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_GT_to_bytes(&aux_bytes, &aux_n, B6) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Finish the hash */
  if(hash_finalize(aux_c) == IERROR) GOTOENDRC(IERROR, cpy06_sign);

  /* Get c as the element associated to the obtained hash value */
  if (!(cpy06_sig->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_from_hash(cpy06_sig->c,
				  aux_c->hash,
				  aux_c->length) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* Compute sr1, sr2, sd1, sd2, sx and st with the obtained c */
  if (!(aux_cmul = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_sign);

  /* sr1 = br1 + c*r1 */
  if (!(cpy06_sig->sr1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_mul(aux_cmul, cpy06_sig->c, r1) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_add(cpy06_sig->sr1, br1, aux_cmul) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* sr2 = br2 + c*r2 */
  if (!(cpy06_sig->sr2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_mul(aux_cmul, cpy06_sig->c, r2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_add(cpy06_sig->sr2, br2, aux_cmul) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* sd1 = bd1 + c*d1 */
  if (!(cpy06_sig->sd1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_mul(aux_cmul, cpy06_sig->c, d1) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_add(cpy06_sig->sd1, bd1, aux_cmul) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* sd2 = bd2 + c*d2 */
  if (!(cpy06_sig->sd2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_mul(aux_cmul, cpy06_sig->c, d2) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_add(cpy06_sig->sd2, bd2, aux_cmul) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* sx = bx + c*x */
  if (!(cpy06_sig->sx = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_mul(aux_cmul, cpy06_sig->c, cpy06_memkey->x) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_add(cpy06_sig->sx, bx, aux_cmul) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

  /* st = bt + c*t */
  if (!(cpy06_sig->st = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_mul(aux_cmul, cpy06_sig->c, cpy06_memkey->t) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);
  if (pbcext_element_Fr_add(cpy06_sig->st, bt, aux_cmul) == IERROR)
    GOTOENDRC(IERROR, cpy06_sign);

 cpy06_sign_end:

  if (rc == IERROR) {
    if (cpy06_sig->T1) {
      pbcext_element_G1_free(cpy06_sig->T1); cpy06_sig->T1 = NULL;
    }
    if (cpy06_sig->T2) {
      pbcext_element_G1_free(cpy06_sig->T2); cpy06_sig->T2 = NULL;
    }
    if (cpy06_sig->T3) {
      pbcext_element_G1_free(cpy06_sig->T3); cpy06_sig->T3 = NULL;
    }
    if (cpy06_sig->T4) {
      pbcext_element_G2_free(cpy06_sig->T4); cpy06_sig->T4 = NULL;
    }
    if (cpy06_sig->T5) {
      pbcext_element_GT_free(cpy06_sig->T5); cpy06_sig->T5 = NULL;
    }
    if (cpy06_sig->c) {
      pbcext_element_Fr_free(cpy06_sig->c); cpy06_sig->c = NULL;
    }
    if (cpy06_sig->sr1) {
      pbcext_element_Fr_free(cpy06_sig->sr1); cpy06_sig->sr1 = NULL;
    }
    if (cpy06_sig->sr2) {
      pbcext_element_Fr_free(cpy06_sig->sr2); cpy06_sig->sr2 = NULL;
    }
    if (cpy06_sig->sd1) {
      pbcext_element_Fr_free(cpy06_sig->sd1); cpy06_sig->sd1 = NULL;
    }
    if (cpy06_sig->sd2) {
      pbcext_element_Fr_free(cpy06_sig->sd2); cpy06_sig->sd2 = NULL;
    }
    if (cpy06_sig->sx) {
      pbcext_element_Fr_free(cpy06_sig->sx); cpy06_sig->sx = NULL;
    }
    if (cpy06_sig->st) {
      pbcext_element_Fr_free(cpy06_sig->st); cpy06_sig->st = NULL;
    }
  }

  if (g1) { pbcext_element_G1_free(g1); g1 = NULL; }
  if (g2) { pbcext_element_G2_free(g2); g2 = NULL; }
  if (B1) { pbcext_element_G1_free(B1); B1 = NULL; }
  if (B2) { pbcext_element_G1_free(B2); B2 = NULL; }
  if (B3) { pbcext_element_G1_free(B3); B3 = NULL; }
  if (B4) { pbcext_element_G1_free(B4); B4 = NULL; }
  if (B5) { pbcext_element_GT_free(B5); B5 = NULL; }
  if (B6) { pbcext_element_GT_free(B6); B6 = NULL; }
  if (r1) { pbcext_element_Fr_free(r1); r1 = NULL; }
  if (r2) { pbcext_element_Fr_free(r2); r2 = NULL; }
  if (r3) { pbcext_element_Fr_free(r3); r3 = NULL; }
  if (aux_r1r2) { pbcext_element_Fr_free(aux_r1r2); aux_r1r2 = NULL; }  
  if (aux_r3x) { pbcext_element_Fr_free(aux_r3x); aux_r3x = NULL; }
  if (aux_e) { pbcext_element_GT_free(aux_e); aux_e = NULL; }
  if (d1) { pbcext_element_Fr_free(d1); d1 = NULL; }
  if (d2) { pbcext_element_Fr_free(d2); d2 = NULL; }  
  if (br1) { pbcext_element_Fr_free(br1); br1 = NULL; }
  if (br2) { pbcext_element_Fr_free(br2); br2 = NULL; }
  if (bd1) { pbcext_element_Fr_free(bd1); bd1 = NULL; }
  if (bd2) { pbcext_element_Fr_free(bd2); bd2 = NULL; }
  if (bx) { pbcext_element_Fr_free(bx); bx = NULL; }
  if (bt) { pbcext_element_Fr_free(bt); bt = NULL; }
  if (aux_xbd1) { pbcext_element_G1_free(aux_xbd1); aux_xbd1 = NULL; }
  if (aux_ybd2) { pbcext_element_G1_free(aux_ybd2); aux_ybd2 = NULL; }
  if (aux_bd1bd2) { pbcext_element_Fr_free(aux_bd1bd2); aux_bd1bd2 = NULL; }
  if (aux_br1br2) { pbcext_element_Fr_free(aux_br1br2); aux_br1br2 = NULL; }
  if (aux_bx) { pbcext_element_Fr_free(aux_bx); aux_bx = NULL; }
  if (aux_cmul) { pbcext_element_Fr_free(aux_cmul); aux_cmul = NULL; }
  if (aux_bytes) { mem_free(aux_bytes); aux_bytes = NULL; }
  if (aux_c) { hash_free(aux_c); aux_c = NULL; }

  return rc;
  
}

/* sign.c ends here */
