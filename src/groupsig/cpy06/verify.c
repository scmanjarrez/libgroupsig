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
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/signature.h"
#include "bigz.h"
#include "shim/pbc_ext.h"
#include "shim/hash.h"
#include "sys/mem.h"

/* Private functions */

/* Public functions */
int cpy06_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg, groupsig_key_t *grpkey) {

  pbcext_element_G1_t *B1, *B2, *B3, *B4, *aux_G1, *e[3];
  pbcext_element_GT_t *B5, *B6, *aux_GT, *aux_e;
  pbcext_element_Fr_t *aux_sd1sd2, *aux_sr1sr2, *aux_sx, *c, *s[3];
  cpy06_signature_t *cpy06_sig;
  cpy06_grp_key_t *cpy06_grpkey;
  cpy06_sysenv_t *cpy06_sysenv;
  hash_t *aux_c;
  byte_t *aux_bytes;
  int aux_n, rc;

  if(!ok || !msg || !sig || sig->scheme != GROUPSIG_CPY06_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_verify", __LINE__, LOGERROR);
    return IERROR;
  }
  
  cpy06_sig = sig->sig;
  cpy06_grpkey = grpkey->key;
  cpy06_sysenv = sysenv->data;
  rc = IOK;

  B1 = B2 = B3 = B4 = aux_G1 = NULL;
  B5 = B6 = aux_GT = aux_e = NULL;
  aux_sd1sd2 = aux_sr1sr2 = aux_sx = c = NULL;
  aux_c = NULL;
  aux_bytes = NULL;

  /* Re-derive B1, B2, B3, B4, B5 and B6 from the signature */
  
  /* B1 = X^sr1/T1^c */
  if (!(aux_G1 = pbcext_element_G1_init))
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_G1_mul(aux_G1, cpy06_sig->T1, cpy06_sig->c) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (!(B1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_G1_mul(B1, cpy06_grpkey->x, cpy06_sig->sr1) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_G1_sub(B1, B1, aux_G1) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* B2 = X^sr2/T2^c */
  if (pbcext_element_mul(aux_G1, cpy06_sig->T2, cpy06_sig->c) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (!(B2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_G1_mul(B2, cpy06_grpkey->y, cpy06_sig->sr2) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_G1_sub(B2, B2, aux_G1) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* B3 = T1^st/X^sd1 */
  if (pbcext_element_G1_mul(aux_G1, cpy06_grpkey->x, cpy06_sig->sd1) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (!(B3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_G1_mul(B3, cpy06_sig->T1, cpy06_sig->st) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_G1_div(B3, B3, aux_G1) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* B4 = T2^st/Y^sd2 */
  if (pbcext_element_mul(aux_G1, cpy06_grpkey->y, cpy06_sig->sd2) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (!(B4 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_G1_mul(B4, cpy06_sig->T2, cpy06_sig->st) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_G1_sub(B4, B4, aux_G1) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* B5 = e(g1,T4)^sx * T5^(-c) */
  if (!(aux_GT = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_pow(aux_GT, cpy06_sig->T5, cpy06_sig->c) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_GT_inv(aux_GT, aux_GT) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (!(B5 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_pairing(B5, cpy06_grpkey->g1, cpy06_sig->T4) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_GT_pow(B5, B5, cpy06_sig->sx) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_GT_mul(B5, B5, aux_GT) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* B6 = e(T3,g2)^st * e(z,g2)^(-sd1-sd2) * e(z,r)^(-sr1-sr2) * e(g1,g2)^(-sx) * ( e(T3,r)/e(q,g2) )^c */

  /* aux_e = e(z,g2)^(-sd1-sd2) * e(z,r)^(-sr1-sr2) * e(g1,g2)^(-sx) */
  if (!(aux_sd1sd2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_Fr_neg(aux_sd1sd2, cpy06_sig->sd1) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_Fr_sub(aux_sd1sd2, aux_sd1sd2, cpy06_sig->sd2) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  if (!(aux_sr1sr2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_Fr_neg(aux_sr1sr2, cpy06_sig->sr1) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_Fr_sub(aux_sr1sr2, aux_sr1sr2, cpy06_sig->sr2) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  if (!(aux_sx = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_Fr_neg(aux_sx, cpy06_sig->sx) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  
  if (!(aux_e = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_verify);

  e[0] = cpy06_grpkey->e2; e[1] = cpy06_grpkey->e3; e[2] = cpy06_grpkey->e4;
  s[0] = aux_sd1sd2; s[1] = aux_sr1sr2; s[2] = aux_sx;
  if (pbcext_element_pow3_zn(aux_e, e, s, 3) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* aux_GT = (e(T3,r)/e(q,g2))^c */
  if (pbcext_pairing(aux_GT, cpy06_sig->T3, cpy06_grpkey->r) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbext_element_GT_div(aux_GT, aux_GT, cpy06_grpkey->e5) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_GT_pow(aux_GT, aux_GT, cpy06_sig->c) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* B6 = e(T3,g2)^st * aux_e * aux_GT */
  if (!(B6 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_pairing(B6, cpy06_sig->T3, cpy06_grpkey->g2) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_GT_pow(B6, B6, cpy06_sig->st) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_GT_mul(B6, B6, aux_e) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_GT_mul(B6, B6, aux_GT) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify),

  /* Recompute the hash-challenge c */

  /* c = hash(M,T1,T2,T3,T4,T5,B1,B2,B3,B4,B5,B6) \in Zp */
  if(!(aux_c = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, cpy06_verify);

  /* Push the message */
  if(hash_update(aux_c, msg->bytes, msg->length) == IERROR) 
    GOTOENDRC(IERROR, cpy06_verify);

  /* Push T1 */
  aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, cpy06_sig->T1) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* Push T2 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, cpy06_sig->T2) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* Push T3 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, cpy06_sig->T3) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* Push T4 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G2_to_bytes(&aux_bytes, &aux_n, cpy06_sig->T4) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* Push T5 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_GT_to_bytes(&aux_bytes, &aux_n, cpy06_sig->T5) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* Push B1 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, B1) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* Push B2 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, B2) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* Push B3 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, B3) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* Push B4 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_G1_to_bytes(&aux_bytes, &aux_n, B4) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* Push B5 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_GT_to_bytes(&aux_bytes, &aux_n, B5) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* Push B6 */
  mem_free(aux_bytes); aux_bytes = NULL;
  if(pbcext_element_GT_to_bytes(&aux_bytes, &aux_n, B6) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);
  
  if(hash_update(aux_c, aux_bytes, aux_n) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* Finish the hash */
  if(hash_finalize(aux_c) == IERROR) GOTOENDRC(IERROR, cpy06_verify);

  /* Get c as the element associated to the obtained hash value */
  if (!(c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_verify);
  if (pbcext_element_Fr_from_hash(c, aux_c->hash, aux_c->length) == IERROR)
    GOTOENDRC(IERROR, cpy06_verify);

  /* Compare the result with the received challenge */
  if(element_cmp(cpy06_sig->c, c)) { /* Different: sig fail */
    *ok = 0;
  } else { /* Same: sig OK */
    *ok = 1;
  }

 cpy06_verify_end:

  if (B1) { pbcext_element_G1_clear(B1); B1 = NULL; }
  if (B2) { pbcext_element_G1_clear(B2); B2 = NULL; }
  if (B3) { pbcext_element_G1_clear(B3); B3 = NULL; }
  if (B4) { pbcext_element_G1_clear(B4); B4 = NULL; }
  if (B5) { pbcext_element_GT_clear(B5); B5 = NULL; }
  if (B6) { pbcext_element_GT_clear(B6); B6 = NULL; }
  if (aux_G1) { pbcext_element_G1_clear(aux_G1); aux_G1 = NULL; }
  if (aux_GT) { pbcext_element_GT_clear(aux_GT); aux_GT = NULL; }
  if (aux_e) { pbcext_element_GT_clear(aux_e); aux_e = NULL; }
  if (aux_sd1sd2) { pbcext_element_Fr_clear(aux_sd1sd2); aux_sd1sd2 = NULL; }
  if (aux_sr1sr2) { pbcext_element_Fr_clear(aux_sr1sr2); aux_sr1sr2 = NULL; }
  if (aux_sx) { pbcext_element_Fr_clear(aux_sx); aux_sx = NULL; }
  if (c) { pbcext_element_Fr_clear(c); c = NULL; }  
  if(aux_bytes) { mem_free(aux_bytes); aux_bytes = NULL; }
  if(aux_c) { hash_free(aux_c); aux_c = NULL; }

  return rc;

}

/* verify.c ends here */
