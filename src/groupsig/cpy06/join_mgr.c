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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "cpy06.h"
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/mgr_key.h"
#include "groupsig/cpy06/mem_key.h"
#include "groupsig/cpy06/gml.h"
#include "groupsig/cpy06/identity.h"
#include "groupsig/cpy06/trapdoor.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"
#include "crypto/spk.h"

int cpy06_get_joinseq(uint8_t *seq) {
  *seq = CPY06_JOIN_SEQ;
  return IOK;
}

int cpy06_get_joinstart(uint8_t *start) {
  *start = CPY06_JOIN_START;
  return IOK;
}


/* @TODO This function still follows the old variable structure for join and
   I am just changing the interface to remove compiler complaints. But this
   breaks the functionality! Fix! */
//gml_t *gml, groupsig_key_t *memkey, groupsig_key_t *mgrkey, groupsig_key_t *grpkey) {
int cpy06_join_mgr(message_t **mout,
		   gml_t *gml,
		   groupsig_key_t *mgrkey,
		   int seq,
		   message_t *min,
		   groupsig_key_t *grpkey) {
  
  groupsig_key_t *memkey;
  cpy06_mem_key_t *cpy06_memkey;
  cpy06_mgr_key_t *cpy06_mgrkey;
  cpy06_grp_key_t *cpy06_grpkey;
  gml_entry_t *gml_entry;
  cpy06_gml_entry_data_t *cpy06_data;
  cpy06_trapdoor_t *cpy06_trap;
  spk_rep_t *spk;
  pbcext_element_G1_t *g1, *I, *pi, *Y[2], *G[3];
  pbcext_element_Fr_t *gammat, *u, *v;
  message_t *_mout;
  byte_t *bkey, *bmsg, *bu, *bv, *bI, *bpi;
  uint64_t len, ulen, vlen, Ilen, pilen;
  uint32_t size;
  uint16_t i[4][2], prods[2];
  uint8_t ok;
  int rc;

  if(!mout ||
     !gml || gml->scheme != GROUPSIG_CPY06_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_CPY06_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_join_mgr", __LINE__, LOGERROR);
    return IERROR;
  }

  cpy06_mgrkey = (cpy06_mgr_key_t *) mgrkey->key;
  cpy06_grpkey = (cpy06_grp_key_t *) grpkey->key;
  rc = IOK;
  g1 = I = pi = NULL;
  bkey = bmsg = bu = bv = bI = bpi = NULL;
  gammat = u = v = NULL;
  len = ulen = vlen = Ilen = pilen = 0;
  cpy06_data = NULL;
  cpy06_trap = NULL;
  spk = NULL;
  memkey = NULL;

  /* First step by manager (seq 1/4): Generate challenge (randomness) */
  if (seq == 1) {

    /* Input message must contain I (of the form yP1 + rQ, which will be
       proven later) */
    if (!(I = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_get_element_G1_bytes(I, &len, min->bytes) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);

    /* Generate random u, v from Z^*_p */
    if (!(u = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_element_Fr_random(u) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (!(v = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_element_Fr_random(v) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);    

    /* Send u, v, I to member */
    if (pbcext_dump_element_Fr_bytes(&bu, &ulen, u) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_dump_element_Fr_bytes(&bv, &vlen, v) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_dump_element_G1_bytes(&bI, &Ilen, I) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);    
    len = ulen + vlen + Ilen;
    
    if (!(bmsg = (byte_t *) mem_malloc(sizeof(byte_t)*len)))
      GOTOENDRC(IERROR, cpy06_join_mgr);
    memcpy(bmsg, bu, ulen);
    memcpy(&bmsg[ulen], bv, vlen);
    memcpy(&bmsg[ulen+vlen], bI, Ilen);
    
    if(!*mout) {   
      if(!(_mout = message_from_bytes(bmsg, len))) {
	GOTOENDRC(IERROR, cpy06_join_mgr);
      }
      
      *mout = _mout;

    } else {
	
      _mout = *mout;
      if(message_set_bytes(*mout, bmsg, len) == IERROR)
	GOTOENDRC(IERROR, cpy06_join_mgr);
	
    }    

  }

  /* Second step by manager (seq 3/4): Check NIZK and issue cred */
  else if (seq == 3) {

    /* Input message is <I,pi,spk> */
    if (!(I = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (!(pi = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_get_element_G1_bytes(I, &Ilen, min->bytes) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_get_element_G1_bytes(pi,  &pilen, min->bytes + Ilen) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);    
    if (!(spk = spk_rep_import(min->bytes + Ilen + pilen, &len)))
      GOTOENDRC(IERROR, cpy06_join_mgr);

    if (pbcext_dump_element_G1_bytes(&bpi, &pilen, pi) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (!(g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_element_G1_from_string(&g1, BLS12_381_P, 10) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);   

    /* Verify spk */
    Y[0] = pi;
    Y[1] = pi;

    G[0] = g1;
    G[1] = I;
    G[2] = cpy06_grpkey->q;

    i[0][0] = 0; i[0][1] = 0; // x*g1 (g[0],x[0])
    i[1][0] = 1; i[1][1] = 0; // v*g1 (g[0],x[1])
    i[2][0] = 2; i[2][1] = 1; // u*I (g[1],x[2])
    i[3][0] = 3; i[3][1] = 2; // rr*q (g[2],x[3])

    prods[0] = 1;
    prods[1] = 3;
    
    if (spk_rep_verify(&ok,
		       Y, 2,
		       G, 3,
		       i, 4,
		       prods,
		       spk,
		       bpi, pilen) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);

  
    if (!(memkey = cpy06_mem_key_init())) GOTOENDRC(IERROR, cpy06_join_mgr);
    cpy06_memkey = (cpy06_mem_key_t *) memkey->key;

    /* /\* x \in_R Z^*_p (@todo Should be non-adaptively chosen by member) *\/ */
    /* if (!(cpy06_memkey->x = pbcext_element_Fr_init())) */
    /*   GOTOENDRC(IERROR, cpy06_join_mgr); */
    /* if (pbcext_element_Fr_random(cpy06_memkey->x) == IERROR) */
    /*   GOTOENDRC(IERROR, cpy06_join_mgr); */
    
    /* t \in_R Z^*_p */
    if (!(cpy06_memkey->t = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_element_Fr_random(cpy06_memkey->t) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);
    
    // /* A = (q*g_1^x)^(1/t+\gamma) */
    /* A = (q*pi)^(1/t+\gamma) */
    if (!(g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_element_G1_from_string(&g1, BLS12_381_P, 10) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (!(gammat = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_element_Fr_add(gammat,
			      cpy06_mgrkey->gamma,
			      cpy06_memkey->t) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_element_Fr_inv(gammat, gammat) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (!(cpy06_memkey->A = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mgr);
    /* if (pbcext_element_G1_mul(cpy06_memkey->A, */
    /* 			    g1, */
    /* 			    cpy06_memkey->x) == IERROR) */
    /*   GOTOENDRC(IERROR, cpy06_join_mgr); */
    if (pbcext_element_G1_add(cpy06_memkey->A,
			      pi, //cpy06_memkey->A,
			      cpy06_grpkey->q) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_element_G1_mul(cpy06_memkey->A,
			      cpy06_memkey->A,
			      gammat) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);
    
    /* Set memkey->x to 0 for export to work */
    if (!(cpy06_memkey->x = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_element_Fr_clear(cpy06_memkey->x) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);
    
    /* Write the memkey into mout */
    bkey = NULL;
    if (cpy06_mem_key_export(&bkey, &size, memkey) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mgr);
    
    if(!*mout) {
      if(!(_mout = message_from_bytes(bkey, size)))
	GOTOENDRC(IERROR, cpy06_join_mgr);
      *mout = _mout;
    } else {
      _mout = *mout;
      if(message_set_bytes(_mout, bkey, size) == IERROR)
	GOTOENDRC(IERROR, cpy06_join_mgr);
    }
    
    /* Update the gml, if any */
    if(gml) {
      
      /* Initialize the GML entry */
      if(!(gml_entry = cpy06_gml_entry_init()))
	GOTOENDRC(IERROR, cpy06_join_mgr);
      
      cpy06_data = gml_entry->data;
      if (!(cpy06_data->trapdoor = trapdoor_init(GROUPSIG_CPY06_CODE)))
	GOTOENDRC(IERROR, cpy06_join_mgr);
      cpy06_trap = (cpy06_trapdoor_t *) cpy06_data->trapdoor->trap;
      
      /* Open trapdoor */
      if (!(cpy06_trap->open = pbcext_element_G1_init()))
	GOTOENDRC(IERROR, cpy06_join_mgr);
      if (pbcext_element_G1_set(cpy06_trap->open, cpy06_memkey->A))
	GOTOENDRC(IERROR, cpy06_join_mgr);
      
      /* Trace trapdoor */
      if (!(cpy06_trap->trace = pbcext_element_G1_init()))
	GOTOENDRC(IERROR, cpy06_join_mgr);
      if (pbcext_element_G1_set(cpy06_trap->trace, pi))
	GOTOENDRC(IERROR, cpy06_join_mgr);
      /* if (pbcext_element_G1_mul(cpy06_trap->trace, */
      /* 				g1, */
      /* 				cpy06_memkey->x)) */
      /* 	GOTOENDRC(IERROR, cpy06_join_mgr); */
      
      /* Currently, CPY06 identities are just uint64_t's */
      if (!(cpy06_data->id = identity_init(GROUPSIG_CPY06_CODE)))
	GOTOENDRC(IERROR, cpy06_join_mgr);
      *(cpy06_identity_t *) cpy06_data->id->id = gml->n;
      
      if(gml_insert(gml, gml_entry) == IERROR)
	GOTOENDRC(IERROR, cpy06_join_mgr);
    }
    
  }

  else {
    GOTOENDRC(IERROR, cpy06_join_mgr);
  }

 cpy06_join_mgr_end:

  if (rc == IERROR) {
    if (gml_entry) {
      cpy06_gml_entry_free(gml_entry); gml_entry = NULL;
    }
    if (cpy06_memkey->t) {
      pbcext_element_Fr_free(cpy06_memkey->t); cpy06_memkey->t = NULL;
    }
    if (cpy06_memkey->A) {
      pbcext_element_G1_free(cpy06_memkey->A); cpy06_memkey->A = NULL;
    }
  }

  if (gammat) { pbcext_element_Fr_free(gammat); gammat = NULL; }
  if (u) { pbcext_element_Fr_free(u); u = NULL; }
  if (v) { pbcext_element_Fr_free(v); v = NULL; }
  if (g1) { pbcext_element_G1_free(g1); g1 = NULL; }
  if (I) { pbcext_element_G1_free(I); I = NULL; }
  if (pi) { pbcext_element_G1_free(pi); pi = NULL; }  
  if (memkey) { cpy06_mem_key_free(memkey); memkey = NULL; }
  if (bkey) { mem_free(bkey); bkey = NULL; }
  if (bpi) { mem_free(bpi); bpi = NULL; }
  if (bmsg) { mem_free(bmsg); bmsg = NULL; }
  if (bu) { mem_free(bu); bu = NULL; }
  if (bv) { mem_free(bv); bv = NULL; }
  if (bI) { mem_free(bI); bI = NULL; }

  return rc;

}

/* join_mgr.c ends here */
