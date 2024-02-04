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
  pbcext_element_G1_t *g1;
  pbcext_element_Fr_t *gammat;
  message_t *_mout;
  byte_t *bkey;
  uint32_t size;
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
  gammat = NULL;
  cpy06_data = NULL;
  cpy06_trap = NULL;

  if (!(memkey = cpy06_mem_key_init())) GOTOENDRC(IERROR, cpy06_join_mgr);
  cpy06_memkey = (cpy06_mem_key_t *) memkey->key;  

  /* x \in_R Z^*_p (@todo Should be non-adaptively chosen by member) */
  if (!(cpy06_memkey->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_join_mgr);
  if (pbcext_element_Fr_random(cpy06_memkey->x) == IERROR)
    GOTOENDRC(IERROR, cpy06_join_mgr);

  /* t \in_R Z^*_p */
  if (!(cpy06_memkey->t = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_join_mgr);
  if (pbcext_element_Fr_random(cpy06_memkey->t) == IERROR)
    GOTOENDRC(IERROR, cpy06_join_mgr);

  /* A = (q*g_1^x)^(1/t+\gamma) */
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
  if (pbcext_element_G1_mul(cpy06_memkey->A,
			    g1,
			    cpy06_memkey->x) == IERROR)
    GOTOENDRC(IERROR, cpy06_join_mgr);
  if (pbcext_element_G1_add(cpy06_memkey->A,
			     cpy06_memkey->A,
			     cpy06_grpkey->q) == IERROR)
    GOTOENDRC(IERROR, cpy06_join_mgr);
  if (pbcext_element_G1_mul(cpy06_memkey->A,
			    cpy06_memkey->A,
			    gammat) == IERROR)
    GOTOENDRC(IERROR, cpy06_join_mgr);

  /* Update the gml, if any */
  if(gml) {

    /* Initialize the GML entry */
    if(!(gml_entry = cpy06_gml_entry_init()))
      GOTOENDRC(IERROR, cpy06_join_mgr);

    cpy06_data = gml_entry->data;
    cpy06_trap = (cpy06_trapdoor_t *) cpy06_data->trapdoor->trap;

    /* Open trapdoor */
    if (!(cpy06_trap->open = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_element_G1_set(cpy06_trap->open, cpy06_memkey->A))
      GOTOENDRC(IERROR, cpy06_join_mgr);

    /* Trace trapdoor */
    if (!(cpy06_trap->trace = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mgr);
    if (pbcext_element_G1_mul(cpy06_trap->trace,
			      g1,
			      cpy06_memkey->x))
      GOTOENDRC(IERROR, cpy06_join_mgr);

    /* Currently, CPY06 identities are just uint64_t's */
    *(cpy06_identity_t *) cpy06_data->id->id = gml->n;
    
    if(gml_insert(gml, gml_entry) == IERROR)
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

  if (g1) { pbcext_element_G1_free(g1); g1 = NULL; }
  if (gammat) { pbcext_element_Fr_free(gammat); gammat = NULL; }
  
  return rc;

}

/* join_mgr.c ends here */
