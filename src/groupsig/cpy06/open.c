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
#include <stdlib.h>
#include <errno.h>

#include "types.h"
//#include "bigz.h"
#include "cpy06.h"
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/mgr_key.h"
#include "groupsig/cpy06/signature.h"
#include "groupsig/cpy06/gml.h"
#include "groupsig/cpy06/identity.h"
#include "groupsig/cpy06/trapdoor.h"

int cpy06_open(uint64_t *id,
	       groupsig_proof_t *proof,
	       crl_t *crl,
	       groupsig_signature_t *sig, 
	       groupsig_key_t *grpkey,
	       groupsig_key_t *mgrkey,
	       gml_t *gml) {

  pbcext_element_G1_t *A, *e[2];
  pbcext_element_Fr_t *s[2];
  cpy06_signature_t *cpy06_sig;
  cpy06_grp_key_t *cpy06_grpkey;
  cpy06_mgr_key_t *cpy06_mgrkey;
  gml_entry_t *gml_entry;
  cpy06_gml_entry_data_t *cpy06_data;
  cpy06_trapdoor_t *cpy06_trap;
  uint64_t i;
  int rc;
  uint8_t match;

  if(!id || 
     !sig || sig->scheme != GROUPSIG_CPY06_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE ||
     !mgrkey || mgrkey->scheme != GROUPSIG_CPY06_CODE ||
     !gml || gml->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_open", __LINE__, LOGERROR);
    return IERROR;
  }

  A = NULL;
  cpy06_sig = sig->sig;
  cpy06_grpkey = grpkey->key;
  cpy06_mgrkey = mgrkey->key;
  match = 0;
  rc = IOK;
  

  /* In the paper, a signature verification process is included within the open
     procedure to check that the signature is valid. Here, for modularity,
     we sepatarate the two processes (note that verify MUST always be called 
     before opening...) */
  
  /* Recover the signer's A as: A = T3/(T1^xi1 * T2^xi2) */
  if (!(A = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_open);

  /* A = T1^xi1 + T2^xi2 =  */
  e[0] = cpy06_sig->T1; e[1] = cpy06_sig->T2;
  s[0] = cpy06_mgrkey->xi1; s[1] = cpy06_mgrkey->xi2;  
  if (pbcext_element_G1_muln(A, e, s, 2) == IERROR)
    GOTOENDRC(IERROR, cpy06_open);

  /* A = T3/A */
  if (pbcext_element_G1_sub(A, cpy06_sig->T3, A) == IERROR)
    GOTOENDRC(IERROR, cpy06_open);

  /* Look up the recovered A in the GML */
  match = 0;
  for (i=0; i<gml->n; i++) {  

    if (!(gml_entry = gml_get(gml, i))) GOTOENDRC(IERROR, cpy06_open);

    cpy06_data = gml_entry->data;
    cpy06_trap = cpy06_data->trapdoor->trap;
    if (!pbcext_element_G1_cmp(cpy06_trap->open, A)) {
      
      /* Get the identity from the matched entry. */
      *id = *(uint64_t *) cpy06_data->id->id;

      match = 1;
      break;

    }

  }

 cpy06_open_end:

  if (A) { pbcext_element_G1_free(A); A = NULL; }

  /* No match: FAIL */
  if (!match) {
    return IFAIL;
  }

  /* /\* If we have received a CRL, update it with the "revoked" member *\/ */
  /* if(crl) { */

  /*   if(!(crl_entry = cpy06_crl_entry_init())) { */
  /*     return IERROR; */
  /*   } */
    
  /*   if(cpy06_identity_copy(crl_entry->id, gml_entry->id) == IERROR) { */
  /*     cpy06_crl_entry_free(crl_entry); */
  /*     return IERROR; */
  /*   } */
    
  /*   crl_entry->trapdoor = trap; */

  /*   if(cpy06_crl_insert(crl, crl_entry) == IERROR) { */
  /*     cpy06_crl_entry_free(crl_entry); */
  /*     return IERROR; */
  /*   } */

  /* } */

  return rc;

}

/* open.c ends here */
