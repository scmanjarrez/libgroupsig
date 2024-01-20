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
#include <stdint.h>
#include <errno.h>

#include "include/crl.h"
#include "cpy06.h"
#include "groupsig/cpy06/signature.h"
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/mgr_key.h"
#include "groupsig/cpy06/crl.h"
#include "groupsig/cpy06/gml.h"
#include "groupsig/cpy06/trapdoor.h"
#include "groupsig/cpy06/identity.h"

int cpy06_trace(uint8_t *ok,
		groupsig_signature_t *sig,
		groupsig_key_t *grpkey,
		crl_t *crl,
		groupsig_key_t *mgrkey,
		gml_t *gml) {

  cpy06_signature_t *cpy06_sig;
  cpy06_grp_key_t *gkey;
  trapdoor_t *trapi;
  cpy06_trapdoor_t *cpy06_trapi;
  pbcext_element_GT_t *e;
  uint64_t i;
  uint8_t revoked;

  if(!ok || !sig || sig->scheme != GROUPSIG_CPY06_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE ||
     !crl) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_trace", __LINE__, LOGERROR);
    return IERROR;
  }

  gkey = (cpy06_grp_key_t *) grpkey->key;
  cpy06_sig = (cpy06_signature_t *) sig->sig;

  if (!(e = pbcext_element_GT_init())) return IERROR;
      
  i = 0; revoked = 0;
  while(i < crl->n) {

    // @bug Memory leak here... but uncommenting crashes the program
    /* if(!(trapi = cpy06_trapdoor_init())) { */
    /*   element_clear(e); */
    /*   return IERROR; */
    /* } */

    /* Get the next trapdoor to test */
    if (!(trapi = ((cpy06_crl_entry_t *) crl_get(crl, i))->trapdoor)) {
      pbcext_element_GT_free(e); e = NULL;
      return IERROR;
    }

    cpy06_trapi = trapi->trap;
  
    /* Compute e(trapi->C, sig->T4) */
    if (pbcext_pairing(e, cpy06_trapi->trace, cpy06_sig->T4) == IERROR) {
      pbcext_element_GT_free(e); e = NULL;
      return IERROR;
    }
    
    if(!pbcext_element_GT_cmp(e, cpy06_sig->T5)) revoked = 1;    

    /* trapdoor_free(trapi); trapi = NULL; */

    i++;

  }

  *ok = revoked;
  pbcext_element_GT_free(e); e = NULL;

  return IOK;


}

/* trace.c ends here */
