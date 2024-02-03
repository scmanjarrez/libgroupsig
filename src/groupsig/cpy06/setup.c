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
#include <math.h>

#include "cpy06.h"
#include "groupsig/cpy06/grp_key.h"
#include "groupsig/cpy06/mgr_key.h"
#include "groupsig/cpy06/gml.h"
#include "sys/mem.h"
#include "shim/pbc_ext.h"

int cpy06_init() {

  if(pbcext_init(BLS12_381) == IERROR) {
    return IERROR;
  }  
  
  return IOK;

}

int cpy06_clear() {
  return IOK;
}

int cpy06_config_free() {
  return IOK;
}

int cpy06_setup(groupsig_key_t *grpkey, groupsig_key_t *mgrkey, gml_t *gml) {

  cpy06_grp_key_t *gkey;
  cpy06_mgr_key_t *mkey;
  pbcext_element_Fr_t *inv;
  pbcext_element_G1_t *g1;  
  pbcext_element_G2_t *g2;
  unsigned int d;
  int rc;

  if(!grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE ||
     !mgrkey || grpkey->scheme != GROUPSIG_CPY06_CODE ||
     !gml) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_setup", __LINE__, LOGERROR);
    return IERROR;
  }

  gkey = grpkey->key;
  mkey = mgrkey->key;
  rc = IOK;
  inv = NULL;

  /* Create group manager private key */

  /* \xi_1 \in_R Z^*_p */
  if (!(mkey->xi1 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_element_Fr_random(mkey->xi1) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);
  
  /* \xi_2 \in_R Z^*_p */
  if (!(mkey->xi2 = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_element_Fr_random(mkey->xi2) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);

  /* \gamma \in_R Z^*_p */
  if (!(mkey->gamma = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_element_Fr_random(mkey->gamma) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);
  
  /* Create group public key */

  /* Q \in_R G1 */
  if (!(gkey->q = pbcext_element_G1_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_element_G1_random(gkey->q) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);

  /* R = g2^\gamma */
  if (!(g2 = pbcext_element_G2_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_element_G2_from_string(&g2, BLS12_381_Q, 10) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);
  if (!(gkey->r = pbcext_element_G2_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_element_G2_mul(gkey->r, g2, mkey->gamma) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);
  
  /* W \in_R G2 \setminus 1 */
  if (!(gkey->w = pbcext_element_G2_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_element_G2_random(gkey->w) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);

  /* Z \in_R G1 \setminus 1 */
  if (!(gkey->z = pbcext_element_G1_init())) GOTOENDRC(IERROR, cpy06_setup);
  do {
    if (pbcext_element_G1_random(gkey->z) == IERROR)
      GOTOENDRC(IERROR, cpy06_setup);
  } while(pbcext_element_G1_is0(gkey->z));

  /* X = Z^(\xi_1^-1) */
  if (!(inv = pbcext_element_Fr_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_element_Fr_inv(inv, mkey->xi1) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);
  if (!(gkey->x = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_element_G1_mul(gkey->x, gkey->z, inv) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);

  /* Y = Z^(\xi_2^-1) */
  if (pbcext_element_Fr_inv(inv, mkey->xi2) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);
  if (!(gkey->y = pbcext_element_G1_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_element_G1_mul(gkey->y, gkey->z, inv) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);

  /* For computation optimizations */

  /* T5 = e(g1, W) */
  if (!(g1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_element_G1_from_string(&g1, BLS12_381_P, 10) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);
  if (!(gkey->T5 = pbcext_element_GT_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_pairing(gkey->T5, g1, gkey->w) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);

  /* e2 = e(z,g2) */
  if (!(gkey->e2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_pairing(gkey->e2, gkey->z, g2) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);    

  /* e3 = e(z,r) */
  if (!(gkey->e3 = pbcext_element_GT_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_pairing(gkey->e3, gkey->z, gkey->r) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);    

  /* e4 = e(g1,g2) */
  if (!(gkey->e4 = pbcext_element_GT_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_pairing(gkey->e4, g1, g2) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);

  /* e5 = e(q,g2) */
  if (!(gkey->e5 = pbcext_element_GT_init())) GOTOENDRC(IERROR, cpy06_setup);
  if (pbcext_pairing(gkey->e5, gkey->q, g2) == IERROR)
    GOTOENDRC(IERROR, cpy06_setup);    

 cpy06_setup_end:

  if (rc == IERROR) {
    if (mkey->xi1) { pbcext_element_Fr_free(mkey->xi1); mkey->xi1 = NULL; }    
    if (mkey->xi2) { pbcext_element_Fr_free(mkey->xi2); mkey->xi2 = NULL; }
    if (mkey->gamma) { pbcext_element_Fr_free(mkey->gamma); mkey->gamma = NULL; }
    if (gkey->q) { pbcext_element_G1_free(gkey->q); gkey->q = NULL; }
    if (gkey->r) { pbcext_element_G2_free(gkey->r); gkey->r = NULL; }    
    if (gkey->w) { pbcext_element_G2_free(gkey->w); gkey->w = NULL; }
    if (gkey->z) { pbcext_element_G1_free(gkey->z); gkey->z = NULL; }
    if (gkey->x) { pbcext_element_G1_free(gkey->x); gkey->x = NULL; }
    if (gkey->y) { pbcext_element_G1_free(gkey->y); gkey->y = NULL; }
    if (gkey->T5) { pbcext_element_GT_free(gkey->T5); gkey->T5 = NULL; }
    if (gkey->e2) { pbcext_element_GT_free(gkey->e2); gkey->e2 = NULL; }
    if (gkey->e3) { pbcext_element_GT_free(gkey->e3); gkey->e3 = NULL; }
    if (gkey->e4) { pbcext_element_GT_free(gkey->e4); gkey->e4 = NULL; }
    if (gkey->e5) { pbcext_element_GT_free(gkey->e5); gkey->e5 = NULL; }
  }

  /* Clear data */
  pbcext_element_Fr_free(inv); inv = NULL;
  pbcext_element_G1_free(g1); g1 = NULL;  
  pbcext_element_G2_free(g2); g2 = NULL;  
  
  return rc;

}

/* setup.c ends here */
