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

#include "kty04.h"
#include "groupsig/kty04/sphere.h"
#include "groupsig/kty04/grp_key.h"
#include "groupsig/kty04/mem_key.h"
#include "bigz.h"
#include "sys/mem.h"

/**
 * @todo The Join procedure includes a protocol for non-adaptive drawing of
 * random powers such that the group member gets x, and the group manager gets
 * b^x (mod n). For now, and for testing purposes, we just let the user choose
 * a random x and send it to the manager, but we must implement it as soon as
 * everything is working correctly.
 */

/* static int _join_mem_draw_random_pow(kty04_grp_key_t *grpkey, kty04_mem_key_t *memkey) { */
/*   return IERROR; */
/* } */

/* @TODO This function still follows the old variable structure for join and
   I am just changing the interface to remove compiler complaints. But this
   breaks the functionality! Fix! */
// groupsig_key_t *memkey, groupsig_key_t *grpkey) {
int kty04_join_mem(message_t **mout, groupsig_key_t *memkey,
                   int seq, message_t *min, groupsig_key_t *grpkey) {

  kty04_grp_key_t *gkey;
  kty04_mem_key_t *mkey;
  message_t *_mout;
  int rc;
  byte_t *bkey;
  uint32_t size;

  if((seq != 0) ||
     (!mout || !memkey || memkey->scheme != GROUPSIG_KTY04_CODE ||
      !grpkey || grpkey->scheme != GROUPSIG_KTY04_CODE)) {
    LOG_EINVAL(&logger, __FILE__, "kty04_join_mem", __LINE__, LOGERROR);
    return IERROR;
  }

  gkey = (kty04_grp_key_t *) grpkey->key;
  mkey = (kty04_mem_key_t *) memkey->key;
  rc = IOK;

  /* Get a random power in the inner sphere of Lambda */
#ifdef DEBUG
  log_printf(&logger, LOGDEBUG,
	     "@todo Warning: This should be done with a protocol for non-adaptive"
	  " drawing of random powers!\n");
#endif

  if(sphere_get_random(gkey->inner_lambda, mkey->xx) == IERROR) GOTOENDRC(IERROR, kty04_join_mem);

  /* Set C = b^xx */
  if(bigz_powm(mkey->C, gkey->b, mkey->xx, gkey->n) == IERROR) GOTOENDRC(IERROR, kty04_join_mem);

  /* Write the memkey into mout */
  bkey = NULL;
  if (kty04_mem_key_export(&bkey, &size, memkey) == IERROR)
    GOTOENDRC(IERROR, kty04_join_mem);

  if(!*mout) {
    if(!(_mout = message_from_bytes(bkey, size)))
      GOTOENDRC(IERROR, kty04_join_mem);
    *mout = _mout;
  } else {
    _mout = *mout;
    if(message_set_bytes(_mout, bkey, size) == IERROR)
      GOTOENDRC(IERROR, kty04_join_mem);
  }

  kty04_join_mem_end:
  // The bytes are copied in message_set bytes to a new buffer, thus we need to remove it.
  if (bkey) { free(bkey); bkey = NULL; }
  return rc;
}

/* join.c ends here */
