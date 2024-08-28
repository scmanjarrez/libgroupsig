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
#include "groupsig/cpy06/mem_key.h"
#include "sys/mem.h"
#include "shim/pbc_ext.h"
#include "crypto/spk.h"

/**
 * Note: cpy06_join_mem and cpy06_join_mgr compose an interactive protocol,
 * as described in the CPY06 paper. Here, as in the paper, we assume that
 * this protocol is run in a confidential and authenticated channel, with
 * protection against replays. The  user of this protocol should make sure of
 * that.
 */
int cpy06_join_mem(message_t **mout,
		   groupsig_key_t *memkey,
		   int seq,
		   message_t *min,
		   groupsig_key_t *grpkey) {

  pbcext_element_Fr_t *y, *r, *s[2], *u, *v, *x[4], *rr;
  pbcext_element_G1_t *g1, *I, *e[2], *Y[2], *G[3], *pi, *aux_g1;
  pbcext_element_G2_t *g2, *aux_g2;
  pbcext_element_GT_t *aux_gt1, *aux_gt2;
  cpy06_mem_key_t *cpy06_memkey, *_cpy06_memkey;
  groupsig_key_t *_memkey;
  cpy06_grp_key_t *cpy06_grpkey;
  spk_rep_t *spk;
  byte_t *bkey, *bmsg, *bpi, *bspk, *bI;
  message_t *_mout;
  uint64_t len, ulen, vlen, Ilen, pilen, spklen;
  uint32_t size;
  uint16_t i[4][2], prods[2];
  int rc;

  if(!mout || !memkey || memkey->scheme != GROUPSIG_CPY06_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_join_mem", __LINE__, LOGERROR);
    return IERROR;
  }

  cpy06_memkey = (cpy06_mem_key_t *) memkey->key;
  cpy06_grpkey = (cpy06_grp_key_t *) grpkey->key;
  y = r = u = v = rr = NULL;
  g1 = I = pi = aux_g1 = NULL;
  g2 = aux_g2 = NULL;
  aux_gt1 = aux_gt2 = NULL;
  bkey = bmsg = bpi = bspk = bI = NULL;
  spk = NULL;
  len = ulen = vlen = Ilen = pilen = spklen = 0;
  rc = IOK;

  /* 1st step by member (seq 0/4): commit to randomness */
  if (seq == 0) {

    /* y,r \in_R Z^*_p */
    if (!(y = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_Fr_random(y) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (!(r = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_Fr_random(r) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    /* I = yG1 + rQ */
    if (!(g1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_G1_from_string(&g1, BLS12_381_P, 10) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (!(I = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    e[0] = g1; e[1] = cpy06_grpkey->q;
    s[0] = y; s[1] = r;
    if (pbcext_element_G1_muln(I, e, s, 2) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    /* We "temporarily" store y and r by updating the received memkey. This is
       simply to allow completing subsequent phases of this protocol run. Those
       variables will be ignored if exporting/importing the key. */
    if (!(cpy06_memkey->_y = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_Fr_set(cpy06_memkey->_y, y) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    if (!(cpy06_memkey->_r = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_Fr_set(cpy06_memkey->_r, r) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    /* First message is I */
    if (pbcext_dump_element_G1_bytes(&bmsg, &len, I) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem)

    if(!*mout) {
      if(!(_mout = message_from_bytes(bmsg, len)))
        GOTOENDRC(IERROR, cpy06_join_mem);
      *mout = _mout;
    } else {
      _mout = *mout;
      if(message_set_bytes(*mout, bmsg, len) == IERROR)
        GOTOENDRC(IERROR, cpy06_join_mem);
    }

  }

  /* 2nd step by member (seq 2/4): generate non-adaptive random xi with member
     committed randomness, and manager provided randomness */
  else if (seq == 2) {

    /* y and r values from seq = 0 are fetched from the memkey */

    /* min = <u,v,I>
       Read u, v and I values from input message */
    if (!(u = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_get_element_Fr_bytes(u, &ulen, min->bytes) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (!(v = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_get_element_Fr_bytes(v, &vlen, min->bytes + ulen) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (!(I = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_get_element_G1_bytes(I, &Ilen, min->bytes + ulen + vlen) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    /* memkey->x = u*memkey->y + v */
    if (!(cpy06_memkey->x = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);

    if (pbcext_element_Fr_mul(cpy06_memkey->x, u, cpy06_memkey->_y) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_Fr_add(cpy06_memkey->x, cpy06_memkey->x, v) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    /* pi = xi*G1 */
    if (!(g1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_G1_from_string(&g1, BLS12_381_P, 10) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (!(pi = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_G1_mul(pi, g1, cpy06_memkey->x) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    /* rr = -r' = -ur */
    if (!(rr = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_Fr_mul(rr, u, cpy06_memkey->_r))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_Fr_neg(rr, rr))
      GOTOENDRC(IERROR, cpy06_join_mem);

    /* We'll be signing pi in the SPK */
    if (pbcext_dump_element_G1_bytes(&bpi, &pilen, pi) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    /* Compute SPK */
    Y[0] = pi;
    Y[1] = pi;

    G[0] = g1;
    G[1] = I;
    G[2] = cpy06_grpkey->q;

    x[0] = cpy06_memkey->x;
    x[1] = v;
    x[2] = u;
    x[3] = rr;

    i[0][0] = 0; i[0][1] = 0; // x*g1 (g[0],x[0])
    i[1][0] = 1; i[1][1] = 0; // v*g1 (g[0],x[1])
    i[2][0] = 2; i[2][1] = 1; // u*I (g[1],x[2])
    i[3][0] = 3; i[3][1] = 2; // rr*q (g[2],x[3])

    prods[0] = 1;
    prods[1] = 3;

    /* We don't really need an SPK (i.e., no need to sign anything), but the
       spk_rep function already allows us to prove the claim we need, so... */
    if (!(spk = spk_rep_init(4)))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (spk_rep_sign(spk,
		     Y, 2,
		     G, 3,
		     x, 4,
		     i, 4,
		     prods,
		     bpi, pilen) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    if (spk_rep_export(&bspk, &spklen, spk) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    /* Output message is <I,pi,spk> */
    if (pbcext_dump_element_G1_bytes(&bI, &Ilen, I) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    len = Ilen + pilen + spklen;

    if (!(bmsg = (byte_t *) mem_malloc(sizeof(byte_t)*len)))
      GOTOENDRC(IERROR, cpy06_join_mem);
    memcpy(bmsg, bI, Ilen);
    memcpy(bmsg+Ilen, bpi, pilen);
    memcpy(&bmsg[Ilen+pilen], bspk, spklen);

    if(!*mout) {
      if(!(_mout = message_from_bytes(bmsg, len)))
        GOTOENDRC(IERROR, cpy06_join_mem);
      *mout = _mout;
    } else {
      _mout = *mout;
      if(message_set_bytes(*mout, bmsg, len) == IERROR)
        GOTOENDRC(IERROR, cpy06_join_mem);
    }

  }

  /* 3rd step by member (seq 4/4): check cert */
  else if (seq == 4) {

    /* min is memkey (except for empty x) */
    _memkey = cpy06_mem_key_import(min->bytes, min->length);
    if(!_memkey) GOTOENDRC(IERROR, cpy06_join_mem);
    _cpy06_memkey = (cpy06_mem_key_t *) _memkey->key;

    /* Check that e(A, t*G2 + R) = e(x*G1+Q, G2) */
    if (!(g1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_G1_from_string(&g1, BLS12_381_P, 10) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (!(g2 = pbcext_element_G2_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_G2_from_string(&g2, BLS12_381_Q, 10) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    if (!(aux_g1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (!(aux_g2 = pbcext_element_G2_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_G2_mul(aux_g2, g2, _cpy06_memkey->t) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_G2_add(aux_g2, aux_g2, cpy06_grpkey->r) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_G1_mul(aux_g1, g1, cpy06_memkey->x) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_G1_add(aux_g1, aux_g1, cpy06_grpkey->q) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    if (!(aux_gt1 = pbcext_element_GT_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (!(aux_gt2 = pbcext_element_GT_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_pairing(aux_gt1, _cpy06_memkey->A, aux_g2) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_pairing(aux_gt2, aux_g1, g2) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_GT_cmp(aux_gt1, aux_gt2))
      GOTOENDRC(IERROR, cpy06_join_mem);

    /* All good: transfer all data to memkey */
    if (!(cpy06_memkey->A = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_G1_set(cpy06_memkey->A, _cpy06_memkey->A) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (!(cpy06_memkey->t = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, cpy06_join_mem);
    if (pbcext_element_Fr_set(cpy06_memkey->t, _cpy06_memkey->t) == IERROR)
      GOTOENDRC(IERROR, cpy06_join_mem);

    if (_memkey) { cpy06_mem_key_free(_memkey); _memkey = NULL; }
  }

  else {
    GOTOENDRC(IERROR, cpy06_join_mem);
  }

  /* // else error */

  /* /\** @todo A provably secure two party computation for adaptive chosing of */
  /*     random powers should be executed here (see KTY04). *\/ */
  /* /\* x \in_R Z^*_p *\/ */
  /* if (!(cpy06_memkey->x = pbcext_element_Fr_init())) */
  /*   GOTOENDRC(IERROR, cpy06_join_mem); */
  /* if (pbcext_element_Fr_random(cpy06_memkey->x) == IERROR) */
  /*   GOTOENDRC(IERROR, cpy06_join_mem); */

  /* /\* By convention here, we will set t and A to 0 to mark that they have not */
  /*    been set... (@todo is this a mathematical stupidity?) */
  /*    NOTE: this is needed by some external applications (e.g. caduceus) */
  /* *\/ */

  /* if (!(cpy06_memkey->t = pbcext_element_Fr_init())) */
  /*   GOTOENDRC(IERROR, cpy06_join_mem); */
  /* /\* pbcext_element_set0(cpy06_memkey->t); *\/ */
  /* if (!(cpy06_memkey->A = pbcext_element_G1_init())) */
  /*   GOTOENDRC(IERROR, cpy06_join_mem); */
  /* /\* pbcext_element_set0(cpy06_memkey->A); *\/ */

  /* bkey = NULL; */
  /* if (cpy06_mem_key_export(&bkey, &size, memkey) == IERROR) */
  /*   GOTOENDRC(IERROR, cpy06_join_mem); */

  /* if(!*mout) { */
  /*   if(!(_mout = message_from_bytes(bkey, size))) */
  /*     GOTOENDRC(IERROR, cpy06_join_mem); */
  /*   *mout = _mout; */
  /* } else { */
  /*   _mout = *mout; */
  /*   if(message_set_bytes(_mout, bkey, size) == IERROR) */
  /*     GOTOENDRC(IERROR, cpy06_join_mem); */
  /* } */

 cpy06_join_mem_end:

  if (rc == IERROR) {
    if (cpy06_memkey->x) {
      pbcext_element_Fr_free(cpy06_memkey->x); cpy06_memkey->x = NULL;
    }
    if (cpy06_memkey->t) {
      pbcext_element_Fr_free(cpy06_memkey->x); cpy06_memkey->t = NULL;
    }
    if (cpy06_memkey->A) {
      pbcext_element_G1_free(cpy06_memkey->A); cpy06_memkey->A = NULL;
    }
  }
  if (bkey) { mem_free(bkey); bkey = NULL; }
  if (bmsg) { mem_free(bmsg); bmsg = NULL; }
  if (bpi) { mem_free(bpi); bpi = NULL; }
  if (bspk) { mem_free(bspk); bspk = NULL; }
  if (spk) { spk_rep_free(spk); spk = NULL; }
  if (bI) { mem_free(bI); bI = NULL; }
  if (y) { pbcext_element_Fr_free(y); y = NULL; }
  if (r) { pbcext_element_Fr_free(r); r = NULL; }
  if (u) { pbcext_element_Fr_free(u); u = NULL; }
  if (v) { pbcext_element_Fr_free(v); v = NULL; }
  if (rr) { pbcext_element_Fr_free(rr); rr = NULL; }
  if (g1) { pbcext_element_G1_free(g1); g1 = NULL; }
  if (I) { pbcext_element_G1_free(I); I = NULL; }
  if (pi) { pbcext_element_G1_free(pi); pi = NULL; }
  if (aux_g1) { pbcext_element_G1_free(aux_g1); aux_g1 = NULL; }
  if (g2) { pbcext_element_G2_free(g2); g2 = NULL; }
  if (aux_g2) { pbcext_element_G2_free(aux_g2); aux_g2 = NULL; }
  if (aux_gt1) { pbcext_element_GT_free(aux_gt1); aux_gt1 = NULL; }
  if (aux_gt2) { pbcext_element_GT_free(aux_gt2); aux_gt2 = NULL; }

  return rc;

}

/* join.c ends here */
