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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "types.h"
#include "sysenv.h"
#include "sys/mem.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "misc/misc.h"
#include "cpy06.h"
#include "groupsig/cpy06/signature.h"

groupsig_signature_t* cpy06_signature_init() {

  groupsig_signature_t *sig;
  cpy06_signature_t *cpy06_sig;

  cpy06_sig = NULL;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_signature_init", __LINE__, errno, 
		  LOGERROR);
  }

  if(!(cpy06_sig = (cpy06_signature_t *) mem_malloc(sizeof(cpy06_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_signature_init", __LINE__, errno, 
		  LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_CPY06_CODE;
  sig->sig = cpy06_sig;
  cpy06_sig->T1 = NULL;
  cpy06_sig->T2 = NULL;
  cpy06_sig->T3 = NULL;
  cpy06_sig->T4 = NULL;
  cpy06_sig->T5 = NULL;
  cpy06_sig->c = NULL;
  cpy06_sig->sr1 = NULL;
  cpy06_sig->sr2 = NULL;
  cpy06_sig->sd1 = NULL;
  cpy06_sig->sd2 = NULL;
  cpy06_sig->sx = NULL;
  cpy06_sig->st = NULL;
  
  return sig;

}

int cpy06_signature_free(groupsig_signature_t *sig) {

  cpy06_signature_t *cpy06_sig;

  if(!sig || sig->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  if(sig->sig) {
    cpy06_sig = sig->sig;
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
    mem_free(cpy06_sig); 
    cpy06_sig = NULL;
  }
  
  mem_free(sig);

  return IOK;

}

int cpy06_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  cpy06_signature_t *cpy06_dst, *cpy06_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_CPY06_CODE ||
     !src || src->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  cpy06_dst = dst->sig;
  cpy06_src = src->sig;
  rc = IOK;

  /* Copy the elements */
  if (!(cpy06_dst->T1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (pbcext_element_G1_set(cpy06_dst->T1, cpy06_src->T1) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (!(cpy06_dst->T2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (pbcext_element_G1_set(cpy06_dst->T2, cpy06_src->T2) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_copy);  
  if (!(cpy06_dst->T3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (pbcext_element_G1_set(cpy06_dst->T3, cpy06_src->T3) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (!(cpy06_dst->T4 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (pbcext_element_G2_set(cpy06_dst->T4, cpy06_src->T4) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (!cpy06_dst->T5 = pbcext_element_GT_init())
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (pbcext_element_GT_set(cpy06_dst->T5, cpy06_src->T5) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (!(cpy06_dst->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (pbcext_element_Fr_set(cpy06_dst->c, cpy06_src->c) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (!(cpy06_dst->sr1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_copy);    
  if (pbcext_element_Fr_set(cpy06_dst->sr1, cpy06_src->sr1) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (!(cpy06_dst->sr2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (pbcext_element_Fr_set(cpy06_dst->sr2, cpy06_src->sr2) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (!(cpy06_dst->sd1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (pbcext_element_Fr_set(cpy06_dst->sd1, cpy06_src->sd1) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (!(cpy06_dst->sd2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_copy);  
  if (pbcext_element_Fr_set(cpy06_dst->sd2, cpy06_src->sd2) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (!(cpy06_dst->sx = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (pbcext_element_Fr_set(cpy06_dst->sx, cpy06_src->sx) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (!(cpy06_dst->st = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_copy);
  if (pbcext_element_Fr_set(cpy06_dst->st, cpy06_src->st) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_copy);

 cpy06_signature_copy_end:

  if (rc == IERROR) {
    if (cpy06_dst->T1) {
      pbcext_element_G1_free(cpy06_dst->T1); cpy06_dst->T1 = NULL;
    }
    if (cpy06_dst->T2) {
      pbcext_element_G1_free(cpy06_dst->T2); cpy06_dst->T2 = NULL;
    }
    if (cpy06_dst->T3) {
      pbcext_element_G1_free(cpy06_dst->T3); cpy06_dst->T3 = NULL;
    }
    if (cpy06_dst->T4) {
      pbcext_element_G2_free(cpy06_dst->T4); cpy06_dst->T4 = NULL;
    }
    if (cpy06_dst->T5) {
      pbcext_element_GT_free(cpy06_dst->T5); cpy06_dst->T5 = NULL;
    }
    if (cpy06_dst->c) {
      pbcext_element_Fr_free(cpy06_dst->c); cpy06_dst->c = NULL;
    }
    if (cpy06_dst->sr1) {
      pbcext_element_Fr_free(cpy06_dst->sr1); cpy06_dst->sr1 = NULL;
    }
    if (cpy06_dst->sr2) {
      pbcext_element_Fr_free(cpy06_dst->sr2); cpy06_dst->sr2 = NULL;
    }
    if (cpy06_dst->sd1) {
      pbcext_element_Fr_free(cpy06_dst->sd1); cpy06_dst->sd1 = NULL;
    }
    if (cpy06_dst->sd2) {
      pbcext_element_Fr_free(cpy06_dst->sd2); cpy06_dst->sd2 = NULL;
    }
    if (cpy06_dst->sx) {
      pbcext_element_Fr_free(cpy06_dst->sx); cpy06_dst->sx = NULL;
    }
    if (cpy06_dst->st) {
      pbcext_element_Fr_free(cpy06_dst->st); cpy06_dst->st = NULL;
    }    
  }
  
  return rc;

}

char* cpy06_signature_to_string(groupsig_signature_t *sig) {

  cpy06_signature_t *cpy06_sig;
  char *T1, *T2, *T3, *T4, *T5, *c, *sr1, *sr2, *sd1, *sd2, *sx, *st, *ssig;
  uint64_t T1_len, T2_len, T3_len, T4_len, T5_len, c_len, sr1_len, sr2_len;
  uint64_t sd1_len, sd2_len, sx_len, st_len;
  uint32_t ssig_len;
  int rc;

  if(!sig || sig->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_signatgure_to_string",
	       __LINE__, LOGERROR);
    return NULL;
  }

  cpy06_sig = sig->sig;
  T1 = T2 = T3 = T4 = T5 = c = sr1 = sr2 = sd1 = sd2 = sx = st = NULL;
  ssig = NULL;
  rc = IOK;

  if (pbcext_element_G1_to_string(&T1, &T1_len, 10, cpy06_sig->T1) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  if (pbcext_element_G1_to_string(&T2, &T2_len, 10, cpy06_sig->T2) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  if (pbcext_element_G1_to_string(&T3, &T3_len, 10, cpy06_sig->T3) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  if (pbcext_element_G2_to_string(&T4, &T4_len, 10, cpy06_sig->T4) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  if (pbcext_element_GT_to_string(&T5, &T5_len, 10, cpy06_sig->T5) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  if (pbcext_element_Fr_to_string(&c, &c_len, 10, cpy06_sig->c) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  if (pbcext_element_Fr_to_string(&sr1, &sr1_len, 10, cpy06_sig->sr1) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  if (pbcext_element_Fr_to_string(&sr2, &sr2_len, 10, cpy06_sig->sr2) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  if (pbcext_element_Fr_to_string(&sd1, &sd1_len, 10, cpy06_sig->sd1) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  if (pbcext_element_Fr_to_string(&sd2, &sd2_len, 10, cpy06_sig->sd2) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  if (pbcext_element_Fr_to_string(&sx, &sx_len, 10, cpy06_sig->sx) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  if (pbcext_element_G1_to_string(&st, &st_len, 10, cpy06_sig->st) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  if (!T1 || !T2 || !T3 || !T4 || !T5 || !c || !sr1 || !sr2 ||
      !sd1 || !sd2 || !sx || !st)
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  skey_len = strlen(T1) + strlen(T2) + strlen(T3) + strlen(T4) + strlen(T5) +
    strlen(c) + strlen(sr1) + strlen(sr2) + strlen(sd1) + strlen(sd2) +
    strlen(sx) + strlen(st) +
    strlen("T1: \nT2: \nT3: \nT4: \nT5: \nc: \nsr1: \nsr2: \n") +
    strlen("sd1: \nsd2: \nsx: \nst: \n") + 1;
  
  if (!(ssig = (char *) mem_malloc(sizeof(char)*ssig_len)))
    GOTOENDRC(IERROR, cpy06_signature_to_string);

  sprintf(ssig,
          "T1: %s\n"
          "T2: %s\n"
          "T3: %s\n"
          "T4: %s\n"
	  "T5: %s\n"
	  "c: %s\n"
	  "sr1: %s\n"
	  "sr2: %s\n"
	  "sd1: %s\n"
	  "sd2: %s\n"
	  "sx: %s\n"
	  "st: %s\n",	  
          T1, T2, T3, T4, T5, c, sr1, sr2, sd1, sd2, sx, st);
  
 cpy06_signature_to_string_end:

  if (rc == IERROR && ssig) { mem_free(ssig); ssig = NULL; }

  if (T1) { mem_free(T1); T1 = NULL; }
  if (T2) { mem_free(T2); T2 = NULL; }
  if (T3) { mem_free(T3); T3 = NULL; }
  if (T4) { mem_free(T4); T4 = NULL; }
  if (T5) { mem_free(T5); T5 = NULL; }
  if (c) { mem_free(c); c = NULL; }
  if (sr1) { mem_free(sr1); sr1 = NULL; }
  if (sr2) { mem_free(sr2); sr2 = NULL; }
  if (sd1) { mem_free(sd1); sd1 = NULL; }
  if (sd2) { mem_free(sd2); sd2 = NULL; }
  if (sx) { mem_free(sx); sx = NULL; }
  if (st) { mem_free(st); st = NULL; }

  return ssig;
  
}

int cpy06_signature_get_size(groupsig_signature_t *sig) {

  cpy06_signature_t *cpy06_sig;
  uint64_t size64, sT1, sT2, sT3, sT4, sT5, sc;
  uint64_t ssr1, ssr2, ssd1, ssd2, ssx, sst;
  
  if(!sig || sig->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_signature_get_size", __LINE__, LOGERROR);
    return -1;
  }

  cpy06_sig = sig->sig;

  sT1 = sT2 = sT3 = sT4 = sT5 = sc = ssr1 = ssr2 = ssd1 = ssd2 = ssx = sst = 0;

  if (pbcext_element_G1_byte_size(&sT1) == IERROR) return -1;
  if (pbcext_element_G1_byte_size(&sT2) == IERROR) return -1;
  if (pbcext_element_G1_byte_size(&sT3) == IERROR) return -1;
  if (pbcext_element_G2_byte_size(&sT4) == IERROR) return -1;
  if (pbcext_element_GT_byte_size(&sT5) == IERROR) return -1;
  if (pbcext_element_Fr_byte_size(&sc) == IERROR) return -1;
  if (pbcext_element_Fr_byte_size(&ssr1) == IERROR) return -1;
  if (pbcext_element_Fr_byte_size(&ssr2) == IERROR) return -1;
  if (pbcext_element_Fr_byte_size(&ssd1) == IERROR) return -1;
  if (pbcext_element_Fr_byte_size(&ssd2) == IERROR) return -1;
  if (pbcext_element_Fr_byte_size(&sx) == IERROR) return -1;
  if (pbcext_element_Fr_byte_size(&st) == IERROR) return -1;

  size64 = sizeof(uint8_t) + sizeof(int)*12 + sT1 + sT2 + sT3 + sT4 + sT5 +
    sc + ssr1 + ssr2 + ssd1 + ssd2 + ssx + sst;
  if (size64 > INT_MAX) return -1;

  return (int) size64;
  
}

int cpy06_signature_export(byte_t **bytes,
			   uint32_t *size,
			   groupsig_signature_t *sig) { 

  cpy06_signature_t *cpy06_sig;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  
  if(!bytes ||
     !size ||
     !sig || sig->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  cpy06_sig = sig->sig;

  /* Get the number of bytes to represent the signature */
  if ((_size = cpy06_signature_get_size(sig)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_CPY06_CODE */
  _bytes[ctr++] = GROUPSIG_CPY06_CODE;

  /* Dump T1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, cpy06_sig->T1) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_export);
  ctr += len;

  /* Dump T2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, cpy06_sig->T2) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_export);
  ctr += len;

  /* Dump T3 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, cpy06_sig->T3) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_export);
  ctr += len;

  /* Dump T4 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, cpy06_sig->T4) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_export);
  ctr += len;

  /* Dump T5 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, cpy06_sig->T5) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_export);
  ctr += len;

  /* Dump c */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_sig->c) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_export);
  ctr += len;

  /* Dump sr1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_sig->sr1) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_export);
  ctr += len;

  /* Dump sr2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_sig->sr2) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_export);
  ctr += len;

  /* Dump sd1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_sig->sd1) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_export);
  ctr += len;

  /* Dump sd2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_sig->sd2) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_export);
  ctr += len;

  /* Dump sx */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_sig->sx) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_export);
  ctr += len;

  /* Dump st */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_sig->st) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_export);
  ctr += len;

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }
  
  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_signature_export", __LINE__,
                      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_signature_export);
  }

  *size = ctr;

 cpy06_signature_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  return rc; 

}

groupsig_signature_t* cpy06_signature_import(byte_t *source, uint32_t size) {

  groupsig_signature_t *sig;
  cpy06_signature_t *cpy06_sig;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(sig = cpy06_signature_init())) {
    return NULL;
  }

  cpy06_sig = sig->sig;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != sig->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_signature_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_signature_import);
  }

  /* Get T1 */
  if(!(cpy06_sig->T1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_signature_import);
  if(pbcext_get_element_G1_bytes(cpy06_sig->T1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_import);
  ctr += len;

  /* Get T2 */
  if(!(cpy06_sig->T2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_signature_import);
  if(pbcext_get_element_G1_bytes(cpy06_sig->T2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_import);
  ctr += len;

  /* Get T3 */
  if(!(cpy06_sig->T3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_signature_import);
  if(pbcext_get_element_G1_bytes(cpy06_sig->T3, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_import);
  ctr += len;

  /* Get T4 */
  if(!(cpy06_sig->T4 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, cpy06_signature_import);
  if(pbcext_get_element_G2_bytes(cpy06_sig->T4, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_import);
  ctr += len;

  /* Get T5 */
  if(!(cpy06_sig->T5 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_signature_import);
  if(pbcext_get_element_GT_bytes(cpy06_sig->T5, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_import);
  ctr += len;

  /* Get c */
  if(!(cpy06_sig->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_import);
  if(pbcext_get_element_Fr_bytes(cpy06_sig->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_import);
  ctr += len;

  /* Get sr1 */
  if(!(cpy06_sig->sr1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_import);
  if(pbcext_get_element_Fr_bytes(cpy06_sig->sr1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_import);
  ctr += len;

  /* Get sr2 */
  if(!(cpy06_sig->sr2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_import);
  if(pbcext_get_element_Fr_bytes(cpy06_sig->sr2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_import);
  ctr += len;

  /* Get sd1 */
  if(!(cpy06_sig->sd1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_import);
  if(pbcext_get_element_Fr_bytes(cpy06_sig->sd1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_import);
  ctr += len;

  /* Get sd2 */
  if(!(cpy06_sig->sd2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_import);
  if(pbcext_get_element_Fr_bytes(cpy06_sig->sd2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_import);
  ctr += len;

  /* Get sx */
  if(!(cpy06_sig->sx = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_import);
  if(pbcext_get_element_Fr_bytes(cpy06_sig->sx, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_import);
  ctr += len;

  /* Get st */
  if(!(cpy06_sig->st = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_signature_import);
  if(pbcext_get_element_Fr_bytes(cpy06_sig->st, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_signature_import);
  ctr += len;

 cpy06_signature_import_end:
  
  if(rc == IERROR && sig) { cpy06_signature_free(sig); sig = NULL; }

  return sig;  

}

/* signature.c ends here */
