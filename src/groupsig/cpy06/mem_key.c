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
#include <fcntl.h>
#include <math.h>

#include "cpy06.h"
#include "groupsig/cpy06/mem_key.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "misc/misc.h"
#include "sys/mem.h"

groupsig_key_t* cpy06_mem_key_init() {
  
  groupsig_key_t *key;
  cpy06_mem_key_t *cpy06_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (cpy06_mem_key_t *) mem_malloc(sizeof(cpy06_mem_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_CPY06_CODE;
  cpy06_key = key->key;
  cpy06_key->x = NULL;
  cpy06_key->t = NULL;
  cpy06_key->A = NULL;

  return key;

}

int cpy06_mem_key_free(groupsig_key_t *key) {

  cpy06_mem_key_t *cpy06_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_mem_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mem_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    cpy06_key = key->key;
    if (cpy06_key->x) {
      pbcext_element_Fr_free(cpy06_key->x); cpy06_key->x = NULL;
    }
    if (cpy06_key->t) {
      pbcext_element_Fr_free(cpy06_key->t); cpy06_key->t = NULL;
    }
    if (cpy06_key->A) {
      pbcext_element_G1_free(cpy06_key->A); cpy06_key->A = NULL;
    }
    mem_free(key->key);
    key->key = NULL;
  }
  
  mem_free(key);

  return IOK;

}

int cpy06_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  cpy06_mem_key_t *cpy06_dst, *cpy06_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_CPY06_CODE ||
     !src || src->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  cpy06_dst = dst->key;
  cpy06_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if (!(cpy06_dst->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_mem_key_copy);
  if (pbcext_element_Fr_set(cpy06_dst->x, cpy06_src->x) == IERROR)
    GOTOENDRC(IERROR, cpy06_mem_key_copy);
  if (!(cpy06_dst->t = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_mem_key_copy);
  if (pbcext_element_Fr_set(cpy06_dst->t, cpy06_src->t) == IERROR)
    GOTOENDRC(IERROR, cpy06_mem_key_copy);
  if (!(cpy06_dst->A = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_mem_key_copy);
  if (pbcext_element_G1_set(cpy06_dst->A, cpy06_src->A) == IERROR)
    GOTOENDRC(IERROR, cpy06_mem_key_copy);

 cpy06_mem_key_copy_end:

  if (rc == IERROR) {
    if (cpy06_dst->x) {
      pbcext_element_Fr_free(cpy06_dst->x); cpy06_dst->x = NULL;
    }
    if (cpy06_dst->t) {
      pbcext_element_Fr_free(cpy06_dst->t); cpy06_dst->t = NULL;
    }
    if (cpy06_dst->A) {
      pbcext_element_G1_free(cpy06_dst->A); cpy06_dst->A = NULL;
    }    
  }

  return rc;

}

int cpy06_mem_key_get_size(groupsig_key_t *key) {

  cpy06_mem_key_t *cpy06_key;
  uint64_t size64, sx, st, sA;

  if(!key || key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mem_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  cpy06_key = key->key;
  sx = st = sA = 0;

  if (pbcext_element_Fr_byte_size(&sx) == IERROR) return -1;
  if (pbcext_element_Fr_byte_size(&st) == IERROR) return -1;
  if (pbcext_element_G1_byte_size(&sA) == IERROR) return -1;

  size64 = sizeof(uint8_t)*2 + sizeof(int)*3 + sx + st + sA;
  if (size64 > INT_MAX) return -1;

  return (int) size64;

}

char* cpy06_mem_key_to_string(groupsig_key_t *key) {

  cpy06_mem_key_t *cpy06_key;
  char *x, *t, *A, *skey;
  uint64_t x_len, t_len, A_len;
  uint32_t skey_len;
  int rc;

  if(!key || key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mem_key_to_string",
	       __LINE__, LOGERROR);
    return NULL;
  }

  cpy06_key = key->key;
  x = t = A = skey = NULL;
  rc = IOK;

  if (pbcext_element_Fr_to_string(&x, &x_len, 10, cpy06_key->x) == IERROR)
    GOTOENDRC(IERROR, cpy06_mem_key_to_string);

  if (pbcext_element_Fr_to_string(&t, &t_len, 10, cpy06_key->t) == IERROR)
    GOTOENDRC(IERROR, cpy06_mem_key_to_string);

  if (pbcext_element_G1_to_string(&A, &A_len, 10, cpy06_key->A) == IERROR)
    GOTOENDRC(IERROR, cpy06_mem_key_to_string);

  if (!x || !t || !A) GOTOENDRC(IERROR, cpy06_mem_key_to_string);

  skey_len = strlen(x) + strlen(t) + strlen(A) + strlen("x: \nt: \nA: \n")+1;

  if (!(skey = (char *) mem_malloc(sizeof(char)*skey_len)))
    GOTOENDRC(IERROR, cpy06_mem_key_to_string);

  memset(skey, 0, sizeof(char)*skey_len);

  sprintf(skey,
	  "x: %s\n"
	  "t: %s\n"
	  "A: %s\n",
	  x, t, A);

 cpy06_mem_key_to_string_end:

  if (x) { mem_free(x); x = NULL; }
  if (t) { mem_free(t); t = NULL; }
  if (A) { mem_free(A); A = NULL; }

  if (rc == IERROR && skey) { mem_free(skey); skey = NULL; }
  
  return s;

}

int cpy06_mem_key_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_key_t *key) {

  cpy06_mem_key_t *cpy06_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  cpy06_key = key->key;

  /* Get the number of bytes to represent the key */
  if ((_size = cpy06_mem_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_CPY06_CODE */
  _bytes[ctr++] = GROUPSIG_CPY06_CODE;

  /* Dump key type */
  _bytes[ctr++] = GROUPSIG_KEY_MEMKEY;

  /* Dump x */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_key->x) == IERROR)
    GOTOENDRC(IERROR, cpy06_mem_key_export);
  ctr += len;

  /* Dump t */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_key->t) == IERROR)
    GOTOENDRC(IERROR, cpy06_mem_key_export);
  ctr += len;

  /* Dump A */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, cpy06_key->A) == IERROR)
    GOTOENDRC(IERROR, cpy06_mem_key_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_mem_key_export", __LINE__,
                      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_mem_key_export);
  }

  *size = ctr;

 cpy06_mem_key_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  return rc;  
  
}

groupsig_key_t* cpy06_mem_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  cpy06_mem_key_t *cpy06_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(key = cpy06_mem_key_init())) {
    return NULL;
  }

  cpy06_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_mem_key_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_mem_key_import);
  }

  /* Next byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MEMKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_mem_key_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_mem_key_import);
  }

  /* Get x */
  if(!(cpy06_key->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_mem_key_import);
  if(pbcext_get_element_Fr_bytes(cpy06_key->x, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_mem_key_import);
  ctr += len;

  /* Get t */
  if(!(cpy06_key->t = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_mem_key_import);
  if(pbcext_get_element_Fr_bytes(cpy06_key->t, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_mem_key_import);
  ctr += len;

  /* Get A */
  if(!(cpy06_key->A = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_mem_key_import);
  if(pbcext_get_element_G1_bytes(cpy06_key->A, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_mem_key_import);
  ctr += len; 

 cpy06_mem_key_import_end:
  
  if(rc == IERROR && key) { cpy06_mem_key_free(key); key = NULL; }
  if(rc == IOK) return key;

  return NULL;

}

/* mem_key.c ends here */
