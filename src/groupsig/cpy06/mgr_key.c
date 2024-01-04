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

#include "cpy06.h"
#include "groupsig/cpy06/mgr_key.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

/**
 * @fn static int _import_fd(FILE *fd, exim_t* obj)
 * @brief Import a representation of the given key from a file descriptor.
 * Expects the same format as the output from _export_fd().
 *
 * @return IOK or IERROR
 */
static int _import_fd(FILE *fd, exim_t* obj) {
  groupsig_key_t *key;
  cpy06_mgr_key_t *cpy06_key;
  cpy06_sysenv_t *cpy06_sysenv;
  uint8_t type, scheme;

  if(!fd || !obj) {
    LOG_EINVAL(&logger, __FILE__, "_import_fd", __LINE__,
           LOGERROR);
    return IERROR;
  }

  if(!(key = cpy06_mgr_key_init())) {
    return IERROR;
  }

  cpy06_key = key->key;

  /* First byte: scheme */
  if(fread(&scheme, sizeof(byte_t), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "_import_fd", __LINE__,
          errno, LOGERROR);
    cpy06_mgr_key_free(key); key = NULL;
    return IERROR;
  }

  /* Next byte: key type */
  if(fread(&type, sizeof(byte_t), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "_import_fd", __LINE__,
          errno, LOGERROR);
    cpy06_mgr_key_free(key); key = NULL;
    return IERROR;
  }

  /* Get the params if sysenv->data is uninitialized */
  if(!sysenv->data) {

    /* Copy the param and pairing to the CPY06 internal environment */
    /* By setting the environment, we avoid having to keep a copy of params
       and pairing in manager/member keys and signatures, crls, gmls... */
    if(!(cpy06_sysenv = (cpy06_sysenv_t *) mem_malloc(sizeof(cpy06_sysenv_t)))) {
      cpy06_mgr_key_free(key); key = NULL;
      return IERROR;
    }

    /* Get the params */
    if(pbcext_get_param_fd(cpy06_sysenv->param, fd) == IERROR) {
      cpy06_mgr_key_free(key); key = NULL;
      return IERROR;
    }

    pairing_init_pbc_param(cpy06_sysenv->pairing, cpy06_sysenv->param);

    if(cpy06_sysenv_update(cpy06_sysenv) == IERROR) {
      cpy06_mgr_key_free(key); key = NULL;
      pbc_param_clear(cpy06_sysenv->param);
      mem_free(cpy06_sysenv); cpy06_sysenv = NULL;
      return IERROR;
    }

  } else { /* Else, skip it */

    if (pbcext_skip_param_fd(fd) == IERROR) {
      cpy06_mgr_key_free(key); key = NULL;
    }
    cpy06_sysenv = sysenv->data;

  }

  /* Get xi1 */
  element_init_Zr(cpy06_key->xi1, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->xi1, fd) == IERROR) {
    cpy06_mgr_key_free(key); key = NULL;
    return IERROR;
  }

  /* Get xi2 */
  element_init_Zr(cpy06_key->xi2, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->xi2, fd) == IERROR) {
    cpy06_mgr_key_free(key); key = NULL;
    return IERROR;
  }

  /* Get gamma */
  element_init_Zr(cpy06_key->gamma, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->gamma, fd) == IERROR) {
    cpy06_mgr_key_free(key); key = NULL;
    return IERROR;
  }

  obj->eximable = (void*) key;
  return IOK;

}

/* Export/import handle definition */

static exim_handle_t _exim_h = {
  &_get_size_bytearray_null,
  &_export_fd,
  &_import_fd,
};

/* public functions */

groupsig_key_t* cpy06_mgr_key_init() {

  groupsig_key_t *key;
  cpy06_mgr_key_t *cpy06_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (cpy06_mgr_key_t *) mem_malloc(sizeof(cpy06_mgr_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }
  
  key->scheme = GROUPSIG_CPY06_CODE;
  cpy06_key = key->key;
  cpy06_key->xi1 = NULL;
  cpy06_key->xi2 = NULL;
  cpy06_key->gamma = NULL;  

  return key;

}

int cpy06_mgr_key_free(groupsig_key_t *key) {

  cpy06_mgr_key_t *cpy06_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_mgr_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mgr_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    cpy06_key = key->key;
    if (cpy06_key->xi1) {
      pbcext_element_Fr_free(cpy06_key->xi1); cpy06_key->xi1 = NULL;
    }
    if (cpy06_key->xi2) {
      pbcext_element_Fr_free(cpy06_key->xi2); cpy06_key->xi2 = NULL;
    }    
    if (cpy06_key->gamma) {
      pbcext_element_Fr_free(cpy06_key->gamma); cpy06_key->gamma = NULL;
    }
    mem_free(key->key);
    key->key = NULL;
  }
  
  mem_free(key);

  return IOK;

}

int cpy06_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  cpy06_mgr_key_t *cpy06_dst, *cpy06_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_CPY06_CODE ||
     !src || src->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mgr_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  cpy06_dst = dst->key;
  cpy06_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if (!(cpy06_dst->xi1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_mgr_key_copy);
  if(pbcext_element_Fr_set(cpy06_dst->xi1, cpy06_src->xi1) == IERROR)
    GOTOENDRC(IERROR, cpy06_mgr_key_copy);
  if (!(cpy06_dst->xi2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_mgr_key_copy);
  if (pbcext_element_Fr_set(cpy06_dst->xi2, cpy06_src->xi2) == IERROR)
    GOTOENDRC(IERROR, cpy06_mgr_key_copy);
  if (!(cpy06_dst->gamma = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_mgr_key_copy);
  if (pbcext_element_Fr_set(cpy06_dst->gamma, cpy06_src->gamma) == IERROR)
    GOTOENDRC(IERROR, cpy06_mgr_key_copy);

 cpy06_mgr_key_copy_end:

  if (rc == IERROR) {
    if (cpy06_dst->xi1) {
      pbcext_element_Fr_free(cpy06_dst->xi1); cpy06_dst->xi1 = NULL;
    }
    if (cpy06_dst->xi2) {
      pbcext_element_Fr_free(cpy06_dst->xi2); cpy06_dst->xi2 = NULL;
    }
    if (cpy06_dst->gamma) {
      pbcext_element_Fr_free(cpy06_dst->gamma); cpy06_dst->gamma = NULL;
    }    
  }

  return rc;

}

int cpy06_mgr_key_get_size(groupsig_key_t *key) {

  cpy06_mgr_key_t *cpy06_key;
  uint64_t size64, sxi1, sxi2, sgamma;

  if(!key || key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mgr_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  sxi1 = sxi2 = sgamma = 0;

  if (pbcext_element_Fr_byte_size(&sxi1) == IERROR) return -1;
  if (pbcext_element_Fr_byte_size(&sxi2) == IERROR) return -1;
  if (pbcext_element_Fr_byte_size(&sgamma) == IERROR) return -1;

  size64 = sizeof(uint8_t)*2 + sizeof(int)*3 + sxi1 + sxi2 + sgamma;

  if (size64 > INT_MAX) return -1;
  return (int) size64;

}

int cpy06_mgr_key_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_key_t *key) {

  cpy06_mgr_key_t *cpy06_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mgr_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  cpy06_key = key->key;

    /* Get the number of bytes to represent the key */
  if ((_size = cpy06_mgr_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_CPY06_CODE */
  _bytes[ctr++] = GROUPSIG_CPY06_CODE;

  /* Dump key type */
  _bytes[ctr++] = GROUPSIG_KEY_MGRKEY;

  /* Dump xi1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_key->xi1) == IERROR) 
    GOTOENDRC(IERROR, cpy06_mgr_key_export);
  ctr += len;

  /* Dump xi2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_key->xi2) == IERROR) 
    GOTOENDRC(IERROR, cpy06_mgr_key_export);
  ctr += len;

  /* Dump gamma */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_key->gamma) == IERROR) 
    GOTOENDRC(IERROR, cpy06_mgr_key_export);
  ctr += len;

  /* Prepare the return */
  if (!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_mgr_key_export", __LINE__,
                      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_mgr_key_export);
  }
  
  *size = ctr;
  
 cpy06_mgr_key_export_end:
  
  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  return rc;

}

groupsig_key_t* cpy06_mgr_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  cpy06_mgr_key_t *cpy06_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mgr_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if (!(key = cpy06_mgr_key_init())) {
    return NULL;
  }

  cpy06_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_mgr_key_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_mgr_key_import);
  }

  /* Next byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MGRKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_mgr_key_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_mgr_key_import);
  }
  
  /* Get xi1 */
  if(!(cpy06_key->xi1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(cpy06_key->xi1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_mgr_key_import);
  ctr += len;

  /* Get xi2 */
  if(!(ps16_key->xi2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(cpy06_key->xi2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_mgr_key_import);
  ctr += len;

  /* Get gamma */
  if(!(ps16_key->gamma = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(cpy06_key->gamma, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_mgr_key_import);
  ctr += len;  

 cpy06_mgr_key_import_end:

  if(rc == IERROR && key) { cpy06_mgr_key_free(key); key = NULL; }
  if(rc == IOK) return key;  

  return rc;  

}

char* cpy06_mgr_key_to_string(groupsig_key_t *key) {

  cpy06_mgr_key_t* cpy06_key = (cpy06_mgr_key_t*) key->key;
  char *xi1 = NULL, *xi2 = NULL, *gamma = NULL, *mgr_key = NULL;
  size_t xi1_size = 0, xi2_size = 0, gamma_size = 0, mgr_key_size = 0;

  if(!key || !cpy06_key ||key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mgr_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  if(pbcext_element_Fr_to_string(&xi1,
                                 &xi1_size,
                                 10,
                                 cpy06_key->xi1) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mgr_key_to_string", __LINE__, LOGERROR);
    goto mgr_key_to_string_error;
  }

  if(pbcext_element_Fr_to_string(&xi2,
                                 &xi2_size,
                                 10,
                                 cpy06_key->xi2) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mgr_key_to_string", __LINE__, LOGERROR);
    goto mgr_key_to_string_error;
  }

  if(pbcext_element_Fr_to_string(&gamma,
                                 &gamma_size,
                                 10,
                                 cpy06_key->gamma) == IERROR) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mgr_key_to_string", __LINE__, LOGERROR);
    goto mgr_key_to_string_error;
  }  

  mgr_key_size = xi1_size + xi2_size + gamma_size + strlen("x: \ny: \n") + 1;
  if (!(mgr_key = (char*) calloc(mgr_key_size, sizeof(char)))){
    LOG_EINVAL(&logger, __FILE__, "cpy016_mgr_key_to_string", __LINE__, LOGERROR);
    goto mgr_key_to_string_error;
  }

  snprintf(mgr_key, mgr_key_size,
	   "xi1: %s\n"
	   "xi2: %s\n",
	   "gamma: %s\n",
	   xi1, xi2, gamma);

 mgr_key_to_string_error:

  if(xi1) { mem_free(xi1), xi1 = NULL; }
  if(xi2) { mem_free(xi1), xi2 = NULL; }
  if(gamma) { mem_free(gamma), gamma = NULL; }

  return mgr_key;

}

/* mgr_key.c ends here */
