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
#include <math.h>
#include <openssl/sha.h>

#include "types.h"
#include "sys/mem.h"
#include "shim/pbc_ext.h"
#include "cpy06.h"
#include "groupsig/cpy06/proof.h"

groupsig_proof_t* cpy06_proof_init() {

  groupsig_proof_t *proof;

  if(!(proof = (groupsig_proof_t *) mem_malloc(sizeof(groupsig_proof_t)))) {
    return NULL;
  }

  proof->scheme = GROUPSIG_CPY06_CODE;
  if(!(proof->proof = (cpy06_proof_t *) mem_malloc(sizeof(cpy06_proof_t)))) {
    mem_free(proof); proof = NULL;
    return NULL;
  }
  
  proof->c = NULL;
  proof->s = NULL;

  return proof;
}

int cpy06_proof_free(groupsig_proof_t *proof) {

  cpy06_proof_t *cpy06_proof;

  if(!proof) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_proof_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IERROR;
  }

  if(proof->proof) {
    cpy06_proof = proof->proof;
    if (pbcext_element_Fr_free(cpy06_proof->c); cpy06_proof->c = NULL; }
    if (pbcext_element_Fr_free(cpy06_proof->s); cpy06_proof->s = NULL; }
    mem_free(proof->proof); proof->proof = NULL;
  }

  mem_free(proof);

  return IOK;

}

/* int cpy06_proof_init_set_c(cpy06_proof_t *proof, bigz_t c) { */

/*   if(!proof || !c) { */
/*     LOG_EINVAL(&logger, __FILE__, "cpy06_proof_init_set_c", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   if(!(proof->c = bigz_init_set(c))) { */
/*     return IERROR; */
/*   } */

/*   return IOK; */

/* } */

/* int cpy06_proof_init_set_s(cpy06_proof_t *proof, bigz_t s) { */

/*   if(!proof || !s) { */
/*     LOG_EINVAL(&logger, __FILE__, "cpy06_proof_init_set_s", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   if(!(proof->s = bigz_init_set(s))) { */
/*     return IERROR; */
/*   } */

/*   return IOK; */

/* } */

char* cpy06_proof_to_string(groupsig_proof_t *proof) {

  cpy06_proof_t *cpy06_proof;
  char *sc, *ss, *sproof;
  uint64_t sc_len, ss_len;
  uint32_t sproof_len;
  int rc;

  if(!proof || proof->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_proof_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  cpy06_proof = proof->proof;
  sc = ss = sproof = NULL;
  rc = IOK;

  if (pbcext_element_Fr_to_string(sc, &sc_len, 10, cpy06_proof->c) == IERROR)
    GOTOENDRC(IERROR, cpy06_proof_to_string);

  if (pbcext_element_Fr_to_string(ss, &ss_len, 10, cpy06_proof->s) == IERROR)
    GOTOENDRC(IERROR, cpy06_proof_to_string);

  if (!sc || !ss) GOTOENDRC(IERROR, cpy06_proof_to_string);

  sproof_len = strlen(sc) + strlen(ss) + strlen("c: \ns: \n")+1;

  if (!(sproof = (char *) mem_malloc(sizeof(char)*sproof_len)))
    GOTOENDRC(IERROR, cpy06_proof_to_string);

  sprintf(sproof,"c: %s\ns: %s\n", sc, ss);

 cpy06_proof_to_string_end:

  if (rc == IERROR && sproof) { mem_free(sproof); sproof = NULL; }

  if (sc) { mem_free(sc); sc = NULL; }
  if (ss) { mem_free(ss); ss =NULL; }
  
  return sproof;

}

int cpy06_proof_get_size_in_format(groupsig_proof_t *proof) {

  cpy06_proof_t *cpy06_proof;
  uint64_t size64, sc, ss;

  if(!proof || proof->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_proof_get_size", __LINE__, LOGERROR);
    return -1;
  }

  cpy06_proof = proof->proof;
  sc = ss = size64 = 0;

  if (pbcext_element_Fr_byte_size(&sc) == IERROR) return -1;
  if (pbcext_element_Fr_byte_size(&ss) == IERROR) return -1;

  size64 = sizeof(uint8_t)+sizeof(int)*2 + sc + ss;
  if (size64 > INT_MAX) return -1;

  return (int) size64;

}

int cpy06_proof_export(byte_t **bytes,
		       uint32_t *size,
		       groupsig_proof_t *proof) { 

  cpy06_proof_t *cpy06_proof;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;

  if(!proof || proof->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_proof_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  cpy06_proof = (cpy06_proof_t *) proof->proof;

    /* Get the number of bytes to represent the signature */
  if ((_size = cpy06_proof_get_size(proof)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_CPY06_CODE */
  _bytes[ctr++] = GROUPSIG_CPY06_CODE;

  /* Dump c */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_proof->c) == IERROR)
    GOTOENDRC(IERROR, cpy06_proof_export);
  ctr += len;

  /* Dump s */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, cpy06_proof->s) == IERROR)
    GOTOENDRC(IERROR, cpy06_proof_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_proof_export", __LINE__,
                      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_proof_export);
  }

  *size = ctr;

 cpy06_proof_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  return rc;

}

groupsig_proof_t* cpy06_proof_import(byte_t *source, uint32_t size) {

  groupsig_proof_t *proof;
  cpy06_proof_t *cpy06_proof;
  uint64_t len;
  byte_t scheme;
  int rc, ctr;

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_proof_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(proof = cpy06_proof_init())) {
    return NULL;
  }

  cpy06_proof = proof->proof;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != proof->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_proof_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_proof_import);
  }

  /* Get c */
  if(!(cpy06_proof->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_proof_import);
  if(pbcext_get_element_Fr_bytes(cpy06_sig->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_proof_import);
  ctr += len;

  /* Get s */
  if(!(cpy06_proof->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, cpy06_proof_import);
  if(pbcext_get_element_Fr_bytes(cpy06_sig->sr1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_proof_import);
  ctr += len;

 cpy06_proof_import_end:
  
  if(rc == IERROR && proof) { cpy06_proof_free(proof); proof = NULL; }

  return proof;
  
}

/* proof.c ends here */
