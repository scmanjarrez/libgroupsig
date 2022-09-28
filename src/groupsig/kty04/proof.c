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
#include "sysenv.h"
#include "sys/mem.h"
#include "shim/base64.h"
#include "misc/misc.h"
#include "kty04.h"
#include "groupsig/kty04/proof.h"

/* Private constants */
#define _INDEX_LENGTH 10

/* Public functions */
groupsig_proof_t* kty04_proof_init() {

  groupsig_proof_t *proof;
  kty04_proof_t *kty04_proof;

  proof = NULL; kty04_proof = NULL;

  /* Initialize the proof contents */
  if(!(proof = (groupsig_proof_t *) mem_malloc(sizeof(groupsig_proof_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_proof_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(kty04_proof = (kty04_proof_t *) mem_malloc(sizeof(kty04_proof_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_proof_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  kty04_proof->c = NULL; kty04_proof->s = NULL;
  proof->scheme = GROUPSIG_KTY04_CODE;
  proof->proof = kty04_proof;

  /* if(!(proof->c = bigz_init())) { */
  /*   free(proof); proof = NULL; */
  /*   return NULL; */
  /* } */

  /* if(!(proof->s = bigz_init())) { */
  /*   bigz_free(proof->c); */
  /*   free(proof); proof = NULL; */
  /*   return NULL; */
  /* } */

  return proof;

}

int kty04_proof_free(groupsig_proof_t *proof) {

  kty04_proof_t *kty04_proof;
  int rc;

  if(!proof || proof->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_proof_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  rc = IOK;
  kty04_proof = (kty04_proof_t *) proof->proof;

  rc += bigz_free(kty04_proof->c);
  rc += bigz_free(kty04_proof->s);
  mem_free(kty04_proof); kty04_proof = NULL;
  mem_free(proof);

  if(rc) rc = IERROR;

  return rc;

}

int kty04_proof_init_set_c(kty04_proof_t *proof, bigz_t c) {

  if(!proof || !c) {
    LOG_EINVAL(&logger, __FILE__, "kty04_proof_init_set_c", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(proof->c = bigz_init_set(c))) {
    return IERROR;
  }

  return IOK;

}

int kty04_proof_init_set_s(kty04_proof_t *proof, bigz_t s) {

  if(!proof || !s) {
    LOG_EINVAL(&logger, __FILE__, "kty04_proof_init_set_s", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(proof->s = bigz_init_set(s))) {
    return IERROR;
  }

  return IOK;

}

/* void* kty04_proof_copy(void *s) { */

/*   kty04_proof_t *cproof, *proof; */

/*   if(!s) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_proof_copy", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   proof = (kty04_proof_t *) s; */
/*   if(proof->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_proof_copy", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */
/*   cproof = NULL; */

/*   /\* Initialize the proof contents *\/ */
/*   if(!(cproof = (kty04_proof_t *) malloc(sizeof(kty04_proof_t)))) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "kty04_proof_copy", __LINE__, errno, LOGERROR); */
/*     return NULL; */
/*   } */

/*   cproof->c = NULL; cproof->s = NULL; */

/*   if(!(cproof->c = bigz_init_set(proof->c))) { */
/*     free(cproof); cproof = NULL; */
/*     return NULL; */
/*   } */

/*   if(!(cproof->s = bigz_init_set(proof->s))) { */
/*     bigz_free(cproof->c); */
/*     free(cproof); cproof = NULL; */
/*     return NULL; */
/*   } */

/*   return cproof; */

/* } */

char* kty04_proof_to_string(groupsig_proof_t *proof) {

  kty04_proof_t *kty04_proof;
  char *sc, *ss, *sproof;
  uint32_t size, offset;

  if(!proof || proof->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_proof_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  sc=NULL; ss=NULL; sproof=NULL;
  size = 2;
  kty04_proof = (kty04_proof_t *) proof->proof;

  /* Get the strings of each of the fields */
  if(!(sc = bigz_get_str10(kty04_proof->c))) return NULL;
  size += strlen(sc)+strlen("c: \n");

  if(!(ss = bigz_get_str10(kty04_proof->s))) {
    free(sc); sc = NULL;
    return NULL;
  }
  size += strlen(ss)+strlen("s: \n");

  if(!(sproof = (char *) malloc(sizeof(char)*size))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_proof_to_string", __LINE__, errno, LOGERROR);
    free(sc); sc = NULL;
    free(ss); ss = NULL;
    return NULL;
  }

  memset(sproof, 0, sizeof(char)*size);

  /* Dump everything */
  sprintf(sproof, "c: %s\n", sc);
  offset = strlen(sc)+strlen("c: \n");
  sprintf(sproof, "s: %s\n", ss);
  offset = strlen(ss)+strlen("s: \n");

  sprintf(&sproof[offset], "\n");
  offset++;

  /* Free everything */
  if(sc) { free(sc); sc = NULL; }
  if(ss) { free(ss); ss = NULL; }

  return sproof;

}

int kty04_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof) {

  int _size, rc, ctr, i;
  size_t len;
  uint8_t code, type;
  byte_t *_bytes, *__bytes, *aux_bytes;
  kty04_proof_t *kty04_proof;

  if(!proof || proof->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_proof_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  kty04_proof = proof->proof;

  /* Get the number of bytes to represent the proof */
  if ((_size = kty04_proof_get_size(proof)) == -1) {
    return IERROR;
  }

  /* 1 byte for the size of each bigz */
  _size += 2;

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump c */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_proof->c, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_proof_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump s */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_proof->s, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_proof_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_signature_export", __LINE__,
          EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, kty04_proof_export);
  }

  *size = ctr;

  kty04_proof_export_end:

   if (rc == IERROR) {
     if(_bytes) { mem_free(_bytes); _bytes = NULL; }
   }

   return rc;

}

groupsig_proof_t* kty04_proof_import(byte_t *source, uint32_t size) {

  int rc, ctr;
  groupsig_proof_t *proof;
  kty04_proof_t *kty04_proof;
  byte_t len, scheme;

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "kty04_proof_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(proof = kty04_proof_init())) {
    return NULL;
  }

  kty04_proof = proof->proof;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != proof->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_proof_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, kty04_proof_import);
  }

  /* Get c */
  len = source[ctr++];
  kty04_proof->c = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get s */
  len = source[ctr++];
  kty04_proof->s = bigz_import(&source[ctr], len);
  ctr += len;

  kty04_proof_import_end:

   if(rc == IERROR && proof) { kty04_proof_free(proof); proof = NULL; }
   if(rc == IOK) return proof;

   return NULL;

}

int kty04_proof_get_size(groupsig_proof_t *proof) {

  uint64_t size;

  if(!proof || proof->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_proof_get_size", __LINE__, LOGERROR);
    return -1;
  }

  /* Scheme tag */
  size = 1;
  size += bigz_sizeinbits(((kty04_proof_t *)(proof->proof))->c)/8;
  size += bigz_sizeinbits(((kty04_proof_t *)(proof->proof))->s)/8;
  /* Extra sign byte for each bigz */
  size += 2;

  return (int) size;


}

/* proof.c ends here */
