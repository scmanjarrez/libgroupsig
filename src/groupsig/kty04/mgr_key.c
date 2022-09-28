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

#include "kty04.h"
#include "groupsig/kty04/mgr_key.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "sys/mem.h"

/* public functions */

groupsig_key_t* kty04_mgr_key_init() {

  groupsig_key_t *key;
  kty04_mgr_key_t *kty04_key;

  if(!(key = (groupsig_key_t *) malloc(sizeof(groupsig_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mgr_key_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(kty04_key = (kty04_mgr_key_t *) malloc(sizeof(kty04_mgr_key_t)))) {
    free(key); key = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mgr_key_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(kty04_key->p = bigz_init())) {
    free(key); key = NULL;
    free(kty04_key); kty04_key = NULL;
    return NULL;
  }

  if(!(kty04_key->q = bigz_init())) {
    bigz_free(kty04_key->p);
    free(kty04_key); kty04_key = NULL;
    free(key); key = NULL;
    return NULL;
  }

  if(!(kty04_key->x = bigz_init())) {
    bigz_free(kty04_key->p); bigz_free(kty04_key->q);
    free(kty04_key); kty04_key = NULL;
    free(key); key = NULL;
    return NULL;
  }

  kty04_key->nu = 0;

  key->scheme = GROUPSIG_KTY04_CODE;
  key->key = kty04_key;

  return key;

}

int kty04_mgr_key_free(groupsig_key_t *key) {

  kty04_mgr_key_t *kty04_key;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
  LOG_EINVAL_MSG(&logger, __FILE__, "kty04_mgr_key_free", __LINE__,
		 "Nothing to free.", LOGWARN);
    return IERROR;
  }

  kty04_key = (kty04_mgr_key_t *) key->key;

  if(kty04_key->p) { bigz_free(kty04_key->p); kty04_key->p = NULL; }
  if(kty04_key->q) { bigz_free(kty04_key->q); kty04_key->q = NULL; }
  if(kty04_key->x) { bigz_free(kty04_key->x); kty04_key->x = NULL; }

  free(kty04_key); kty04_key = NULL;
  free(key);

  return IOK;

}

int kty04_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  kty04_mgr_key_t *kty04_dst, *kty04_src;

  if(!dst || dst->scheme != GROUPSIG_KTY04_CODE ||
     !src || src->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  kty04_dst = (kty04_mgr_key_t *) dst->key;
  kty04_src = (kty04_mgr_key_t *) src->key;

  if(bigz_set(kty04_dst->p, kty04_src->p) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->q, kty04_src->q) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->x, kty04_src->x) == IERROR) return IERROR;
  kty04_dst->nu = kty04_src->nu;

  return IOK;

}

/* groupsig_key_t* kty04_mgr_key_get_prv(groupsig_key_t *key) { */

/*   if(!key || key->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_get_prv", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   /\* All the data in the key is private (except nu, which is  */
/*      only to save some computing time) *\/ */
/*   return key; */

/* } */

/* groupsig_key_t* kty04_mgr_key_get_pub(groupsig_key_t *key) { */

/*   if(!key || key->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_get_pub", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   /\* The manager key is completely private *\/ */
/*   return NULL; */

/* } */

/* int mgr_key_set_prv(kty04_mgr_key_t *dst, kty04_mgr_key_t *src); */
/* int mgr_key_set_pub(kty04_mgr_key_t *dst, kty04_mgr_key_t *src); */

int kty04_mgr_key_get_size(groupsig_key_t *key) {

  uint64_t size;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  size = 0;
  size += bigz_sizeinbits(((kty04_mgr_key_t *)(key->key))->p)/8;
  size += bigz_sizeinbits(((kty04_mgr_key_t *)(key->key))->q)/8;
  size += bigz_sizeinbits(((kty04_mgr_key_t *)(key->key))->x)/8;
  size += sizeof(uint64_t);
  /* Extra sign byte for each element */
  size += 3;

  return (int) size;

}

int kty04_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  int _size, rc, ctr, i;
  size_t len;
  uint8_t code, type;
  byte_t *_bytes, *__bytes, *aux_bytes;
  kty04_mgr_key_t *kty04_key;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  kty04_key = key->key;

  /* Get the number of bytes to represent the key */
  if ((_size = kty04_mgr_key_get_size(key)) == -1) {
    return IERROR;
  }

  /* 1 byte for the length of each bigz */
  _size += 3;

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_KTY04_CODE */
  code = GROUPSIG_KTY04_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_MGRKEY;
  _bytes[ctr++] = GROUPSIG_KEY_MGRKEY;

  /* Dump p */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->p, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_mgr_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump q */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->q, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_mgr_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump x */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->x, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_mgr_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump nu */
  __bytes = &_bytes[ctr];
  for(i=0; i<8; i++){
    __bytes[i] = (kty04_key->nu >> 7-i) && 0xFF;
    ctr++;
  }

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_mgr_key_export", __LINE__,
          EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, kty04_mgr_key_export);
  }

  *size = ctr;

  kty04_mgr_key_export_end:

   if (rc == IERROR) {
     if(_bytes) { mem_free(_bytes); _bytes = NULL; }
   }

   return rc;

}

/* int kty04_mgr_key_export_pub(groupsig_key_t *key, groupsig_key_format_t format, void *dst) { */

/*   if(!key || key->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_export_pub", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   return IERROR; */

/* } */

/* int kty04_mgr_key_export_prv(groupsig_key_t *key, groupsig_key_format_t format, void *dst) { */

/*   if(!key || key->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_export_prv", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   return kty04_mgr_key_export(key, format, dst); */

/* } */

groupsig_key_t* kty04_mgr_key_import(byte_t *source, uint32_t size) {

  int rc, ctr, i;
  groupsig_key_t *key;
  kty04_mgr_key_t *kty04_key;
  byte_t len, scheme, type;

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(key = kty04_mgr_key_init())) {
    return NULL;
  }

  kty04_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_mgr_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, kty04_mgr_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MGRKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_mgr_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, kty04_mgr_key_import);
  }

  /* Get p */
  len = source[ctr++];
  kty04_key->p = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get q */
  len = source[ctr++];
  kty04_key->q = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get x */
  len = source[ctr++];
  kty04_key->x = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get nu */
  for(i=0; i<8; i++){
    kty04_key->nu = kty04_key->nu << 8;
    kty04_key->nu = kty04_key->nu + source[ctr+i];
  }
  ctr += 8;

  kty04_mgr_key_import_end:

   if(rc == IERROR && key) { kty04_mgr_key_free(key); key = NULL; }
   if(rc == IOK) return key;

   return NULL;


}

/* groupsig_key_t* kty04_mgr_key_import_prv(groupsig_key_format_t format, void *source) { */
/*   return kty04_mgr_key_import(format, source); */
/* } */

/* groupsig_key_t* kty04_mgr_key_import_pub(groupsig_key_format_t format, void *source) { */

/*   if(!source) { */
/*     LOG_EINVAL(&logger, __FILE__, "mgr_key_import_pub", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   return NULL; */
/* } */

char* kty04_mgr_key_to_string(groupsig_key_t *key) {

  kty04_mgr_key_t *mkey;
  char *sp, *sq, *sx, *snu, *skey;
  uint32_t length;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  sp=NULL; sq=NULL; sx=NULL; snu=NULL; skey=NULL;
  mkey = (kty04_mgr_key_t *) key->key;

  if(!(sp = bigz_get_str10(mkey->p))) goto key_to_string_error;
  if(!(sq = bigz_get_str10(mkey->q))) goto key_to_string_error;
  if(!(sx = bigz_get_str10(mkey->x))) goto key_to_string_error;
  if(!(snu = misc_uint642string(mkey->nu))) goto key_to_string_error;

  length = strlen(sp)+strlen("p: \n")+strlen(sq)+strlen("q: \n")+
    strlen(sx)+strlen("x: \n")+strlen(snu)+strlen("nu: \n");

  if(!(skey = (char *) malloc(sizeof(char)*(length+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mgr_key_to_string", __LINE__,
		  errno, LOGERROR);
    goto key_to_string_error;
  }

  sprintf(skey,
	  "p: %s\n"
	  "q: %s\n"
	  "x: %s\n"
	  "nu: %s\n\n",
	  sp, sq, sx, snu);

 key_to_string_error:

  free(sp); sp = NULL;
  free(sq); sq = NULL;
  free(sx); sx = NULL;
  free(snu); snu = NULL;

  return skey;

}

/* char* kty04_mgr_key_prv_to_string(groupsig_key_t *key) { */

/*   if(!key || key->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_prv_to_string", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   return kty04_mgr_key_to_string(key); */

/* } */

/* char* kty04_mgr_key_pub_to_string(groupsig_key_t *key) { */

/*   if(!key || key->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_pub_to_string", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   /\* The manager key does not have public part *\/ */
/*   return NULL; */

/* } */

/* mgr_key.c ends here */
