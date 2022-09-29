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

#include "kty04.h"
#include "groupsig/kty04/mem_key.h"
#include "shim/base64.h"
#include "misc/misc.h"
#include "sys/mem.h"

groupsig_key_t* kty04_mem_key_init() {

  kty04_mem_key_t *kty04_key;
  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) malloc(sizeof(groupsig_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(kty04_key = (kty04_mem_key_t *) malloc(sizeof(kty04_mem_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  kty04_key->A = NULL; kty04_key->C = NULL; kty04_key->x = NULL;
  kty04_key->xx = NULL, kty04_key->e = NULL;

  if(!(kty04_key->A = bigz_init())) goto init_error;
  if(!(kty04_key->C = bigz_init())) goto init_error;
  if(!(kty04_key->x = bigz_init())) goto init_error;
  if(!(kty04_key->xx = bigz_init())) goto init_error;
  if(!(kty04_key->e = bigz_init())) goto init_error;

  key->scheme = GROUPSIG_KTY04_CODE;
  key->key = kty04_key;

  return key;

 init_error:

  if(kty04_key->A) bigz_free(kty04_key->A);
  if(kty04_key->C) bigz_free(kty04_key->C);
  if(kty04_key->x) bigz_free(kty04_key->x);
  if(kty04_key->xx) bigz_free(kty04_key->xx);
  if(kty04_key->e) bigz_free(kty04_key->e);
  if(kty04_key) { free(kty04_key); kty04_key = NULL; }
  if(key) { free(key); key = NULL; }

  return NULL;

}

int kty04_mem_key_free(groupsig_key_t *key) {

  kty04_mem_key_t *kty04_key;
  int rc;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_mem_key_free", __LINE__,
       "Nothing to free.", LOGERROR);
    return IERROR;
  }

  rc = IOK;
  kty04_key = (kty04_mem_key_t *) key->key;

  rc += bigz_free(kty04_key->A);
  rc += bigz_free(kty04_key->C);
  rc += bigz_free(kty04_key->x);
  rc += bigz_free(kty04_key->xx);
  rc += bigz_free(kty04_key->e);

  free(kty04_key); kty04_key = NULL;
  free(key);

  if(rc != IOK) rc = IERROR;

  return rc;

}

int kty04_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  kty04_mem_key_t *dkey, *skey;

  if(!dst  || dst->scheme != GROUPSIG_KTY04_CODE ||
     !src  || src->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  dkey = (kty04_mem_key_t *) dst->key;
  skey = (kty04_mem_key_t *) src->key;

  if(bigz_set(dkey->A, skey->A) == IERROR)
    return IERROR;

  if(bigz_set(dkey->C, skey->C) == IERROR)
    return IERROR;

  if(bigz_set(dkey->x, skey->x) == IERROR)
    return IERROR;

  if(bigz_set(dkey->xx, skey->xx) == IERROR)
    return IERROR;

  if(bigz_set(dkey->e, skey->e) == IERROR)
    return IERROR;

  dst->scheme = GROUPSIG_KTY04_CODE;
  dst->key = dkey;

  return IOK;

}

int kty04_mem_key_get_size(groupsig_key_t *key) {

  uint64_t size;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  size = 0;
  size += bigz_sizeinbits(((kty04_mem_key_t*)key->key)->A)/8;
  if(bigz_sizeinbits(((kty04_mem_key_t*)key->key)->A) % 8 != 0) {
    size += 1;
  }
  size += bigz_sizeinbits(((kty04_mem_key_t*)key->key)->C)/8;
  if(bigz_sizeinbits(((kty04_mem_key_t*)key->key)->C) % 8 != 0) {
    size += 1;
  }
  size += bigz_sizeinbits(((kty04_mem_key_t*)key->key)->x)/8;
  if(bigz_sizeinbits(((kty04_mem_key_t*)key->key)->x) % 8 != 0) {
    size += 1;
  }
  size += bigz_sizeinbits(((kty04_mem_key_t*)key->key)->xx)/8;
  if(bigz_sizeinbits(((kty04_mem_key_t*)key->key)->xx) % 8 != 0) {
    size += 1;
  }
  size += bigz_sizeinbits(((kty04_mem_key_t*)key->key)->e)/8;
  if(bigz_sizeinbits(((kty04_mem_key_t*)key->key)->e) % 8 != 0) {
    size += 1;
  }
  /* Extra sign byte for each element */
  size += 5;


  return (int) size;

}

groupsig_key_t* kty04_mem_key_get_prv(groupsig_key_t *key) {

  groupsig_key_t *prv_key;
  kty04_mem_key_t *kty04_prv_key, *kty04_key;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_get_prv", __LINE__, LOGERROR);
    return NULL;
  }

  kty04_key = (kty04_mem_key_t *) key->key;

  if(!(prv_key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_get_prv", __LINE__, errno, LOGERROR);
    return NULL;
  }

  /* The private part of the member key is the x' (xx) value */
  if(!(kty04_prv_key = (kty04_mem_key_t *) mem_malloc(sizeof(kty04_mem_key_t)))) {
    mem_free(prv_key); prv_key = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_get_prv", __LINE__, errno, LOGERROR);
    return NULL;
  }

  /* Initialize and set the xx field */
  if(!(kty04_prv_key->xx = bigz_init_set(kty04_key->xx))) {
    mem_free(prv_key); prv_key = NULL;
    free(kty04_prv_key); kty04_prv_key = NULL;
    return NULL;
  }

  /* Set the remaining elements to NULL */
  kty04_prv_key->A = NULL;
  kty04_prv_key->C = NULL;
  kty04_prv_key->x = NULL;
  kty04_prv_key->e = NULL;

  prv_key->scheme = GROUPSIG_KTY04_CODE;
  prv_key->key = kty04_prv_key;

  return prv_key;

}

groupsig_key_t* kty04_mem_key_get_pub(groupsig_key_t *key) {

  groupsig_key_t *pub_key;
  kty04_mem_key_t *kty04_pub_key, *kty04_key;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_get_pub", __LINE__, LOGERROR);
    return NULL;
  }

  kty04_key = (kty04_mem_key_t *) key->key;

  if(!(pub_key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_get_pub", __LINE__, errno, LOGERROR);
    return NULL;
  }


  /* The public part of the member key are all fields except x' (xx) */
  if(!(kty04_pub_key = (kty04_mem_key_t *) malloc(sizeof(kty04_mem_key_t)))) {
    mem_free(pub_key); pub_key = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_get_pub", __LINE__, errno, LOGERROR);
    return NULL;
  }

  /* Initialize and set the fields */
  if(!(kty04_pub_key->A = bigz_init_set(kty04_key->A))) {
    free(pub_key); pub_key = NULL;
    free(kty04_pub_key); kty04_pub_key = NULL;
    return NULL;
  }

  if(!(kty04_pub_key->C = bigz_init_set(kty04_key->C))) {
    bigz_free(kty04_pub_key->A);
    free(pub_key); pub_key = NULL;
    free(kty04_pub_key); kty04_pub_key = NULL;
    return NULL;
  }

  if(!(kty04_pub_key->x = bigz_init_set(kty04_key->x))) {
    bigz_free(kty04_pub_key->A); bigz_free(kty04_pub_key->C);
    free(pub_key); pub_key = NULL;
    free(kty04_pub_key); kty04_pub_key = NULL;
    return NULL;
  }

  if(!(kty04_pub_key->e = bigz_init_set(kty04_key->e))) {
    bigz_free(kty04_pub_key->A); bigz_free(kty04_pub_key->C);
    bigz_free(kty04_pub_key->e);
    free(pub_key); pub_key = NULL;
    free(kty04_pub_key); kty04_pub_key = NULL;
    return NULL;
  }

  /* Set the remaining elements to NULL */
  kty04_pub_key->xx = NULL;

  pub_key->scheme = GROUPSIG_KTY04_CODE;
  pub_key->key = kty04_pub_key;

  return pub_key;

}

/* int mem_key_set_prv(kty04_mem_key_t *dst, kty04_mem_key_t *src); */
/* int mem_key_set_pub(kty04_mem_key_t *dst, kty04_mem_key_t *src); */

char* kty04_mem_key_to_string(groupsig_key_t *key) {

  kty04_mem_key_t *kty04_key;
  char *sA, *sC, *sx, *sxx, *se, *skey;
  uint32_t length;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  sA=NULL; sC=NULL; sx=NULL; sxx=NULL; se=NULL; skey=NULL;
  kty04_key = (kty04_mem_key_t *) key->key;

  sA = bigz_get_str10(kty04_key->A);
  sC = bigz_get_str10(kty04_key->C);
  sx = bigz_get_str10(kty04_key->x);
  sxx = bigz_get_str10(kty04_key->xx);
  se = bigz_get_str10(kty04_key->e);

  if(!sA || !sC || !sx || !sxx || !se) {
    goto to_string_error;
  }

  length = strlen(sA)+strlen("A: \n")+strlen(sC)+strlen("C: \n")+
    strlen(sx)+strlen("x: \n")+strlen(sxx)+strlen("x': \n")+
    strlen(se)+strlen("e: \n");

  if(!(skey = (char *) malloc(sizeof(char)*(length+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_to_string", __LINE__,
      errno, LOGERROR);
    goto to_string_error;
  }

  memset(skey, 0, sizeof(char)*(length+1));

  sprintf(skey,
    "A: %s\n"
    "C: %s\n"
    "x: %s\n"
    "x': %s\n"
    "e: %s\n\n",
    sA, sC, sx, sxx, se);

 to_string_error:

  if(sA) { free(sA); sA = NULL; }
  if(sC) { free(sC); sC = NULL; }
  if(sx) { free(sx); sx = NULL; }
  if(sxx) { free(sxx); sxx = NULL; }
  if(se) { free(se); se = NULL; }

  return skey;

}

char* kty04_mem_key_prv_to_string(groupsig_key_t *key) {

  kty04_mem_key_t *kty04_key;
  char *sxx, *skey;
  uint32_t length;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_prv_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  sxx=NULL; skey=NULL;
  kty04_key = (kty04_mem_key_t *) key->key;

  if(!(sxx = bigz_get_str10(kty04_key->xx))) {
    return NULL;
  }

  length = strlen(sxx)+strlen("x': \n");

  if(!(skey = (char *) malloc(sizeof(char)*(length+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_prv_to_string", __LINE__,
      errno, LOGERROR);
    free(sxx); sxx = NULL;
    return NULL;
  }

  memset(skey, 0, sizeof(char)*(length+1));
  sprintf(skey, "x': %s\n", sxx);

  mem_free(sxx); sxx = NULL;

  return skey;

}

char* kty04_mem_key_pub_to_string(groupsig_key_t *key) {

  kty04_mem_key_t *kty04_key;
  char *sA, *sC, *sx, *se, *skey;
  uint32_t length;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_pub_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  sA=NULL; sC=NULL; sx=NULL; se=NULL; skey=NULL;
  kty04_key = (kty04_mem_key_t *) key->key;

  sA = bigz_get_str10(kty04_key->A);
  sC = bigz_get_str10(kty04_key->C);
  sx = bigz_get_str10(kty04_key->x);
  se = bigz_get_str10(kty04_key->e);

  if(!sA || !sC || !sx || !se) goto mem_key_pub_to_string_end;

  length = strlen(sA)+strlen("A: \n")+strlen(sC)+strlen("C: \n")+
    strlen(sx)+strlen("x: \n")+strlen(se)+strlen("e: \n");

  if(!(skey = (char *) malloc(sizeof(char)*(length+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_pub_to_string", __LINE__,
      errno, LOGERROR);
    goto mem_key_pub_to_string_end;
  }

  memset(skey, 0, sizeof(char)*(length+1));

  sprintf(skey,
    "A: %s\n"
    "C: %s\n"
    "x: %s\n"
    "e: %s\n\n",
    sA, sC, sx, se);

 mem_key_pub_to_string_end:

  if(sA) { mem_free(sA); sA = NULL; }
  if(sC) { mem_free(sC); sC = NULL; }
  if(sx) { mem_free(sx); sx = NULL; }
  if(se) { mem_free(se); se = NULL; }

  return skey;

}

int kty04_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  int _size, rc, ctr, i;
  size_t len;
  uint8_t code, type;
  byte_t *_bytes, *__bytes, *aux_bytes;
  kty04_mem_key_t *kty04_key;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }
  rc = IOK;
  ctr = 0;
  kty04_key = key->key;

  /* Get the number of bytes to represent the key */
  if ((_size = kty04_mem_key_get_size(key)) == -1) {
    return IERROR;
  }

  /* 1 byte for the length of each bigz */
  _size += 5;
  /* 1 byte for the length of the groupsig code and another for the keytype */
  _size += 2;

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_KTY04_CODE */
  code = GROUPSIG_KTY04_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_MEMKEY;
  _bytes[ctr++] = GROUPSIG_KEY_MEMKEY;

  /* Dump A */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->A, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_mem_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i - 1];
    ctr++;
  }
  free(aux_bytes);

  /* Dump C */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->C, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_mem_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i - 1];
    ctr++;
  }
  free(aux_bytes);

  /* Dump x */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->x, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_mem_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i - 1];
    ctr++;
  }
  free(aux_bytes);

  /* Dump xx */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->xx, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_mem_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i - 1];
    ctr++;
  }
  free(aux_bytes);

  /* Dump e */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->e, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_mem_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i - 1];
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_mem_key_export", __LINE__,
          EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, kty04_mem_key_export);
  }

  *size = ctr;

  kty04_mem_key_export_end:

   if (rc == IERROR) {
     if(_bytes) { mem_free(_bytes); _bytes = NULL; }
   }

   return rc;


}

int kty04_mem_key_export_pub(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  groupsig_key_t *pub_key;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_export_pub", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(pub_key = kty04_mem_key_get_pub(key))) {
    return IERROR;
  }

  if(kty04_mem_key_export(bytes, size, pub_key) == IERROR) {
    kty04_mem_key_free(pub_key);
    return IERROR;
  }

  kty04_mem_key_free(pub_key);

  return IOK;

}

int kty04_mem_key_export_prv(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  groupsig_key_t *prv_key;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_export_prv", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(prv_key = kty04_mem_key_get_prv(key))) {
    return IERROR;
  }

  if(kty04_mem_key_export(bytes, size, prv_key) == IERROR) {
    kty04_mem_key_free(prv_key);
    return IERROR;
  }

  kty04_mem_key_free(prv_key);

  return IOK;

}

groupsig_key_t* kty04_mem_key_import(byte_t *source, uint32_t size) {

  int rc, ctr;
  groupsig_key_t *key;
  kty04_mem_key_t *kty04_key;
  byte_t len, scheme, type;


  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(key = kty04_mem_key_init())) {
    return NULL;
  }

  kty04_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_mem_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, kty04_mem_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MEMKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_mem_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, kty04_mem_key_import);
  }

  /* Get A */
  len = source[ctr++];
  kty04_key->A = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get C */
  len = source[ctr++];
  kty04_key->C = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get x */
  len = source[ctr++];
  kty04_key->x = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get xx */
  len = source[ctr++];
  kty04_key->xx = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get e */
  len = source[ctr++];
  kty04_key->e = bigz_import(&source[ctr], len);
  ctr += len;

 kty04_mem_key_import_end:

  if(rc == IERROR && key) { kty04_mem_key_free(key); key = NULL; }
  if(rc == IOK) return key;

  return NULL;


}

groupsig_key_t* kty04_mem_key_import_prv(byte_t *source, uint32_t size) {

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_import_prv", __LINE__, LOGERROR);
    return NULL;
  }

  /** @todo This may also be returning the public part! */
  return kty04_mem_key_import(source, size);

}

groupsig_key_t* kty04_mem_key_import_pub(byte_t *source, uint32_t size) {

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_import_pub", __LINE__, LOGERROR);
    return NULL;
  }

  /** @todo This may also be returning the private part! */
  return kty04_mem_key_import(source, size);

}

/* mem_key.c ends here */
