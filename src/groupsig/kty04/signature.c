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
#include "groupsig/kty04/signature.h"

/* Private constants */
#define _INDEX_LENGTH 10

/* Public functions */
groupsig_signature_t* kty04_signature_init() {

  groupsig_signature_t *sig;
  kty04_signature_t *kty04_sig;
  uint32_t i;
  int rc;

  kty04_sig = NULL;
  rc = IOK;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_init", __LINE__, errno,
		  LOGERROR);
  }

  if(!(kty04_sig = (kty04_signature_t *) mem_malloc(sizeof(kty04_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_init", __LINE__, errno,
		  LOGERROR);
    return NULL;
  }

  kty04_sig->c = NULL; kty04_sig->A = NULL; kty04_sig->sw = NULL;

  if(!(kty04_sig->c = bigz_init())) GOTOENDRC(IERROR, kty04_signature_init);

  /* Initialize the A's */
  kty04_sig->m = KTY04_SIGNATURE_M;
  if(!(kty04_sig->A = (bigz_t *) malloc(sizeof(bigz_t)*kty04_sig->m))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_init", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_signature_init);
  }
  memset(kty04_sig->A, 0, sizeof(bigz_t)*kty04_sig->m);

  for(i=0; i<kty04_sig->m; i++) {
    if(!(kty04_sig->A[i] = bigz_init())) GOTOENDRC(IERROR, kty04_signature_init);
  }

  /* Set the number of relations to the default */
  kty04_sig->z = KTY04_SIGNATURE_Z;

  /* Initialize the sw's */
  kty04_sig->r = KTY04_SIGNATURE_R;
  if(!(kty04_sig->sw = (bigz_t *) malloc(sizeof(bigz_t)*kty04_sig->r))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_init", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_signature_init);
  }
  memset(kty04_sig->sw, 0, sizeof(bigz_t)*kty04_sig->r);

  for(i=0; i<kty04_sig->r; i++) {
    if(!(kty04_sig->sw[i] = bigz_init())) GOTOENDRC(IERROR, kty04_signature_init);
  }

  sig->scheme = GROUPSIG_KTY04_CODE;
  sig->sig = kty04_sig;

 kty04_signature_init_end:

  if(rc == IERROR) {
    if(kty04_sig->c) bigz_free(kty04_sig->c);
    if(kty04_sig->A) for(i=0; i<kty04_sig->m; i++) bigz_free(kty04_sig->A[i]);
    if(kty04_sig->sw) for(i=0; i<kty04_sig->r; i++) bigz_free(kty04_sig->sw[i]);
    if(kty04_sig) { free(kty04_sig); kty04_sig = NULL; }
    if(sig) { free(sig); sig = NULL; }
  }

  return sig;

}

int kty04_signature_free(groupsig_signature_t *sig) {

  kty04_signature_t *kty04_sig;
  uint32_t i;
  int rc;

  if(!sig || sig->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  rc = IOK;
  kty04_sig = (kty04_signature_t *) sig->sig;

  /* Free the c */
  rc += bigz_free(kty04_sig->c);

  /* Free the A's */
  if(kty04_sig->A) {
    for(i=0; i<kty04_sig->m; i++) {
      rc += bigz_free(kty04_sig->A[i]);
    }
    free(kty04_sig->A); kty04_sig->A = NULL;
  }

  /* Free the sw's */
  if(kty04_sig->sw) {
    for(i=0; i<kty04_sig->r; i++) {
      rc += bigz_free(kty04_sig->sw[i]);
    }
    free(kty04_sig->sw); kty04_sig->sw = NULL;
  }

  free(kty04_sig); kty04_sig = NULL;
  free(sig);

  if(rc) return IERROR;
  return IOK;

}

int kty04_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  kty04_signature_t *kty04_dst, *kty04_src;
  uint32_t i;

  if(!dst || dst->scheme != GROUPSIG_KTY04_CODE ||
     !src || src->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  kty04_src = (kty04_signature_t *) src->sig;
  kty04_dst = (kty04_signature_t *) dst->sig;

  /* Initialize the signature contents */
  if(bigz_set(kty04_dst->c, kty04_src->c) == IERROR)
    return IERROR;

  /* Initialize the A's */
  kty04_dst->m = kty04_src->m;
  for(i=0; i<kty04_dst->m; i++) {
    if(bigz_set(kty04_dst->A[i], kty04_src->A[i]) == IERROR)
      return IERROR;
  }

  /* Set the number of relations to the default */
  kty04_dst->z = kty04_src->z;

  /* Initialize the sw's */
  kty04_dst->r = kty04_src->r;
  for(i=0; i<kty04_dst->r; i++) {
    if(bigz_set(kty04_dst->sw[i], kty04_src->sw[i]) == IERROR)
      return IERROR;
  }

  return IOK;

}

char* kty04_signature_to_string(groupsig_signature_t *sig) {

  kty04_signature_t *kty04_sig;
  char *sc, **ssw, **sA, *ssig;
  uint32_t i, size, offset;
  int rc;

  if(!sig || sig->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  sc=NULL; ssw=NULL; sA=NULL; ssig=NULL;
  size = 0;
  rc = IOK;
  kty04_sig = (kty04_signature_t *) sig->sig;

  /* Get the strings of each of the fields */
  if(!(sc = bigz_get_str10(kty04_sig->c))) GOTOENDRC(IERROR, kty04_signature_to_string);
  size += strlen(sc)+strlen("c: \n");

  if(!(sA = (char **) malloc(sizeof(char *)*kty04_sig->m))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_to_string", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_signature_to_string);
  }
  memset(sA, 0, sizeof(char *)*kty04_sig->m);

  /* We give the indexes an arbitrary size of 10 decimal digits (chars). If they
     are bigger, they will be truncated. 10 seems much more than enough and
     using a fixed size makes things much easier... */
  for(i=0; i<kty04_sig->m; i++) {
    if(!(sA[i] = bigz_get_str10(kty04_sig->A[i]))) return NULL;
    size += strlen(sA[i])+strlen("A[]: \n")+_INDEX_LENGTH;
  }
  size += 1;

  if(!(ssw = (char **) malloc(sizeof(char *)*kty04_sig->r))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_to_string", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_signature_to_string);
  }
  memset(ssw, 0, sizeof(char *)*kty04_sig->r);

  for(i=0; i<kty04_sig->r; i++) {
    if(!(ssw[i] = bigz_get_str10(kty04_sig->sw[i]))) return NULL;
    size += strlen(ssw[i])+strlen("s[]: \n")+_INDEX_LENGTH;
  }
  size += 1;

  if(!(ssig = (char *) malloc(sizeof(char)*size))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_to_string", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_signature_to_string);
  }
  memset(ssig, 0, sizeof(char)*size);

  /* Dump everything */
  sprintf(ssig, "c: %s\n", sc);
  offset = strlen(sc)+strlen("c: \n");

  for(i=0; i<kty04_sig->m; i++) {
    sprintf(&ssig[offset], "A[%u]: %s\n", i, sA[i]);
    offset += strlen(sA[i])+strlen("A[ ]: \n");
  }
  sprintf(&ssig[offset], "\n");
  offset++;

  for(i=0; i<kty04_sig->r; i++) {
    sprintf(&ssig[offset], "s[%u]: %s\n", i, ssw[i]);
    offset += strlen(ssw[i])+strlen("s[ ]: \n");
  }
  sprintf(&ssig[offset], "\n");
  offset++;

 kty04_signature_to_string_end:

  /* Free everything */
  if(sc) { free(sc); sc = NULL; }

  if(sA) {
    for(i=0; i<kty04_sig->m; i++) {
      free(sA[i]); sA[i] = NULL;
    }
    free(sA); sA = NULL;
  }

  if(ssw) {
    for(i=0; i<kty04_sig->r; i++) {
      free(ssw[i]); ssw[i] = NULL;
    }
    free(ssw); ssw = NULL;
  }

  if(rc == IERROR) {
    if(ssig) { free(ssig); ssig = NULL; }
  }

  return ssig;

}

int kty04_signature_get_size(groupsig_signature_t *sig) {

  uint64_t size;
  int i;

  if(!sig || sig->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_signature_get_size", __LINE__, LOGERROR);
    return -1;
  }

  size = 0;
  size += sizeof(uint8_t);
  size += bigz_sizeinbits(((kty04_signature_t*)sig->sig)->c)/8;
  for(i = 0; i < ((kty04_signature_t*)sig->sig)->m; i++) {
    size += bigz_sizeinbits(((kty04_signature_t*)sig->sig)->A[i])/8;
  }
  for(i = 0; i < ((kty04_signature_t*)sig->sig)->r; i++) {
    size += bigz_sizeinbits(((kty04_signature_t*)sig->sig)->sw[i])/8;
  }
  size += sizeof(uint64_t)*3;
  /* Extra sign byte for each bigz */
  size += 1 + ((kty04_signature_t*) sig->sig)->m + ((kty04_signature_t*) sig->sig)->r;

  return (int) size;

}

int kty04_signature_export(byte_t **bytes, uint32_t *size, groupsig_signature_t *signature) {

  int _size, rc, ctr, i;
  size_t len;
  uint8_t code, type;
  byte_t *_bytes, *__bytes, *aux_bytes;
  kty04_signature_t *kty04_signature;

  if(!signature || signature->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  kty04_signature = (kty04_signature_t*) signature->sig;

  /* Get the number of bytes to represent the key */
  if ((_size = kty04_signature_get_size(signature)) == -1) {
    return IERROR;
  }

  /* 1 byte for the size of each bigz */
  _size += 1 + kty04_signature->m + kty04_signature->r;

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_KTY04_CODE */
  code = GROUPSIG_KTY04_CODE;
  _bytes[ctr++] = code;

  /* Dump m */
  __bytes = &_bytes[ctr];
  for(i=0; i<4; i++){
    __bytes[i] = (kty04_signature->m >> 3-i) && 0xFF;
    ctr++;
  }

  /* Dump z */
  __bytes = &_bytes[ctr];
  for(i=0; i<4; i++){
    __bytes[i] = (kty04_signature->z >> 3-i) && 0xFF;
    ctr++;
  }

  /* Dump r */
  __bytes = &_bytes[ctr];
  for(i=0; i<4; i++){
    __bytes[i] = (kty04_signature->r >> 3-i) && 0xFF;
    ctr++;
  }

  /* Dump c */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_signature->c, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_signature_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump A */
  for(i = 0; i < kty04_signature->m; i++) {
    __bytes = &_bytes[ctr];
    aux_bytes = bigz_export(kty04_signature->A[i], &len);
    if(!aux_bytes) GOTOENDRC(IERROR, kty04_signature_export);
    __bytes[0] = (byte_t) len;
    ctr++;
    for(i = 1; i < len + 1; i++){
      __bytes[i] = aux_bytes[i];
      ctr++;
    }
    free(aux_bytes);
  }

  /* Dump sw */
  for(i = 0; i < kty04_signature->r; i++) {
    __bytes = &_bytes[ctr];
    aux_bytes = bigz_export(kty04_signature->sw[i], &len);
    if(!aux_bytes) GOTOENDRC(IERROR, kty04_signature_export);
    __bytes[0] = (byte_t) len;
    ctr++;
    for(i = 1; i < len + 1; i++){
      __bytes[i] = aux_bytes[i];
      ctr++;
    }
    free(aux_bytes);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_signature_export", __LINE__,
          EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, kty04_signature_export);
  }

  *size = ctr;

  kty04_signature_export_end:

   if (rc == IERROR) {
     if(_bytes) { mem_free(_bytes); _bytes = NULL; }
   }

   return rc;

}

groupsig_signature_t* kty04_signature_import(byte_t *source, uint32_t size) {

  int rc, ctr, i;
  groupsig_signature_t *signature;
  kty04_signature_t *kty04_signature;
  byte_t len, scheme;

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "kty04_signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(signature = kty04_signature_init())) {
    return NULL;
  }

  kty04_signature = signature->sig;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != signature->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_signature_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, kty04_signature_import);
  }

  /* Get m */
  for(i=0; i<4; i++){
    kty04_signature->m = kty04_signature->m << 8;
    kty04_signature->m = kty04_signature->m + source[ctr+i];
  }
  ctr += 4;

  /* Get z */
  for(i=0; i<4; i++){
    kty04_signature->z = kty04_signature->z << 8;
    kty04_signature->z = kty04_signature->z + source[ctr+i];
  }
  ctr += 4;

  /* Get r */
  for(i=0; i<4; i++){
    kty04_signature->r = kty04_signature->r << 8;
    kty04_signature->r = kty04_signature->r + source[ctr+i];
  }
  ctr += 4;

  /* Get c */
  len = source[ctr++];
  kty04_signature->c = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get A */
  for(i = 0; i < kty04_signature->m; i++) {
    len = source[ctr++];
    kty04_signature->A[i] = bigz_import(&source[ctr], len);
    ctr += len;
  }

  /* Get sw */
  for(i = 0; i < kty04_signature->r; i++) {
    len = source[ctr++];
    kty04_signature->sw[i] = bigz_import(&source[ctr], len);
    ctr += len;
  }
  kty04_signature_import_end:

   if(rc == IERROR && signature) { kty04_signature_free(signature); signature = NULL; }
   if(rc == IOK) return signature;

   return NULL;

}

/* signature.c ends here */
