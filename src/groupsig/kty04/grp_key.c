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

#include "sysenv.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "shim/base64.h"

#include "kty04.h"
#include "groupsig/kty04/grp_key.h"

/* Internal constants */
#define MAX_SNU 100
#define MAX_SEPSILON 100

/* static (private) functions */

static int _grp_key_free_spheres(kty04_grp_key_t *key) {

  int rc;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "_grp_key_free_spheres", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  rc = IOK;
  if(key->lambda) {
    rc += sphere_free(key->lambda);
  }

  if(key->M) {
    rc += sphere_free(key->M);
  }

  if(key->gamma) {
    rc += sphere_free(key->gamma);
  }

  if(key->inner_lambda) {
    rc += sphere_free(key->inner_lambda);
  }

  if(key->inner_M) {
    rc += sphere_free(key->inner_M);
  }

  if(key->inner_gamma) {
    rc += sphere_free(key->inner_gamma);
  }

  if(rc) rc = IERROR;

  return rc;

}


/* "Public" functions */

groupsig_key_t* kty04_grp_key_init() {

  groupsig_key_t *key;
  kty04_grp_key_t *kty04_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_grp_key_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(kty04_key = (kty04_grp_key_t *) malloc(sizeof(kty04_grp_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_grp_key_init", __LINE__, errno, LOGERROR);
    mem_free(key); key = NULL;
    return NULL;
  }

  kty04_key->n = NULL; kty04_key->a = NULL; kty04_key->a0 = NULL;
  kty04_key->b = NULL; kty04_key->b = NULL; kty04_key->g = NULL;
  kty04_key->h = NULL; kty04_key->y = NULL; kty04_key->epsilon = 0;
  kty04_key->nu = 0; kty04_key->k = 0; kty04_key->lambda = NULL;
  kty04_key->inner_lambda = NULL; kty04_key->M = NULL; kty04_key->inner_M = NULL;
  kty04_key->gamma = NULL; kty04_key->inner_gamma = NULL;

  if(!(kty04_key->n = bigz_init())) goto init_err;
  if(!(kty04_key->a = bigz_init())) goto init_err;
  if(!(kty04_key->a0 = bigz_init())) goto init_err;
  if(!(kty04_key->b = bigz_init())) goto init_err;
  if(!(kty04_key->g = bigz_init())) goto init_err;
  if(!(kty04_key->h = bigz_init())) goto init_err;
  if(!(kty04_key->y = bigz_init())) goto init_err;
  kty04_key->lambda = NULL;
  kty04_key->M = NULL;
  kty04_key->gamma = NULL;
  kty04_key->inner_lambda = NULL;
  kty04_key->inner_M = NULL;
  kty04_key->inner_gamma = NULL;

  key->scheme = GROUPSIG_KTY04_CODE;
  key->key = kty04_key;

  return key;

 init_err:

  if(kty04_key->n) bigz_free(kty04_key->n);
  if(kty04_key->a) bigz_free(kty04_key->a);
  if(kty04_key->a0) bigz_free(kty04_key->a0);
  if(kty04_key->b) bigz_free(kty04_key->b);
  if(kty04_key->g) bigz_free(kty04_key->g);
  if(kty04_key->h) bigz_free(kty04_key->h);
  if(kty04_key->y) bigz_free(kty04_key->y);
  if(kty04_key) { free(kty04_key); kty04_key = NULL; }
  if(key) { mem_free(key); key = NULL; }

  return NULL;

}

int kty04_grp_key_free(groupsig_key_t *key) {

  kty04_grp_key_t *kty04_key;
  int rc;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_grp_key_free", __LINE__, LOGWARN);
    return IERROR;
  }

  kty04_key = (kty04_grp_key_t *) key->key;
  rc = IOK;

  if(kty04_key->n) { rc += bigz_free(kty04_key->n); kty04_key->n = NULL; }
  if(kty04_key->a) { rc += bigz_free(kty04_key->a); kty04_key->a = NULL; }
  if(kty04_key->a0) { rc += bigz_free(kty04_key->a0); kty04_key->a0 = NULL; }
  if(kty04_key->b) { rc += bigz_free(kty04_key->b); kty04_key->b = NULL; }
  if(kty04_key->g) { rc += bigz_free(kty04_key->g); kty04_key->g = NULL; }
  if(kty04_key->h) { rc += bigz_free(kty04_key->h); kty04_key->h = NULL; }
  if(kty04_key->y) { rc += bigz_free(kty04_key->y); kty04_key->y = NULL; }

  rc += _grp_key_free_spheres(kty04_key);

  free(kty04_key); kty04_key = NULL;
  free(key);

  if(rc) rc = IERROR;

  return rc;

}

int kty04_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  kty04_grp_key_t *kty04_dst, *kty04_src;

  if(!dst || dst->scheme != GROUPSIG_KTY04_CODE ||
     !src || src->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_grp_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  kty04_dst = (kty04_grp_key_t *) dst->key;
  kty04_src = (kty04_grp_key_t *) src->key;

  if(bigz_set(kty04_dst->n, kty04_src->n) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->a, kty04_src->a) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->a0, kty04_src->a0) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->b, kty04_src->b) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->g, kty04_src->g) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->h, kty04_src->h) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->y, kty04_src->y) == IERROR) return IERROR;

  kty04_dst->epsilon = kty04_src->epsilon;
  kty04_dst->nu = kty04_src->nu;
  kty04_dst->k = kty04_src->k;

  /* Copy the spheres */

  /* Lambda */
  if(!(kty04_dst->lambda = sphere_init())) {
    return IERROR;
  }
  if(bigz_set(kty04_dst->lambda->center, kty04_src->lambda->center) == IERROR) {
    sphere_free(kty04_dst->lambda);
    return IERROR;
  }
  if(bigz_set(kty04_dst->lambda->radius, kty04_src->lambda->radius) == IERROR) {
    sphere_free(kty04_dst->lambda);
    return IERROR;
  }

  /* Inner lambda */
  if(!(kty04_dst->inner_lambda = sphere_init())) {
    sphere_free(kty04_dst->lambda);
    return IERROR;
  }
  if(bigz_set(kty04_dst->inner_lambda->center, kty04_src->inner_lambda->center) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    return IERROR;
  }
  if(bigz_set(kty04_dst->inner_lambda->radius, kty04_src->inner_lambda->radius) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    return IERROR;
  }

  /* M */
  if(!(kty04_dst->M = sphere_init())) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    return IERROR;
  }
  if(bigz_set(kty04_dst->M->center, kty04_src->M->center) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->M);
    return IERROR;
  }
  if(bigz_set(kty04_dst->M->radius, kty04_src->M->radius) == IERROR) {
    sphere_free(kty04_dst->inner_lambda);
    sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->M);
    return IERROR;
  }

  /* Inner M */
  if(!(kty04_dst->inner_M = sphere_init())) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->M);
    return IERROR;
  }
  if(bigz_set(kty04_dst->inner_M->center, kty04_src->inner_M->center) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    return IERROR;
  }
  if(bigz_set(kty04_dst->inner_M->radius, kty04_src->inner_M->radius) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    return IERROR;
  }

  /* Gamma */
  if(!(kty04_dst->gamma = sphere_init())) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    return IERROR;
  }
  if(bigz_set(kty04_dst->gamma->center, kty04_src->gamma->center) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    sphere_free(kty04_dst->gamma);
    return IERROR;
  }
  if(bigz_set(kty04_dst->gamma->radius, kty04_src->gamma->radius) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    sphere_free(kty04_dst->gamma);
    return IERROR;
  }

  /* Inner gamma */
  if(!(kty04_dst->inner_gamma = sphere_init())) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    sphere_free(kty04_dst->gamma);
    return IERROR;
  }
  if(bigz_set(kty04_dst->inner_gamma->center, kty04_src->inner_gamma->center) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    sphere_free(kty04_dst->inner_gamma); sphere_free(kty04_dst->gamma);
    return IERROR;
  }
  if(bigz_set(kty04_dst->inner_gamma->radius, kty04_src->inner_gamma->radius) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    sphere_free(kty04_dst->inner_gamma); sphere_free(kty04_dst->gamma);
    return IERROR;
  }

  return IOK;

}

int kty04_grp_key_get_size(groupsig_key_t *key) {

  uint64_t size;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_grp_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  size = 0;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->n)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->a)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->a0)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->b)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->g)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->h)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->y)/8;
  /* epsilon, nu, k */
  size += 3*sizeof(uint64_t);
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->lambda->center)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->lambda->radius)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->inner_lambda->center)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->inner_lambda->radius)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->M->center)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->M->radius)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->inner_M->center)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->inner_M->radius)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->gamma->center)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->gamma->radius)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->inner_gamma->center)/8;
  size += bigz_sizeinbits(((kty04_grp_key_t*)key->key)->inner_gamma->radius)/8;
  /* Extra sign byte for each bigz */
  size += 19;

  return (int) size;

}

int kty04_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  int _size, rc, ctr, i;
  size_t len;
  uint8_t code, type;
  byte_t *_bytes, *__bytes, *aux_bytes;
  kty04_grp_key_t *kty04_key;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_grp_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  kty04_key = key->key;

  /* Get the number of bytes to represent the key */
  if ((_size = kty04_grp_key_get_size(key)) == -1) {
    return IERROR;
  }

  /* 1 byte for the length of each bigz */
  _size += 19;

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_KTY04_CODE */
  code = GROUPSIG_KTY04_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_GRPKEY;
  _bytes[ctr++] = GROUPSIG_KEY_GRPKEY;

  /* Dump n */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->n, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump a */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->a, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump a0 */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->a0, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump b */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->b, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump g */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->g, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump h */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->h, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump y */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->y, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump epsilon */
  __bytes = &_bytes[ctr];
  for(i=0; i<8; i++){
    __bytes[i] = (kty04_key->epsilon >> 7-i) && 0xFF;
    ctr++;
  }

  /* Dump nu */
  __bytes = &_bytes[ctr];
  for(i=0; i<8; i++){
    __bytes[i] = (kty04_key->nu >> 7-i) && 0xFF;
    ctr++;
  }

  /* Dump k */
  __bytes = &_bytes[ctr];
  for(i=0; i<8; i++){
    __bytes[i] = (kty04_key->k >> 7-i) && 0xFF;
    ctr++;
  }

  /* Dump lambda center */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->lambda->center, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump lambda radius */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->lambda->radius, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump inner lambda center */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->inner_lambda->center, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump inner lambda radius */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->inner_lambda->radius, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump M center */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->M->center, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump M radius */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->M->radius, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump inner M center */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->inner_M->center, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump inner M radius */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->inner_M->radius, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump gamma center */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->gamma->center, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump gamma radius */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->gamma->radius, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump inner gamma center */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->inner_gamma->center, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
  __bytes[0] = (byte_t) len;
  ctr++;
  for(i = 1; i < len + 1; i++){
    __bytes[i] = aux_bytes[i];
    ctr++;
  }
  free(aux_bytes);

  /* Dump inner gamma radius */
  __bytes = &_bytes[ctr];
  aux_bytes = bigz_export(kty04_key->inner_gamma->radius, &len);
  if(!aux_bytes) GOTOENDRC(IERROR, kty04_grp_key_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_grp_key_export", __LINE__,
          EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, kty04_grp_key_export);
  }

  *size = ctr;

  kty04_grp_key_export_end:

   if (rc == IERROR) {
     if(_bytes) { mem_free(_bytes); _bytes = NULL; }
   }

   return rc;

}

groupsig_key_t* kty04_grp_key_import(byte_t *source, uint32_t size) {
  int rc, ctr, i;
  groupsig_key_t *key;
  kty04_grp_key_t *kty04_key;
  byte_t len, scheme, type;


  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "kty04_grp_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(key = kty04_grp_key_init())) {
    return NULL;
  }

  kty04_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_grp_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, kty04_grp_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_GRPKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_grp_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, kty04_grp_key_import);
  }

  /* Get n */
  len = source[ctr++];
  kty04_key->n = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get a */
  len = source[ctr++];
  kty04_key->a = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get a0 */
  len = source[ctr++];
  kty04_key->a0 = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get b */
  len = source[ctr++];
  kty04_key->b = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get g */
  len = source[ctr++];
  kty04_key->b = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get h */
  len = source[ctr++];
  kty04_key->b = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get y */
  len = source[ctr++];
  kty04_key->b = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get epsilon */
  for(i=0; i<8; i++){
    kty04_key->epsilon = kty04_key->epsilon << 8;
    kty04_key->epsilon = kty04_key->epsilon + source[ctr+i];
  }
  ctr += 8;

  /* Get nu */
  for(i=0; i<8; i++){
    kty04_key->nu = kty04_key->nu << 8;
    kty04_key->nu = kty04_key->nu + source[ctr+i];
  }
  ctr += 8;

  /* Get k */
  for(i=0; i<8; i++){
    kty04_key->k = kty04_key->k << 8;
    kty04_key->k = kty04_key->k + source[ctr+i];
  }
  ctr += 8;

  /* Get lambda center */
  len = source[ctr++];
  kty04_key->lambda->center = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get lambda radius */
  len = source[ctr++];
  kty04_key->lambda->radius = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get inner lambda center */
  len = source[ctr++];
  kty04_key->inner_lambda->center = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get inner lambda radius */
  len = source[ctr++];
  kty04_key->inner_lambda->radius = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get M center */
  len = source[ctr++];
  kty04_key->M->center = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get M radius */
  len = source[ctr++];
  kty04_key->M->radius = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get inner M center */
  len = source[ctr++];
  kty04_key->inner_M->center = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get inner M radius */
  len = source[ctr++];
  kty04_key->inner_M->radius = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get gamma center */
  len = source[ctr++];
  kty04_key->gamma->center = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get gamma radius */
  len = source[ctr++];
  kty04_key->gamma->radius = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get inner gamma center */
  len = source[ctr++];
  kty04_key->inner_gamma->center = bigz_import(&source[ctr], len);
  ctr += len;

  /* Get gamma radius */
  len = source[ctr++];
  kty04_key->inner_gamma->radius = bigz_import(&source[ctr], len);
  ctr += len;

  kty04_grp_key_import_end:

   if(rc == IERROR && key) { kty04_grp_key_free(key); key = NULL; }
   if(rc == IOK) return key;

   return NULL;

}

char* kty04_grp_key_to_string(groupsig_key_t *key) {

  kty04_grp_key_t *gkey;
  char *sn, *sa, *sa0, *sb, *sg, *sh, *sy, *snu, *sepsilon, *sk, *skey;
  char *s_lambda, *s_inner_lambda, *s_M, *s_inner_M, *s_gamma, *s_inner_gamma;
  uint32_t skey_len;
  size_t bits;

  if(!key) {
    LOG_EINVAL(&logger, __FILE__, "grp_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  /* For each field, we have to add space for its name (i.e., for a, add space
     for printing "a: ", for a0 add space for "a0: ", and so on). Besides, a
     '\n' will be printed after each field. Also, we have to take into account
     the spheres. For them, we will add    "lambda: ", "inner lambda: ", etc.,
     but without the '\n' because they are included by the called functions.
  */
  sn=NULL; sa=NULL; sa0=NULL; sb=NULL; sg=NULL; sh=NULL; sy=NULL; snu=NULL;
  sepsilon=NULL; sk=NULL; s_lambda=NULL; s_inner_lambda=NULL; s_M=NULL;
  s_inner_M=NULL; s_gamma=NULL; s_inner_gamma=NULL; skey=NULL;

  gkey = (kty04_grp_key_t *) key->key;

  sn = bigz_get_str10( gkey->n);
  sa = bigz_get_str10( gkey->a);
  sa0 = bigz_get_str10( gkey->a0);
  sb = bigz_get_str10( gkey->b);
  sg = bigz_get_str10( gkey->g);
  sh = bigz_get_str10( gkey->h);
  sy = bigz_get_str10( gkey->y);
  snu = misc_uint642string(gkey->nu);
  sepsilon = misc_uint642string(gkey->epsilon);
  sk = misc_uint642string(gkey->k);

  s_lambda = sphere_to_string(gkey->lambda);
  s_inner_lambda = sphere_to_string(gkey->inner_lambda);
  s_M = sphere_to_string(gkey->M);
  s_inner_M = sphere_to_string(gkey->inner_M);
  s_gamma = sphere_to_string(gkey->gamma);
  s_inner_gamma = sphere_to_string(gkey->inner_gamma);

  if(!sn || !sa || !sa0 || !sb || !sg || !sh || !sy ||
     !s_lambda || !s_inner_lambda || !s_M || !s_inner_M ||
     !s_gamma || !s_inner_gamma) {
    goto grp_key_to_string_error;
  }

  errno = 0;
  bits = bigz_sizeinbits(gkey->n);
  if(errno) goto grp_key_to_string_error;

  skey_len = 10 + // bits probably wont exceed 10 chars...
    strlen(sn)+strlen("n: ( bits)\n")+strlen(sa)+strlen("a: \n")+
    strlen(sa0)+strlen("a0: \n")+strlen(sb)+strlen("b: \n")+
    strlen(sg)+strlen("g: \n")+strlen(sh)+strlen("h: \n")+
    strlen(sy)+strlen("y: \n")+strlen("nu: \n")+strlen(snu)+
    strlen("epsilon: \n")+strlen(sepsilon)+strlen("k: \n")+strlen(sk)+
    strlen(s_lambda)+strlen("lambda: ")+strlen(s_inner_lambda)+
    strlen("inner lambda: ")+strlen(s_M)+strlen("M: ")+strlen(s_inner_M)+
    strlen("inner M: ")+strlen(s_gamma)+strlen("gamma: ")+
    strlen(s_inner_gamma)+strlen("inner gamma: ");

  if(!(skey = (char *) malloc(sizeof(char)*(skey_len+1)))) {
    goto grp_key_to_string_error;
  }

  memset(skey, 0, sizeof(char)*(skey_len+1));

  sprintf(skey,
	  "n: %s (%ld bits)\n"
	  "a: %s\n"
	  "a0: %s\n"
	  "b: %s\n"
	  "g: %s\n"
	  "h: %s\n"
	  "y: %s\n"
	  "epsilon: %s\n"
	  "nu: %s\n"
	  "k: %s\n"
	  "lambda: %s"
	  "inner lambda: %s"
	  "M: %s"
	  "inner M: %s"
	  "gamma: %s"
	  "inner gamma: %s",
	  sn, bits, sa, sa0, sb, sg, sh, sy, sepsilon, snu, sk, s_lambda, s_inner_lambda,
	  s_M, s_inner_M, s_gamma, s_inner_gamma);

 grp_key_to_string_error:

  if(sn) { free(sn); sn = NULL; }
  if(sa) { free(sa); sa = NULL; }
  if(sa0) { free(sa0); sa0 = NULL; }
  if(sb) { free(sb); sb = NULL; }
  if(sg) { free(sg); sg = NULL; }
  if(sh) { free(sh); sh = NULL; }
  if(sy) { free(sy); sy = NULL; }
  if(snu) { free(snu); snu = NULL; }
  if(sepsilon) { free(sepsilon); sepsilon = NULL; }
  if(sk) { free(sk); sk = NULL; }
  if(s_lambda) { free(s_lambda); s_lambda = NULL; }
  if(s_inner_lambda) { free(s_inner_lambda); s_inner_lambda = NULL; }
  if(s_M) { free(s_M); s_M = NULL; }
  if(s_inner_M) { free(s_inner_M); s_inner_M = NULL; }
  if(s_gamma) { free(s_gamma); s_gamma = NULL; }
  if(s_inner_gamma) { free(s_inner_gamma); s_inner_gamma = NULL; }

  return skey;

}

int kty04_grp_key_set_spheres_std(kty04_grp_key_t *key) {

  bigz_t lcenter, mcenter, gcenter, lradius, mradius, gradius;
  int rc;

  if(!key) {
    LOG_EINVAL(&logger, __FILE__, "kty04_grp_key_set_spheres_std", __LINE__, LOGERROR);
    return IERROR;
  }

  lcenter = NULL; mcenter = NULL; gcenter = NULL;
  lradius = NULL; mradius = NULL; gradius = NULL;
  rc = IOK;

  /* The Lambda sphere is S(2^(nu/4-1), 2^(nu/4-1)) */
  if(!(key->lambda = sphere_init()))
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(!(lcenter = bigz_init()))
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_ui_pow_ui(lcenter, 2, key->nu/4-1) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(!(lradius = bigz_init_set(lcenter)))
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_set(key->lambda->center, lcenter) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_set(key->lambda->radius, lradius) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);

  /* The M sphere is S(2^(nu/2-1), 2^(nu/2-1)) */
  if(!(key->M = sphere_init()))
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(!(mcenter = bigz_init()))
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_ui_pow_ui(mcenter, 2, key->nu/2-1) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(!(mradius = bigz_init_set(mcenter)))
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_set(key->M->center, mcenter) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_set(key->M->radius, mradius) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);

  /* The Gamma sphere is S(2^(3*nu/4)+2^(nu/4-1), 2^(nu/4-1)) */
  if(!(key->gamma = sphere_init()))
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(!(gradius = bigz_init()))
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_ui_pow_ui(gradius, 2, key->nu/4-1) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(!(gcenter = bigz_init()))
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_ui_pow_ui(gcenter, 2, 3*key->nu/4) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_add(gcenter, gcenter, gradius) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_set(key->gamma->center, gcenter) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_set(key->gamma->radius, gradius) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);

  /* Initialize the inner spheres and set them */

  /* Inner Lambda */
  if(!(key->inner_lambda = sphere_init()))
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(sphere_get_inner(key->lambda, key->epsilon, key->k,
		      key->inner_lambda) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);

  /* Inner M */
  if(!(key->inner_M = sphere_init()))
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(sphere_get_inner(key->M, key->epsilon, key->k,
		      key->inner_M) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);

  /* Inner Gamma */
  if(!(key->inner_gamma = sphere_init()))
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(sphere_get_inner(key->gamma, key->epsilon, key->k,
		      key->inner_gamma) == IERROR)
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);

 kty04_grp_key_set_spheres_std_end:

  if(lcenter) bigz_free(lcenter);
  if(mcenter) bigz_free(mcenter);
  if(gcenter) bigz_free(gcenter);
  if(lradius) bigz_free(lradius);
  if(mradius) bigz_free(mradius);
  if(gradius) bigz_free(gradius);

  return rc;

}

/* grp_key.c ends here */
