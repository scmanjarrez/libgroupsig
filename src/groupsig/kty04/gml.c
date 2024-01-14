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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "misc/misc.h"
#include "sys/mem.h"
#include "kty04.h"
#include "groupsig/kty04/gml.h"
#include "groupsig/kty04/identity.h"
#include "groupsig/kty04/trapdoor.h"


gml_t* kty04_gml_init() {

  gml_t *gml;

  if(!(gml = (gml_t *) malloc(sizeof(gml_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_gml_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  gml->scheme = GROUPSIG_KTY04_CODE;
  gml->entries = NULL;
  gml->n = 0;

  return gml;

}

int kty04_gml_free(gml_t *gml) {

  uint64_t i;

  if(!gml || gml->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  for(i=0; i<gml->n; i++) {
    kty04_gml_entry_free(gml->entries[i]); gml->entries[i] = NULL;
  }

  mem_free(gml->entries); gml->entries = NULL;
  mem_free(gml); gml = NULL;

  return IOK;

}

int kty04_gml_insert(gml_t *gml, gml_entry_t *entry) {

  if(!gml || gml->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_insert", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gml->entries = (gml_entry_t **)
       realloc(gml->entries, sizeof(gml_entry_t *)*(gml->n+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_gml_insert", __LINE__, errno, LOGERROR);
    return IERROR;
  }

  gml->entries[gml->n] = entry;
  gml->n++;

  return IOK;

}

int kty04_gml_remove(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_remove", __LINE__, LOGERROR);
    return IERROR;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_remove", __LINE__, "Invalid index.",
  		   LOGERROR);
    return IERROR;
  }

  /* Just set it to NULL */
  /** @todo This will generate a lot of unused memory! Use some other ADT */
  gml->entries[index] = NULL;

  /* Decrement the number of entries */
  gml->n--;

  return IOK;

}

gml_entry_t* kty04_gml_get(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_get", __LINE__, LOGERROR);
    return NULL;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_get", __LINE__, "Invalid index.",
  		   LOGERROR);
    return NULL;
  }

  return gml->entries[index];

}

int kty04_gml_export(byte_t **bytes, uint32_t *size, gml_t *gml) {

  byte_t *bentry, *_bytes;
  uint64_t i;
  int rc;
  uint32_t total_size, entry_size;

  if(!gml || gml->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  total_size = entry_size = 0;
  bentry = _bytes = NULL;

  /* Dump the number of entries */
  if (!(_bytes = mem_malloc(sizeof(uint64_t))))
    GOTOENDRC(IERROR, kty04_gml_export);
  memcpy(_bytes, &gml->n, sizeof(uint64_t));
  total_size = sizeof(uint64_t);
  /* Export the entries one by one */
  for (i=0; i<gml->n; i++) {
    if (gml_entry_export(&bentry, &entry_size, gml->entries[i]) == IERROR)
      GOTOENDRC(IERROR, kty04_gml_export);
    total_size += entry_size;
    if (!(_bytes = mem_realloc(_bytes, total_size)))
      GOTOENDRC(IERROR, kty04_gml_export);
    memcpy(&_bytes[total_size-entry_size], bentry, entry_size);
    mem_free(bentry); bentry = NULL;
  }

  if (!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, total_size);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = total_size;

 kty04_gml_export_end:

  if (rc == IERROR) {
    if (_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  if (bentry) { mem_free(bentry); bentry = NULL; }

  return rc;

}

gml_t* kty04_gml_import(byte_t *bytes, uint32_t size) {

  gml_t *gml;
  uint64_t i;
  uint32_t read;
  int entry_size;
  int rc;
  FILE *fd;

  if(!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_import", __LINE__, LOGERROR);
    return NULL;
  }

  read = 0;
  gml = NULL;
  rc = IOK;

  if (!(gml = kty04_gml_init())) GOTOENDRC(IERROR, kty04_gml_import);

  /* Read the number of entries to process */
  memcpy(&gml->n, bytes, sizeof(uint64_t));
  read += sizeof(uint64_t);

  if (!(gml->entries = mem_malloc(sizeof(gml_entry_t *)*gml->n)))
    GOTOENDRC(IERROR, kty04_gml_import);

  /* Import the entries one by one */
  for (i=0; i<gml->n; i++) {
    if (!(gml->entries[i] = kty04_gml_entry_import(&bytes[read], size-read)))
      GOTOENDRC(IERROR, kty04_gml_import);

    if ((entry_size = kty04_gml_entry_get_size(gml->entries[i])) == -1)
      GOTOENDRC(IERROR, kty04_gml_import);

    read += entry_size;
  }

 kty04_gml_import_end:

  if (rc == IERROR) {
    kty04_gml_free(gml);
    gml = NULL;
  }

  return gml;

}

gml_entry_t* kty04_gml_entry_init() {

  gml_entry_t *entry;
  kty04_gml_entry_data_t *data;

  if(!(entry = (gml_entry_t *) malloc(sizeof(gml_entry_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_gml_entry_init", __LINE__,
		  errno, LOGERROR);
    return NULL;
  }

  entry->scheme = GROUPSIG_KTY04_CODE;
  entry->id = UINT64_MAX;  // I don't know what should be the default value: 0 or UINT64_MAX

  if(!(entry->data = malloc(sizeof(kty04_gml_entry_data_t)))) {
    mem_free(entry); entry = NULL;
    return NULL;
  }
  data = (kty04_gml_entry_data_t *) entry->data;

  if(!(data->id = identity_init(GROUPSIG_KTY04_CODE))) {
    mem_free(entry->data); entry->data = NULL;
    mem_free(entry); entry = NULL;
    return NULL;
  }

  if(!(data->trapdoor = trapdoor_init(GROUPSIG_KTY04_CODE))) {
    identity_free(data->id); data->id = NULL;
    mem_free(entry->data); entry->data = NULL;
    mem_free(entry); entry = NULL;
    return NULL;
  }

  if(!(data->A = bigz_init())) {
    identity_free(data->id); data->id = NULL;
    trapdoor_free(data->trapdoor); data->trapdoor = NULL;
    mem_free(entry->data); entry->data = NULL;
    mem_free(entry); entry = NULL;
  }

  return entry;
}


int kty04_gml_entry_free(gml_entry_t *entry) {

  kty04_gml_entry_data_t *data;
  int rc;

  if(!entry) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_gml_entry_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  rc = IOK;
  data = (kty04_gml_entry_data_t *) entry->data;

  if (data) {
    if (data->id) { rc = identity_free(data->id); data->id = NULL; }
    if (data->trapdoor) { rc = trapdoor_free(data->trapdoor); data->trapdoor = NULL; }
    if (data->A) { rc = bigz_free(data->A); data->A = NULL; }
    mem_free(entry->data); entry->data = NULL;
  }
  mem_free(entry); entry = NULL;

  return rc;

}

int kty04_gml_entry_get_size(gml_entry_t *entry) {

  byte_t *bytes;
  uint32_t size;

  if (!entry) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_entry_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  if (!(bytes = (byte_t *) kty04_gml_entry_to_string(entry)))
    return -1;
  size = strlen(bytes);

  if (size >= INT_MAX) return -1;
  
  return (int) size;

}

int kty04_gml_entry_export(byte_t **bytes,
                           uint32_t *size,
                           gml_entry_t *entry) {

  if (!bytes ||
      !size ||
      !entry || entry->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_entry_export", __LINE__, LOGERROR);
    return IERROR;
  }

  *bytes = (byte_t *) kty04_gml_entry_to_string(entry);

  *size = strlen(*bytes);

  return IOK;

}

gml_entry_t* kty04_gml_entry_import(byte_t *bytes, uint32_t size) {

  gml_entry_t *entry;
  kty04_gml_entry_data_t *data;
  char *strapdoor, *sA, *sid;
  byte_t *input;

  if (!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_entry_import", __LINE__, LOGERROR);
    return NULL;
  }

  if (!(entry = kty04_gml_entry_init())) return NULL;
  if (!(input = mem_malloc(size + 1))) {
    mem_free(entry); entry = NULL;
    return NULL;
  }

  if (!(memcpy(input, bytes, size))) {
    mem_free(entry); entry = NULL;
    return NULL;
  }

  data = (kty04_gml_entry_data_t *) entry->data;

  sid = strtok(input, "\t");
  sA = strtok(NULL, "\t");
  strapdoor = strtok(NULL, "\t");

  data->id = identity_from_string(GROUPSIG_KTY04_CODE, sid);
  if ((bigz_set_str10(data->A, sA)) == IERROR) return NULL;
  data->trapdoor = trapdoor_from_string(GROUPSIG_KTY04_CODE, strapdoor);

  return entry;

}

char* kty04_gml_entry_to_string(gml_entry_t *entry) {

  kty04_gml_entry_data_t *data;
  char *strapdoor, *sA, *sid, *sentry;
  uint64_t sentry_len;

  if(!entry ||
     entry->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_entry_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  data = (kty04_gml_entry_data_t *)(entry->data);

  /* A string representation of a GML entry will be:
     <id>\t<A>\t<trapdoor> */

  /* Get the string representations of the entry's fields */
  if(!(sid = identity_to_string(data->id))) {
    return NULL;
  }

  if(!(sA = bigz_get_str10(data->A))) {
    mem_free(sid); sid = NULL;
    return NULL;
  }

  if(!(strapdoor = trapdoor_to_string(data->trapdoor))) {
    mem_free(sid); sid = NULL;
    mem_free(sA); sA = NULL;
    return NULL;
  }

  /* Calculate the length of the entry, adding the size of 3 separators + \0 */
  sentry_len = strlen(sid)+strlen(sA)+strlen(strapdoor)+strlen("\t\t\t") + 1;

  if(!(sentry = (char *) malloc(sizeof(char)*sentry_len))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_gml_entry_to_string", __LINE__, errno,
		  LOGERROR);
    free(strapdoor); strapdoor = NULL;
    mem_free(sid); sid = NULL;
    free(sA); sA = NULL;
    return NULL;
  }

  memset(sentry, 0, sentry_len*sizeof(char));
  int sz = sprintf(sentry, "%s\t%s\t%s\t", sid, sA, strapdoor);

  mem_free(sid);
  mem_free(sA);
  mem_free(strapdoor);

  return sentry;

}

int kty04_gml_entry_cmp_As(gml_entry_t *entry1,
                           gml_entry_t *entry2) {

  kty04_gml_entry_data_t *d1, *d2;

  if(!entry1 || !entry2) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_entry_cmp_As", __LINE__, LOGERROR);
    return 0;
  }

  d1 = (kty04_gml_entry_data_t *) entry1->data;
  d2 = (kty04_gml_entry_data_t *) entry2->data;

  return bigz_cmp(d1->A, d2->A);

}

int kty04_gml_entry_cmp_trapdoors(gml_entry_t *entry1,
                                  gml_entry_t *entry2) {

  kty04_gml_entry_data_t *d1, *d2;

  if(!entry1 || !entry2) {
    LOG_EINVAL(&logger, __FILE__, "kty04_gml_entry_cmp_trapdoors", __LINE__, LOGERROR);
    return 0;
  }

  d1 = (kty04_gml_entry_data_t *) entry1->data;
  d2 = (kty04_gml_entry_data_t *) entry2->data;

  return bigz_cmp(*(kty04_trapdoor_t *) d1->trapdoor->trap,
                  *(kty04_trapdoor_t *) d2->trapdoor->trap);

}
