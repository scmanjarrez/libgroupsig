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
#include "cpy06.h"
#include "groupsig/cpy06/gml.h"
#include "groupsig/cpy06/identity.h"
#include "groupsig/cpy06/trapdoor.h"


gml_t* cpy06_gml_init() {

  gml_t *gml;

  if(!(gml = (gml_t *) malloc(sizeof(gml_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_gml_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  gml->scheme = GROUPSIG_CPY06_CODE;
  gml->entries = NULL;
  gml->n = 0;

  return gml;

}

int cpy06_gml_free(gml_t *gml) {

  uint64_t i;

  if(!gml || gml->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_free", __LINE__,
  		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  for(i=0; i<gml->n; i++) {
    cpy06_gml_entry_free(gml->entries[i]);
  }

  mem_free(gml->entries); gml->entries = NULL;
  mem_free(gml);

  return IOK;

}

int cpy06_gml_insert(gml_t *gml, gml_entry_t *entry) {

  if(!gml || gml->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_insert", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gml->entries = (gml_entry_t **) 
       realloc(gml->entries, sizeof(gml_entry_t *)*(gml->n+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_gml_insert",
		  __LINE__, errno, LOGERROR);
    return IERROR;
  }

  gml->entries[gml->n] = entry;
  gml->n++;

  return IOK;

}

int cpy06_gml_remove(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_remove", __LINE__, LOGERROR);
    return IERROR;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_remove", __LINE__,
		   "Invalid index.", LOGERROR);
    return IERROR;
  }

  /* Just set it to NULL */
  /** @todo This will generate a lot of unused memory! Use some other ADT */
  gml->entries[index] = NULL;
  
  /* Decrement the number of entries */
  gml->n--;

  return IOK;

}

gml_entry_t* cpy06_gml_get(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_get", __LINE__, LOGERROR);
    return NULL;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_get", __LINE__, "Invalid index.",
  		   LOGERROR);
    return NULL;
  }

  return gml->entries[index];
  
}

int cpy06_gml_export(byte_t **bytes, uint32_t *size, gml_t *gml) {

  byte_t *bentry, *_bytes;
  uint64_t i;
  int rc;
  uint32_t total_size, entry_size;

  if(!gml || gml->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  total_size = entry_size = 0;
  bentry = _bytes = NULL;

  /* Dump the number of entries */
  if (!(_bytes = mem_malloc(sizeof(uint64_t))))
    GOTOENDRC(IERROR, cpy06_gml_export);
  
  memcpy(_bytes, &gml->n, sizeof(uint64_t));
  total_size = sizeof(uint64_t);
  
  /* Export the entries one by one */
  for (i=0; i<gml->n; i++) {
    
    if (gml_entry_export(&bentry, &entry_size, gml->entries[i]) == IERROR)
      GOTOENDRC(IERROR, cpy06_gml_export);
    
    total_size += entry_size;
    
    if (!(_bytes = mem_realloc(_bytes, total_size)))
      GOTOENDRC(IERROR, cpy06_gml_export);
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

 cpy06_gml_export_end:

  if (rc == IERROR) {
    if (_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  if (bentry) { mem_free(bentry); bentry = NULL; }

  return rc;

}

gml_t* cpy06_gml_import(byte_t *bytes, uint32_t size) {

  gml_t *gml;
  uint64_t i;
  uint32_t read;
  int entry_size;
  int rc;
  FILE *fd;

  if(!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_import", __LINE__, LOGERROR);
    return NULL;
  }

  read = 0;
  gml = NULL;
  rc = IOK;

  if (!(gml = cpy06_gml_init())) GOTOENDRC(IERROR, cpy06_gml_import);

  /* Read the number of entries to process */
  memcpy(&gml->n, bytes, sizeof(uint64_t));
  read += sizeof(uint64_t);

  if (!(gml->entries = mem_malloc(sizeof(gml_entry_t *)*gml->n)))
    GOTOENDRC(IERROR, cpy06_gml_import);

  /* Import the entries one by one */
  for (i=0; i<gml->n; i++) {
    if (!(gml->entries[i] = cpy06_gml_entry_import(&bytes[read], size-read)))
      GOTOENDRC(IERROR, cpy06_gml_import);

    if ((entry_size = cpy06_gml_entry_get_size(gml->entries[i])) == -1)
      GOTOENDRC(IERROR, cpy06_gml_import);

    read += entry_size;
  }

 cpy06_gml_import_end:

  if (rc == IERROR) {
    cpy06_gml_free(gml);
    gml = NULL;
  }

  return gml;
 
}

/* int cpy06_gml_export_new_entry(void *entry, void *dst, gml_format_t format) { */

/*   if(!entry || !dst) { */
/*     LOG_EINVAL(&logger, __FILE__, "cpy06_gml_export_new_entry", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   if(!_is_supported_format(format)) { */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_export_new_entry", __LINE__, */
/*   		   "Unsupported GML format.", LOGERROR); */
/*     return IERROR; */
/*   } */

/*   switch(format) { */
/*   case GML_FILE: */
/*     return _gml_export_new_entry_file(entry, (char *) dst); */
/*   default: */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_export_new_entry", __LINE__, */
/*   		   "Unsupported GML format.", LOGERROR); */
/*     return IERROR; */
/*   } */

/*   return IERROR;   */

/* } */

gml_entry_t* cpy06_gml_entry_init() {

  gml_entry_t *entry;
  cpy06_gml_entry_data_t *data;
  int rc;

  entry = NULL;
  data = NULL;
  rc = IOK;

  if (!(entry = (gml_entry_t *) malloc(sizeof(gml_entry_t))))
    GOTOENDRC(IERROR, cpy06_gml_entry_init);

  entry->scheme = GROUPSIG_CPY06_CODE;
  entry->id = UINT64_MAX;
  entry->data = NULL;
  
  if (!(entry->data =
	(cpy06_gml_entry_data_t *) malloc(sizeof(cpy06_gml_entry_data_t))))
    GOTOENDRC(IERROR, cpy06_gml_entry_init);
  data = (cpy06_gml_entry_data_t *) entry->data;

  if (!(data->id = identity_init(GROUPSIG_CPY06_CODE)))
    GOTOENDRC(IERROR, cpy06_gml_entry_init);

  if (!(data->trapdoor = trapdoor_init(GROUPSIG_CPY06_CODE)))
    GOTOENDRC(IERROR, cpy06_gml_entry_init);

 cpy06_gml_entry_init_end:

  if (rc == IERROR) { cpy06_gml_entry_free(entry); entry = NULL; }
  
  return entry;

}


int cpy06_gml_entry_free(gml_entry_t *entry) {

  cpy06_gml_entry_data_t *data;
  int rc;
  
  if(!entry) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_entry_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  rc = IOK;
  data = (cpy06_gml_entry_data_t *) entry->data;

  if (data) {
    if (data->id) {
      rc = identity_free(data->id); data->id = NULL;
    }
    if (data->trapdoor) {
      rc &= trapdoor_free(data->trapdoor); data->trapdoor = NULL;
    }
    mem_free(data); data = NULL;
  }
  
  mem_free(entry);
  
  return rc;

}

int cpy06_gml_entry_get_size(gml_entry_t *entry) {

  byte_t *bytes;
  uint64_t size;

  if (!entry ||
      entry->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_entry_get_size",
	       __LINE__, LOGERROR);
    return -1;    
  }

  if (!(bytes = (byte_t *) cpy06_gml_entry_to_string(entry)))
    return -1;
  size = strlen(bytes);

  if (size >= INT_MAX) return -1;

  return (int) size;
  
}

int cpy06_gml_entry_export(byte_t **bytes,
			   uint32_t *size,
			   gml_entry_t *entry) {

  byte_t *_bytes;

  /* @TODO: This should export to bytes, not to a string */
  
  if (!bytes ||
      !size ||
      !entry || entry->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_entry_export", __LINE__, LOGERROR);
    return IERROR;
  }

  if (!(_bytes = (byte_t *) cpy06_gml_entry_to_string(entry))) return IERROR;

  *size = strlen(_bytes);
  *bytes = _bytes;  

  return IOK;  
}

gml_entry_t* cpy06_gml_entry_import(byte_t *bytes, uint32_t size) {

  gml_entry_t *entry;
  cpy06_gml_entry_data_t *data;
  char *strapdoor, *sid;
  byte_t *input;
  int rc;

  if (!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_entry_import", __LINE__, LOGERROR);
    return NULL;    
  }

  entry = NULL;
  data = NULL;  
  rc = IOK;

  if (!(entry = cpy06_gml_entry_init()))
    GOTOENDRC(IERROR, cpy06_gml_entry_import);

  if (!(input = mem_malloc(size + 1)))
    GOTOENDRC(IERROR, cpy06_gml_entry_import);

  if (!(memcpy(input, bytes, size)))
    GOTOENDRC(IERROR, cpy06_gml_entry_import);

  data = (cpy06_gml_entry_data_t *) entry->data;

  sid = strtok(input, "\t");
  strapdoor = strtok(NULL, "\t");

  if (!(data->id = identity_from_string(GROUPSIG_CPY06_CODE, sid)))
    GOTOENDRC(IERROR, cpy06_gml_entry_import);
  if (!(data->trapdoor = trapdoor_from_string(GROUPSIG_CPY06_CODE, strapdoor)))
    GOTOENDRC(IERROR, cpy06_gml_entry_import);

 cpy06_gml_entry_import_end:

  if (rc == IERROR) {
    if (entry) { cpy06_gml_entry_free(entry); entry = NULL; }
  }

  if (input) { mem_free(input); input = NULL; }
  
  return entry;  
  
}

char* cpy06_gml_entry_to_string(gml_entry_t *entry) {

  cpy06_gml_entry_data_t *data;
  char *strapdoor, *sid, *sentry;
  uint64_t sentry_len;
  int rc;

  if(!entry ||
     entry->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_entry_to_string",
	       __LINE__, LOGERROR);
    return NULL;
  }

  data = (cpy06_gml_entry_data_t *) entry->data;
  strapdoor = sid = sentry = NULL;
  rc = IOK;

  /* A string representation of a GML entry will be: 
     <id>\t<trapdoor> */

  /* Get the string representations of the entry's fields */
  if (!(sid = identity_to_string(data->id)))
    GOTOENDRC(IERROR, cpy06_gml_entry_to_string);
  
  if (!(strapdoor = trapdoor_to_string(data->trapdoor)))
    GOTOENDRC(IERROR, cpy06_gml_entry_to_string);
  
  /* Calculate the length of the entry, adding a tab */
  sentry_len = strlen(sid)+strlen(strapdoor)+strlen("\t\t")+1;
  
  if (!(sentry = (char *) malloc(sizeof(char)*sentry_len)))
    GOTOENDRC(IERROR, cpy06_gml_entry_to_string);
  
  memset(sentry, 0, sentry_len*sizeof(char));
  sprintf(sentry, "%s\t%s\t", sid, strapdoor);

 cpy06_gml_entry_to_string_end:
  
  mem_free(sid); sid = NULL;
  mem_free(strapdoor); strapdoor = NULL;

  if (rc == IERROR) { mem_free(sentry); sentry = NULL; }

  return sentry;
 
}

/* int cpy06_gml_entry_cmp_trapdoors(cpy06_gml_entry_t *entry1, cpy06_gml_entry_t *entry2) { */

/*   if(!entry1 || !entry2) { */
/*     LOG_EINVAL(&logger, __FILE__, "cpy06_gml_entry_cmp_trapdoors", __LINE__, LOGERROR); */
/*     return 0; */
/*   } */

/*   return cpy06_trapdoor_cmp(entry1->trapdoor, entry2->trapdoor); */

/* } */

/* cpy06_gml.c ends here */
