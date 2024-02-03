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

#include <stdlib.h>

#include "types.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "groupsig/cpy06/trapdoor.h"
#include "shim/pbc_ext.h"

trapdoor_t* cpy06_trapdoor_init() {
  
  trapdoor_t *trap;
  cpy06_trapdoor_t *cpy06_trap;
  
  if (!(trap = (trapdoor_t *) mem_malloc(sizeof(trapdoor_t)))) {
    return NULL;
  }

  if (!(cpy06_trap = (cpy06_trapdoor_t *) mem_malloc(sizeof(cpy06_trapdoor_t)))) {
    mem_free(trap); trap = NULL;
    return NULL;
  }
  
  trap->scheme = GROUPSIG_CPY06_CODE;
  trap->trap = cpy06_trap;
  cpy06_trap->open = NULL;
  cpy06_trap->trace = NULL;
  
  return trap;
  
}

int cpy06_trapdoor_free(trapdoor_t *trap) {
  
  cpy06_trapdoor_t *cpy06_trap;
  
  if(!trap || trap->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_trapdoor_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if (trap->trap) {
    cpy06_trap = trap->trap;
    if (cpy06_trap->open) {
      pbcext_element_G1_free(cpy06_trap->open);
      cpy06_trap->open = NULL;
    }
    if (cpy06_trap->trace) {
      pbcext_element_G1_free(cpy06_trap->trace);
      cpy06_trap->trace = NULL;
    }
    mem_free(cpy06_trap); cpy06_trap = NULL;
  }
  
  mem_free(trap);
  
  return IOK;
  
}

int cpy06_trapdoor_copy(trapdoor_t *dst, trapdoor_t *src) {

  cpy06_trapdoor_t *cpy06_dst, *cpy06_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_CPY06_CODE ||
     !src || src->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_trapdoor_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  cpy06_dst = dst->trap;
  cpy06_src = src->trap;
  rc = IOK;

  /* Open trapdoor */
  if (!(cpy06_dst->open = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_trapdoor_copy);

  if (pbcext_element_G1_set(cpy06_dst->open, cpy06_src->open) == IERROR)
    GOTOENDRC(IERROR, cpy06_trapdoor_copy);

  /* Trace trapdoor */
  if (!(cpy06_dst->trace = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_trapdoor_copy);

  if (pbcext_element_G1_set(cpy06_dst->trace, cpy06_src->trace) == IERROR)
    GOTOENDRC(IERROR, cpy06_trapdoor_copy);

 cpy06_trapdoor_copy_end:

  if (rc == IERROR) {
    if (cpy06_dst->open) {
      pbcext_element_G1_free(cpy06_dst->open); cpy06_dst->open = NULL;
    }
    if (cpy06_dst->trace) {
      pbcext_element_G1_free(cpy06_dst->trace); cpy06_dst->trace = NULL;
    }    
  }

  return rc;

}

char* cpy06_trapdoor_to_string(trapdoor_t *trap) {

  cpy06_trapdoor_t *cpy06_trap;
  char *sopen, *strace, *strap;
  uint64_t sopen_len, strace_len, strap_len;
  int rc;
  
  if(!trap || trap->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_trapdoor_to_string",
	       __LINE__, LOGERROR);
    return NULL;
  }

  sopen = strace = strap = NULL;
  sopen_len = strace_len = strap_len = 0;
  cpy06_trap = trap->trap;
  rc = IOK;

  if (pbcext_element_G1_to_string(&sopen,
				  &sopen_len,
				  10,
				  cpy06_trap->open) == IERROR)
    GOTOENDRC(IERROR, cpy06_trapdoor_to_string);
  
  if (pbcext_element_G1_to_string(&strace,
				  &strace_len,
				  10,
				  cpy06_trap->trace) == IERROR)
    GOTOENDRC(IERROR, cpy06_trapdoor_to_string);

  if (!(strap = mem_malloc(sizeof(char *)*(sopen_len+strace_len)+2)))
    GOTOENDRC(IERROR, cpy06_trapdoor_to_string);
    
  sprintf(strap, "%s %s", sopen, strace);

 cpy06_trapdoor_to_string_end:

  if (rc == IERROR && strap) { mem_free(strap); strap = NULL; }
  
  mem_free(sopen); sopen = NULL;
  mem_free(strace); strace = NULL;  

  return strap;
  
}

trapdoor_t* cpy06_trapdoor_from_string(char *strap) {
  
  trapdoor_t *trap;
  cpy06_trapdoor_t *cpy06_trap;
  char *sopen, *strace;
  int rc;
  
  if(!strap) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_trapdoor_from_string",
	       __LINE__, LOGERROR);
    return NULL;
  }

  trap = NULL;
  cpy06_trap = NULL;
  sopen = strace = NULL;
  rc = IOK;
  
  if (!(sopen = (char *) mem_malloc(sizeof(char)*strlen(strap)+1)))
    GOTOENDRC(IERROR, cpy06_trapdoor_from_string);

  if (!(strace = (char *) mem_malloc(sizeof(char)*strlen(strap)+1)))
    GOTOENDRC(IERROR, cpy06_trapdoor_from_string);

  if ((rc = sscanf(strap, "%s %s", sopen, strace)) == EOF)
    GOTOENDRC(IERROR, cpy06_trapdoor_from_string);

  if(rc != 2) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_trapdoor_from_string", __LINE__,
		      EDQUOT, "Corrupted or invalid trapdoor.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_trapdoor_from_string);
  }

  if(!(trap = cpy06_trapdoor_init()))
    GOTOENDRC(IERROR, cpy06_trapdoor_from_string);
  cpy06_trap = trap->trap;

  if (!(cpy06_trap->open = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_trapdoor_from_string);
  
  if (pbcext_element_G1_from_string(&cpy06_trap->open, sopen, 10) == IERROR)
    GOTOENDRC(IERROR, cpy06_trapdoor_from_string);

  if (!(cpy06_trap->trace = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_trapdoor_from_string);
  
  if (pbcext_element_G1_from_string(&cpy06_trap->trace, strace, 10) == IERROR)
    GOTOENDRC(IERROR, cpy06_trapdoor_from_string);

 cpy06_trapdoor_from_string_end:

  if (rc == IERROR && trap) {
    cpy06_trapdoor_free(trap); trap = NULL;
  }
  
  mem_free(sopen); sopen = NULL;
  mem_free(strace); strace = NULL;
  
  return trap;
  
}

int cpy06_trapdoor_cmp(trapdoor_t *t1, trapdoor_t *t2) {
  
  if(!t1 || t1->scheme != GROUPSIG_CPY06_CODE ||
     !t2 || t2->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_trapdoor_cmp", __LINE__, LOGERROR);
    return IERROR;
  }

  return pbcext_element_G1_cmp(((cpy06_trapdoor_t *)t1->trap)->open, 
			       ((cpy06_trapdoor_t *)t2->trap)->open);

}

/* identity.c ends here */
