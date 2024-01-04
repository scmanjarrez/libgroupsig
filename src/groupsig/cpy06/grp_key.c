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

#include "sysenv.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"

#include "cpy06.h"
#include "groupsig/cpy06/grp_key.h"


/**
 * @fn static int _get_size_bytearray_null(exim_t *obj)
 * @brief Returns the size in bytes of the exim wrapped object. The size will be
 * equal to the size of bytearray output by _export_fd() or created by
 * _import_fd().
 *
 * @param[in] obj The object to be sized.
 *
 * @return The size in bytes of the object contained in obj.
 */
static int _get_size_bytearray_null(exim_t *obj){
  int size;
  byte_t *bytes_params;
  uint64_t size_params;
  cpy06_sysenv_t *cpy06_sysenv;
  if(!obj || !obj->eximable){
    return -1;
  }
  cpy06_grp_key_t *key = (cpy06_grp_key_t*)obj->eximable;
  cpy06_sysenv = sysenv->data;

  bytes_params = NULL;
  if(pbcext_dump_param_bytes(&bytes_params, &size_params, cpy06_sysenv->param) == IERROR) {
    return IERROR;
  }

  size = element_length_in_bytes(key->g1)+element_length_in_bytes(key->g2)+
    element_length_in_bytes(key->q)+element_length_in_bytes(key->r)+
    element_length_in_bytes(key->w)+element_length_in_bytes(key->x)+
    element_length_in_bytes(key->y)+element_length_in_bytes(key->z)+
    sizeof(int)*9+size_params+2;

  return size;
}

/**
 * @fn static int _export_fd(exim_t* obj, FILE *fd)
 * @brief Writes a bytearray representation of the given exim object to a
 * file descriptor with format:
 *
 *  | CPY06_CODE | KEYTYPE | size_params | params | size_g1 | g1 | size_g2 | g2 |
 *    size_q | q | size_r | r | size_w | w | size_x | x | size_y | y | size_z | z |
 *
 * @param[in] key The key to export.
 * @param[in, out] fd An open filestream to write to.
 *
 * @return IOK or IERROR
 */
static int _export_fd(exim_t* obj, FILE *fd) {

  cpy06_sysenv_t *cpy06_sysenv;
  cpy06_grp_key_t *key;
  uint8_t code, type;

  if(!obj || !obj->eximable || !fd) {
    LOG_EINVAL(&logger, __FILE__, "_export_fd", __LINE__, LOGERROR);
    return IERROR;
  }
  
  key = (cpy06_grp_key_t*) obj->eximable;
  cpy06_sysenv = sysenv->data;

  /* Dump GROUPSIG_CPY06_CODE */
  code = GROUPSIG_CPY06_CODE;
  if(fwrite(&code, sizeof(byte_t), 1, fd) != 1) {
    return IERROR;
  }

  /* Dump key type */
  type = GROUPSIG_KEY_GRPKEY;
  if(fwrite(&type, sizeof(byte_t), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "_export_fd", __LINE__,
		  errno, LOGERROR);
    return IERROR;
  }

  /* Dump params */
  if(pbcext_dump_param_fd(cpy06_sysenv->param, fd) == IERROR) {
    return IERROR;
  }

  /* Dump g1 */
  if(pbcext_dump_element_fd(key->g1, fd) == IERROR) {
    return IERROR;
  }

  /* Dump g2 */
  if(pbcext_dump_element_fd(key->g2, fd) == IERROR) {
    return IERROR;
  }

  /* Dump q */
  if(pbcext_dump_element_fd(key->q, fd) == IERROR) {
    return IERROR;
  }

  /* Dump r */
  if(pbcext_dump_element_fd(key->r, fd) == IERROR) {
    return IERROR;
  }

  /* Dump w */
  if(pbcext_dump_element_fd(key->w, fd) == IERROR) {
    return IERROR;
  }

  /* Dump x */
  if(pbcext_dump_element_fd(key->x, fd) == IERROR) {
    return IERROR;
  }

  /* Dump y */
  if(pbcext_dump_element_fd(key->y, fd) == IERROR) {
    return IERROR;
  }

  /* Dump z */
  if(pbcext_dump_element_fd(key->z, fd) == IERROR) {
    return IERROR;
  }

  return IOK;
}

/**
 * @fn static int _import_fd(FILE *fd, exim_t* obj)
 * @brief Import a representation of the given key from a file descriptor.
 * Expects the same format as the output from _export_fd().
 *
 * @return IOK or IERROR
 */
static int _import_fd(FILE *fd, exim_t* obj) {
  
  groupsig_key_t *key;
  cpy06_grp_key_t *cpy06_key;
  cpy06_sysenv_t *cpy06_sysenv;
  byte_t scheme, type;

  if(!fd || !obj) {
    LOG_EINVAL(&logger, __FILE__, "_import_fd", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(key = cpy06_grp_key_init())) {
    return IERROR;
  }

  cpy06_key = key->key;

  /* First sizeof(int) bytes: scheme */
  if(fread(&scheme, sizeof(byte_t), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "_import_fd", __LINE__,
		  errno, LOGERROR);
    cpy06_grp_key_free(key); key = NULL;
    return IERROR;
  }

  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_import_fd", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    cpy06_grp_key_free(key); key = NULL;
    return IERROR;
  }

  /* Next sizeof(int) bytes: key type */
  if(fread(&type, sizeof(byte_t), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "_import_fd", __LINE__,
		  errno, LOGERROR);
    cpy06_grp_key_free(key); key = NULL;
    return IERROR;
  }

  if(type != GROUPSIG_KEY_GRPKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_import_fd", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    cpy06_grp_key_free(key); key = NULL;
    return IERROR;
  }


  /* Get the params if sysenv->data is uninitialized */
  if(!sysenv->data) {

    /* Copy the param and pairing to the CPY06 internal environment */
    /* By setting the environment, we avoid having to keep a copy of params
       and pairing in manager/member keys and signatures, crls, gmls... */
    if(!(cpy06_sysenv = (cpy06_sysenv_t *) mem_malloc(sizeof(cpy06_sysenv_t)))) {
      cpy06_grp_key_free(key); key = NULL;
      return IERROR;
    }

    if(pbcext_get_param_fd(cpy06_sysenv->param, fd) == IERROR) {
      cpy06_grp_key_free(key); key = NULL;
      return IERROR;
    }

    pairing_init_pbc_param(cpy06_sysenv->pairing, cpy06_sysenv->param);

    if(cpy06_sysenv_update(cpy06_sysenv) == IERROR) {
      cpy06_grp_key_free(key); key = NULL;
      pbc_param_clear(cpy06_sysenv->param);
      mem_free(cpy06_sysenv); cpy06_sysenv = NULL;
      return IERROR;
    }

  } else { /* Else, skip it */

    if (pbcext_skip_param_fd(fd) == IERROR) {
      cpy06_grp_key_free(key); key = NULL;
    }

    cpy06_sysenv = sysenv->data;

  }

  /* Get g1 */
  element_init_G1(cpy06_key->g1, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->g1, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get g2 */
  element_init_G2(cpy06_key->g2, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->g2, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get q */
  element_init_G1(cpy06_key->q, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->q, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get r */
  element_init_G2(cpy06_key->r, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->r, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get w */
  element_init_G2(cpy06_key->w, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->w, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get x */
  element_init_G1(cpy06_key->x, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->x, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get y */
  element_init_G1(cpy06_key->y, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->y, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get z */
  element_init_G1(cpy06_key->z, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->z, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Precomputations... */

  /* T5 = e(g1, W) */
  element_init_GT(cpy06_key->T5, cpy06_sysenv->pairing);
  element_pairing(cpy06_key->T5, cpy06_key->g1, cpy06_key->w);

  /* e2 = e(z,g2) */
  element_init_GT(cpy06_key->e2, cpy06_sysenv->pairing);
  element_pairing(cpy06_key->e2, cpy06_key->z, cpy06_key->g2);

  /* e3 = e(z,r) */
  element_init_GT(cpy06_key->e3, cpy06_sysenv->pairing);
  element_pairing(cpy06_key->e3, cpy06_key->z, cpy06_key->r);

  /* e4 = e(g1,g2) */
  element_init_GT(cpy06_key->e4, cpy06_sysenv->pairing);
  element_pairing(cpy06_key->e4, cpy06_key->g1, cpy06_key->g2);

  /* e5 = e(q,g2) */
  element_init_GT(cpy06_key->e5, cpy06_sysenv->pairing);
  element_pairing(cpy06_key->e5, cpy06_key->q, cpy06_key->g2);

  obj->eximable = (void*) key;
  return IOK;
}

/* Export/import handle definition */

static exim_handle_t _exim_h = {
				&_get_size_bytearray_null,
				&_export_fd,
				&_import_fd,
};

/* "Public" functions */

groupsig_key_t* cpy06_grp_key_init() {

  groupsig_key_t *key;
  cpy06_grp_key_t *cpy06_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (cpy06_grp_key_t *) mem_malloc(sizeof(cpy06_grp_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_CPY06_CODE;
  cpy06_key = key->key;
  cpy06_key->q = NULL;
  cpy06_key->r = NULL;
  cpy06_key->w = NULL;
  cpy06_key->x = NULL;
  cpy06_key->y = NULL;
  cpy06_key->z = NULL;
  cpy06_key->T5 = NULL;
  cpy06_key->e2 = NULL;
  cpy06_key->e3  = NULL;
  cpy06_key->e4 = NULL;
  cpy06_key->e5 = NULL;
  
  return key;
  
}

int cpy06_grp_key_free(groupsig_key_t *key) {

  cpy06_grp_key_t *cpy06_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_grp_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_grp_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    cpy06_key = key->key;
    if (cpy06_key->q) {
      pbcext_element_G1_free(cpy06_key->q); cpy06_key->q = NULL;
    }
    if (cpy06_key->r) {
      pbcext_element_G2_free(cpy06_key->r); cpy06_key->r = NULL;
    }
    if (cpy06_key->w) {
      pbcext_element_G2_free(cpy06_key->w); cpy06_key->w = NULL;
    }
    if (cpy06_key->x) {
      pbcext_element_G1_free(cpy06_key->x); cpy06_key->x = NULL;
    }
    if (cpy06_key->y) {
      pbcext_element_G1_free(cpy06_key->y); cpy06_key->y = NULL;
    }
    if (cpy06_key->z) {    
      pbcext_element_G1_free(cpy06_key->z); cpy06_key->z = NULL;
    }
    if (cpy06_key->T5) {
      pbcext_element_GT_free(cpy06_key->T5); cpy06_key->T5 = NULL;
    }
    if (cpy06_key->e2) {
      pbcext_element_GT_free(cpy06_key->e2); cpy06_key->e2 = NULL;
    }
    if (cpy06_key->e3) {
      pbcext_element_GT_free(cpy06_key->e3); cpy06_key->e3 = NULL;
    }
    if (cpy06_key->e4) {
      cpy06_element_GT_free(cpy06_key->e4); cpy06_key->e4 = NULL;
    }
    if (cpy06_key->e5) {
      cpy06_element_GT_free(cpy06_key->e5); cpy06_key->e5 = NULL;
    }
    mem_free(key->key);
    key->key = NULL;
  }

  mem_free(key);

  return IOK;

}

int cpy06_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  cpy06_grp_key_t *cpy06_dst, *cpy06_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_CPY06_CODE ||
     !src || src->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_grp_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  cpy06_dst = dst->key;
  cpy06_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if (!(cpy06_dst->q = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_copy);
  if (pbcext_element_G1_set(cpy06_dst->q, cpy06_src->q) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_copy);
  if (!(cpy06_dst->r = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_copy);
  if (pbcext_element_G2_set(cpy06_dst->r, cpy06_src->r) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (!(cpy06_dst->w = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_copy);
  if (pbcext_element_G2_set(cpy06_dst->w, cpy06_src->w) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_copy);
  if (!(cpy06_dst->x = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_copy);
  if (pbcext_element_set(cpy06_dst->x, cpy06_src->x) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (!(cpy06_dst->y = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (pbcext_element_G1_set(cpy06_dst->y, cpy06_src->y) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (!(cpy06_dst->z = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (pbcext_element_G1_set(cpy06_dst->z, cpy06_src->z) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_copy);
  if (!(cpy06_dst->T5 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (pbcext_element_GT_set(cpy06_dst->T5, cpy06_src->T5) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (!(cpy06_dst->e2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (pbcext_element_GT_set(cpy06_dst->e2, cpy06_src->e2) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (!(cpy06_dst->e3 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (pbcext_element_GT_set(cpy06_dst->e3, cpy06_src->e3) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (!(cpy06_dst->e4 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (pbcext_element_GT_set(cpy06_dst->e4, cpy06_src->e4) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (!(cpy06_dst->e5 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_copy);  
  if (pbcext_element_GT_set(cpy06_dst->e5, cpy06_src->e5) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_copy);

 cpy06_grp_key_copy_end:

  if (rc == IERROR) {
    if (cpy06_dst->q) {
      pbcext_element_G1_free(cpy06_dst->q); cpy06_dst->q = NULL;
    }
    if (cpy06_dst->r) {
      pbcext_element_G2_free(cpy06_dst->r); cpy06_dst->r = NULL;
    }
    if (cpy06_dst->w) {
      pbcext_element_G2_free(cpy06_dst->w); cpy06_dst->w = NULL;
    }
    if (cpy06_dst->x) {
      pbcext_element_G1_free(cpy06_dst->x); cpy06_dst->x = NULL;
    }
    if (cpy06_dst->y) {
      pbcext_element_G1_free(cpy06_dst->y); cpy06_dst->y = NULL;
    }
    if (cpy06_dst->z) {
      pbcext_element_G1_free(cpy06_dst->z); cpy06_dst->z = NULL;
    }
    if (cpy06_dst->T5) {
      pbcext_element_GT_free(cpy06_dst->T5); cpy06_dst->T5 = NULL;
    }
    if (cpy06_dst->e2) {
      pbcext_element_GT_free(cpy06_dst->e2); cpy06_dst->e2 = NULL;
    }
    if (cpy06_dst->e3) {
      pbcext_element_GT_free(cpy06_dst->e3); cpy06_dst->e3 = NULL;
    }
    if (cpy06_dst->e4) {
      pbcext_element_GT_free(cpy06_dst->e4); cpy06_dst->e4 = NULL;
    }
    if (cpy06_dst->e5) {
      pbcext_element_GT_free(cpy06_dst->e5); cpy06_dst->e5 = NULL;
    }    
  }
  
  return rc;

}

int cpy06_grp_key_get_size(groupsig_key_t *key) {

  cpy06_grp_key_t *cpy06_key;
  uint64_t size64, sq, sr, sw, sx, sy, sz, sT5, se2, se3, se4, se5;
  
  if(!key || key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_grp_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  cpy06_key = key->key;

  sq = sr = sw = sx = sy = sz = sT5 = se2 = se3 = se4 = se5 = 0;

  if(pbcext_element_G1_byte_size(&sq) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sr) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sw) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sx) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sy) == IERROR) return -1;  
  if(pbcext_element_G1_byte_size(&sz) == IERROR) return -1;
  if(pbcext_element_GT_byte_size(&sT5) == IERROR) return -1;
  if(pbcext_element_GT_byte_size(&se2) == IERROR) return -1;
  if(pbcext_element_GT_byte_size(&se3) == IERROR) return -1;
  if(pbcext_element_GT_byte_size(&se4) == IERROR) return -1;
  if(pbcext_element_GT_byte_size(&se5) == IERROR) return -1;  

  size64 = sizeof(uint8_t)*2 + sizeof(int)*11 + sq + sr + sw + sx + sy + sz +
    sT5 + se2 + se3 + se4 + se5;
  if (size64 > INT_MAX) return -1;

  return (int) size64;

}

int cpy06_grp_key_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_key_t *key) {

  cpy06_grp_key_t *cpy06_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  
  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_grp_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  cpy06_key = key->key;

  /* Get the number of bytes to represent the key */
  if ((_size = cpy06_grp_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_CPY06_CODE */
  _bytes[ctr++] = GROUPSIG_CPY06_CODE;

  /* Dump key type */
  _bytes[ctr++] = GROUPSIG_KEY_GRPKEY;

  /* Dump q */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, cpy06_key->q) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_export);
  ctr += len;

  /* Dump r */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, cpy06_key->r) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_export);
  ctr += len;

  /* Dump w */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, cpy06_key->w) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_export);
  ctr += len;

  /* Dump x */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, cpy06_key->x) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_export);
  ctr += len;

  /* Dump y */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, cpy06_key->y) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_export);
  ctr += len;

  /* Dump z */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, cpy06_key->z) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_export);
  ctr += len;

  /* Dump T5 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, cpy06_key->T5) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_export);
  ctr += len;

  /* Dump e2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, cpy06_key->e2) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_export);
  ctr += len;

  /* Dump e3 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, cpy06_key->e3) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_export);
  ctr += len;

  /* Dump e4 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, cpy06_key->e4) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_export);
  ctr += len;

  /* Dump e5 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, cpy06_key->e5) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_grp_key_export", __LINE__,
                      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_grp_key_export);
  }

  *size = ctr;

 cpy06_grp_key_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  return rc;  
  
}

groupsig_key_t* cpy06_grp_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  cpy06_grp_key_t *cpy06_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_grp_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(key = cpy06_grp_key_init())) {
    return NULL;
  }

  cpy06_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_grp_key_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_GRPKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_grp_key_import", __LINE__,
                      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  }

  /* Get q */
  if(!(cpy06_key->q = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  if(pbcext_get_element_G1_bytes(cpy06_key->q, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  ctr += len;

  /* Get r */
  if(!(cpy06_key->r = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  if(pbcext_get_element_G2_bytes(cpy06_key->r, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  ctr += len;

  /* Get w */
  if(!(cpy06_key->w = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  if(pbcext_get_element_G2_bytes(cpy06_key->w, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  ctr += len;

  /* Get x */
  if(!(cpy06_key->x = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  if(pbcext_get_element_G1_bytes(cpy06_key->x, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  ctr += len;

  /* Get y */
  if(!(cpy06_key->y = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  if(pbcext_get_element_G1_bytes(cpy06_key->y, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  ctr += len;

  /* Get z */
  if(!(cpy06_key->z = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  if(pbcext_get_element_G1_bytes(cpy06_key->z, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  ctr += len;

  /* Get T5 */
  if(!(cpy06_key->T5 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  if(pbcext_get_element_GT_bytes(cpy06_key->T5, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  ctr += len;

  /* Get e2 */
  if(!(cpy06_key->e2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  if(pbcext_get_element_GT_bytes(cpy06_key->e2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  ctr += len;

  /* Get e3 */
  if(!(cpy06_key->e3 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  if(pbcext_get_element_GT_bytes(cpy06_key->e3, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  ctr += len;

  /* Get e4 */
  if(!(cpy06_key->e4 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  if(pbcext_get_element_GT_bytes(cpy06_key->e4, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  ctr += len;

  /* Get e5 */
  if(!(cpy06_key->e5 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  if(pbcext_get_element_GT_bytes(cpy06_key->e5, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_import);
  ctr += len;  

 cpy06_grp_key_import_end:
  
  if(rc == IERROR && key) { cpy06_grp_key_free(key); key = NULL; }
  if(rc == IOK) return key;

  return NULL;  

}

char* cpy06_grp_key_to_string(groupsig_key_t *key) { 

  char *q, *r, *w, *x, *y, *z, *T5, *e2, *e3, *e4, *e5, *skey;
  uint64_t q_len, r_len, w_len, x_len, y_len, z_len;
  uint64_t T5_len, e2_len, e3_len, e4_len, e5_len;
  uint32_t skey_len;
  int rc;

  g = r = w = x = y = z = T5 = e2 = e3 = e4 = e5 = NULL;
  skey = NULL;
  rc = IOK;
  
  if(pbcext_element_G1_to_string(&q,
                                 &q_len,
                                 10,
                                 gkey->q) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_to_string);

  if(pbcext_element_G2_to_string(&r,
                                 &r_len,
                                 10,
                                 gkey->r) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_to_string);

  if(pbcext_element_G2_to_string(&w,
                                 &w_len,
                                 10,
                                 gkey->w) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_to_string);  
  
  if(pbcext_element_G1_to_string(&x,
                                 &q_len,
                                 10,
                                 gkey->x) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_to_string);

  if(pbcext_element_G1_to_string(&y,
                                 &y_len,
                                 10,
                                 gkey->y) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_to_string);

  if(pbcext_element_G1_to_string(&z,
                                 &z_len,
                                 10,
                                 gkey->z) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_to_string);

  if(pbcext_element_GT_to_string(&T5,
                                 &T5_len,
                                 10,
                                 gkey->T5) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_to_string);

  if(pbcext_element_GT_to_string(&e2,
                                 &e2_len,
                                 10,
                                 gkey->e2) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_to_string);

  if(pbcext_element_GT_to_string(&e3,
                                 &e3_len,
                                 10,
                                 gkey->e3) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_to_string);

  if(pbcext_element_GT_to_string(&e4,
                                 &e4_len,
                                 10,
                                 gkey->e4) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_to_string);

  if(pbcext_element_GT_to_string(&e5,
                                 &e5_len,
                                 10,
                                 gkey->e5) == IERROR)
    GOTOENDRC(IERROR, cpy06_grp_key_to_string);

  if (!q || !r || !w || !x || !y || !z || !T5 || !e2 || !e3 || !e4 || !e5)
    GOTOENDRC(IERROR, cpy06_grp_key_to_string);

  skey_len = strlen(q) + strlen(r) + strlen(w) + strlen(x) + strlen(y) +
    strlen(z) + strlen(T5) + strlen(e2) + strlen(e3) + strlen(e4) + strlen(e5) +
    strlen("q: \nr: \nw: \nx: \ny: \nz: \nT5: e2: \ne3: \ne4: \ne5") + 1;
  
  if (!(skey = (char *) malloc(sizeof(char)*skey_len)))
    GOTOENDRC(IERROR, cpy06_grp_key_to_string);

  memset(skey, 0, sizeof(char)*skey_len);

  sprintf(skey,
          "q: %s\n"
          "r: %s\n"
          "w: %s\n"
          "x: %s\n"
	  "y: %s\n"
	  "z: %s\n"
	  "T5: %s\n"
	  "e2: %s\n"
	  "e3: %s\n"
	  "e4: %s\n"
	  "e5: %s\n",
          q, r, w, x, y, z, T5, e2, e3, e4, e5);

 cpy06_grp_key_to_string_end:

  if (q) { mem_free(q); q = NULL; }
  if (r) { mem_free(r); r = NULL; }
  if (w) { mem_free(w); w = NULL; }
  if (x) { mem_free(x); x = NULL; }
  if (y) { mem_free(y); y = NULL; }
  if (z) { mem_free(z); z = NULL; }
  if (T5) { mem_free(T5); T5 = NULL; }
  if (e2) { mem_free(e2); e2 = NULL; }
  if (e3) { mem_free(e3); e3 = NULL; }
  if (e4) { mem_free(e4); e4 = NULL; }
  if (e5) { mem_free(e5); e5 = NULL; }  

  return skey;
  
}

/* grp_key.c ends here */
