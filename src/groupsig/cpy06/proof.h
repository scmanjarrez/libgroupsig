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

#ifndef _CPY06_PROOF_H
#define _CPY06_PROOF_H

#include <stdint.h>

#include "include/proof.h"
#include "shim/pbc_ext.h"
#include "cpy06.h"

/* @TODO: The code here can probably simplified/optimized via the crypto/spk.h
   module (as an spk_rep_t proof). Not sure though, so leaving as technical 
   debt. */

/**
 * @struct cpy06_proof_t
 * @brief General NIZK proofs of knowledge for CPY06.
 */
typedef struct {
  pbcext_element_Fr_t *c; /**< */
  pbcext_element_Fr_t *s; /**< */
} cpy06_proof_t;

/** 
 * @fn struct groupsig_proof_t* cpy06_proof_init()
 * @brief Initializes the fields of a CPY06 proof.
 *
 * @return A pointer to the allocated proof or NULL if error.
 */
groupsig_proof_t* cpy06_proof_init();

/** 
 * @fn int cpy06_proof_free(groupsig_proof_t *proof)
 * @brief Frees the alloc'ed fields of the given CPY06 proof.
 *
 * @param[in,out] proof The proof to free.
 * 
 * @return IOK or IERROR
 */
int cpy06_proof_free(groupsig_proof_t *proof);

/* /\**  */
/*  * @fn int cpy06_proof_init_set_c(cpy06_proof_t *proof, pbcext_element_Fr_t *c) */
/*  * Initializes the c field of the given proof and sets it to the specified value. */
/*  *  */
/*  * @param[in,out] proof The proof whose c field is to be initialized and set. */
/*  * @param[in] c The value to copy into proof->c. */
/*  *  */
/*  * @return IOK or IERROR */
/*  *\/ */
/* int cpy06_proof_init_set_c(cpy06_proof_t *proof, pbcext_element_Fr_t *c); */

/* /\**  */
/*  * @fn int cpy06_proof_init_set_s(cpy06_proof_t *proof, pbcext_element_Fr_t *s) */
/*  * Initializes the s field of the given proof and sets it to the specified value. */
/*  *  */
/*  * @param[in,out] proof The proof whose s field is to be initialized and set. */
/*  * @param[in] s The value to copy into proof->s. */
/*  *  */
/*  * @return IOK or IERROR */
/*  *\/ */
/* int cpy06_proof_init_set_s(cpy06_proof_t *proof, pbcext_element_Fr_t *s); */

/** 
 * @fn int cpy06_proof_copy(groupsig_proof_t *dst, groupsig_proof_t *src)
 * @brief Copies the given proof into a new one.
 *
 * @param[in,out] dst The destination proof. Initialized by the caller.
 * @param[in] src The proof to copy.
 * 
 * @return IOK or IERROR.
 */
int cpy06_proof_copy(groupsig_proof_t *dst, groupsig_proof_t *src);

/** 
 * @fn int cpy06_proof_to_string
 * @brief Returns a printable string representing the current proof.
 *
 * @param[in] proof The proof to print.
 * 
 * @return IOK or IERROR
 */
char* cpy06_proof_to_string(groupsig_proof_t *proof);

/** 
 * @fn int cpy06_proof_get_size(groupsig_proof_t *proof)
 * @brief Returns the size of the proof as an array of bytes.
 *
 * @param[in] proof The proof.
 * 
 * @return -1 if error, the size the size that this proof would have in case
 *  of being exported to an array of bytes.
 */
int cpy06_proof_get_size(groupsig_proof_t *proof);

/** 
 * @fn int cpy06_proof_export(byte_t **bytes, 
 *                            uint32_t *size, 
 *                            groupsig_proof_t *proof);
 * @brief Writes a bytearray representation of the given proof, with format:
 *
 * | CPY06_CODE | sizeof(c) | c | sizeof(s) | s |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported 
 *  proof. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] proof The proof to export.
 * 
 * @return IOK or IERROR with errno updated.
 */
int cpy06_proof_export(byte_t **bytes, uint32_t *size, groupsig_proof_t *proof);

/** 
 * @fn int cpy06_proof_import(byte_t *source, uint32_t size)
 * @brief Imports a proof according to the specified format.
 *
 * @param[in] format The format of the proof to import.
 * @param[in] source The proof to be imported.
 * 
 * @return IOK or IERROR
 */
groupsig_proof_t* cpy06_proof_import(byte_t *source, uint32_t size);

/**
 * @var cpy06_proof_handle
 * @brief Set of functions to manage CPY06 proofs.
 */
static const groupsig_proof_handle_t cpy06_proof_handle = {
  .scheme = GROUPSIG_CPY06_CODE, /**< The scheme code. */
  .init = &cpy06_proof_init, /**< Initalizes proofs. */
  .free = &cpy06_proof_free, /**< Frees proofs. */
  .copy = &cpy06_proof_copy, /**< Copies proofs. */
  .get_size = &cpy06_proof_get_size, /**< Gets the size of a proof in the
					specified format. */
  .gexport = &cpy06_proof_export, /**< Exports proofs. */
  .gimport = &cpy06_proof_import, /**< Imports proofs. */
  .to_string = &cpy06_proof_to_string /**< Gets printable representations of
					 proofs. */
};

#endif /* _CPY06_PROOF_H */

/* proof.h ends here */
