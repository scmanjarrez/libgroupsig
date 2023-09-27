/****************************************************************************************/
/*
 *  file_hw.c
 *
 *  Created on: 28/03/2023
 *  Authors: macarena@imse-cnm.csic.es and sergio.galan@csic.es
 */
/****************************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include "../rsa/rsa_axi.h"
#include "functions_hw.h"
#include "sha2_hw.h"
#include "mmio.h"
#include "file_hw.h"
#include <pynq_api.h>


#define SIZE_SHA2 256
#define SIZE_STREAM 32
#define SIZE_BYTE (unsigned long long)512E3
#define SIZE_BITS SIZE_BYTE * 8
#define SIZE_INPUT SIZE_BITS / 8
#define SIZE_OUTPUT SIZE_SHA2 / 8
#define PYNQZ2 1
#define AXI64 1

unsigned char* ull_to_bytes(unsigned long long* ulls, int len) {
    int num_bytes = len * sizeof(unsigned long long);
    unsigned char* result = calloc(num_bytes, sizeof(unsigned char));
    unsigned char* aux_ptr = result;

    for (int i = 0; i < len; i++) {
        unsigned long long ull = ulls[i];
        for (int j = 0; j < sizeof(unsigned long long); j++) {
            *(aux_ptr++) = (ull >> ((sizeof(unsigned long long) - j - 1) * 8)) & 0xFF;
        }
    }
    return result;
}

unsigned char* ui_to_bytes(unsigned int* uis, int len) {
    int num_bytes = len * sizeof(unsigned int);
    unsigned char* result = calloc(num_bytes, sizeof(unsigned char));
    unsigned char* aux_ptr = result;

    for (int i = 0; i < len; i++) {
        unsigned int ui = uis[i];
        for (int j = 0; j < sizeof(unsigned int); j++) {
            *(aux_ptr++) = (ui >> ((sizeof(unsigned int) - j - 1) * 8)) & 0xFF;
        }
    }
    return result;
}

unsigned long long* bytes_to_ull(unsigned char *bytes, int len) {
	int len_ull = len/sizeof(unsigned long long);
	if(len%sizeof(unsigned long long)) {
		len_ull++;
	}
	int counter_ull = len_ull - 1;
	int j = 0;
	unsigned long long *ret = calloc(len_ull, sizeof(unsigned long long));
	for(int i = len - 1; i > -1; i--) {
		ret[counter_ull] +=  ((unsigned long long) bytes[i]) << (8 * j);
		j++;
		if(j == sizeof(unsigned long long)) {
			counter_ull--;
			j = 0;
		}
	}
	return ret;
}


unsigned int* bytes_to_uint(unsigned char *bytes, int len) {
	int len_uint = len/sizeof(unsigned int);
	if(len%sizeof(unsigned int)) {
		len_uint++;
	}
	int counter_uint = len_uint - 1;
	int j = 0;
	unsigned int *ret = calloc(len_uint, sizeof(unsigned int));
	for(int i = len - 1; i > -1; i--) {
		ret[counter_uint] +=  ((unsigned int) bytes[i])<< (8 * j);
		j++;
		if(j == sizeof(unsigned int)) {
			counter_uint--;
			j = 0;
		}
	}
	return ret;
}

/* unsigned char* mod_exp_hw(unsigned char *base, int base_len, unsigned char *exp, int exp_len, unsigned char *mod, int mod_len){

	//int v = 1;


	MMIO_WINDOW ms2xl;
	createMMIOWindow(&ms2xl, MS2XL_BASEADDR, MS2XL_LENGTH);

	//unsigned char in[SIZE_INPUT];
	//unsigned char out_hw[SIZE_OUTPUT];
	//unsigned long long length; //Where the length comes from?
	
	unsigned char * res= NULL;

	#if defined (AXI64)
	unsigned long long *aux_res = NULL;
	unsigned long long *aux_base = bytes_to_ull(base, base_len);
	unsigned long long *aux_exp = bytes_to_ull(exp, exp_len);
	unsigned long long *aux_mod = bytes_to_ull(mod, mod_len);

	#else
	unsigned int *aux_res = NULL;
	unsigned int *aux_base = bytes_to_uint(base, base_len);
	unsigned int *aux_exp = bytes_to_uint(exp, exp_len);
	unsigned int *aux_mod = bytes_to_uint(mod, mod_len);
	#endif

	// Modular Exponentiation HW Execution
	
	int DBG=0;
	
	aux_res = RSA_SIGN(aux_base, aux_exp, aux_mod, DBG);
	#if defined (AXI64)
		res = ull_to_bytes(aux_res, 1024/8/sizeof(unsigned long long));
	#else		
		res = uint_to_bytes(aux_res, 1024/8/sizeof(unsigned int));

	#endif
	return res;

} */

int load_hw(){

	int v = 1;


 #if defined(PYNQZ2)

  	int Status;
 	FILE *bptr;
	char* bitstream_file = "./bit/SPIRS_RoT.bit";

	if ((bptr = fopen(bitstream_file, "r"))) {
		fclose(bptr);
	} else {
		printf("\n   Bitstream doesn't exist. Bye ...\n\n");
		exit(ERROR);
	}

	if (v >= 1) printf("\n   Loading Bitstream ...");

	Status = PYNQ_loadBitstream(bitstream_file);
	if (Status != SUCCESS) {
		printf("LoadBitstream Failure\n");
		return ERROR;
	}

    if (v >= 1) printf(" done \n");

  #endif
	return 0;

}

unsigned char* hash_message_hw(unsigned char* msg, int msg_len){


	int v = 1;


	MMIO_WINDOW ms2xl;
	createMMIOWindow(&ms2xl, MS2XL_BASEADDR, MS2XL_LENGTH);

	//unsigned char in[SIZE_INPUT];
	unsigned char out_hw[SIZE_OUTPUT];
	//unsigned long long length; //Where the length comes from?
	//for (int i=1;i<=msg_len;i++){
		//code to pass byte_t to char
	//	in[i]= msg[i];
	//} 
	
	// SHA2 HW Execution
	int DBG=1;
	printf("Data to be sent to sha256_hw:\nin=%s\nmsg_len=%d\n", msg, msg_len);
	sha256_hw(msg, out_hw,msg_len, ms2xl, DBG);
	
	// code to pass char to pointer of byte_t
	unsigned char * hashed_msg = NULL;
	hashed_msg=malloc(SIZE_OUTPUT*sizeof(unsigned char));
	memcpy(hashed_msg, out_hw, SIZE_OUTPUT);
	return hashed_msg;

}
