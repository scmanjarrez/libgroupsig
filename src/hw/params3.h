/****************************************************************************************/
/*
 *  IMSE.CNM_SPIRS_sha3__xl_1.0: paramas.h 
 *
 *  Created on: 14/09/2023
 *      Author: camacho@imse-cnm.csic.es
*/
/****************************************************************************************/

// MDLEN: 28 (SHA3-224), 32 (SHA3-256), 48 (SHA3-386), 64 (SHA3-512)

#ifdef SHA3_512

  #define SIZE_SHA3 512
  // define MS2XL_BASEADDR 0x43C50000
  #define MDLEN 64

#elif SHA3_384

  #define SIZE_SHA3 384
  // #define MS2XL_BASEADDR 0x43C10000
  #define MDLEN 48

#elif SHA3_256

  #define SIZE_SHA3 256
  // #define MS2XL_BASEADDR 0x43C20000
  #define MDLEN 32

#elif SHA3_224

  #define SIZE_SHA3 224
  //#define MS2XL_BASEADDR 0x43C30000
  #define MDLEN 28

#else

  #define SIZE_SHA3 512
  // #define MS2XL_BASEADDR 0x43C50000
  #define MDLEN 64

#endif

  #define SIZE_BYTE 1000000
  #define SIZE_BITS SIZE_BYTE * 8
  #define SIZE_INPUT SIZE_BITS / 8
  #define SIZE_OUTPUT SIZE_SHA3 / 8

  #define MAX_LINE_LENGTH SIZE_INPUT

  #define SIZE_BLOCK (1600 - (2*SIZE_SHA3))
