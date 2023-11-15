/****************************************************************************************/
/*
 *  IMSE.CNM_SPIRS_sha2_xl_3.0: params.h 
 *
 *  Created on: 17/09/2023
 *      Author: camacho@imse-cnm.csic.es
*/
/****************************************************************************************/


#ifdef SHA_224

#define _SHA_224_

#define SIZE_SHA2 224
#define	SIZE_BLOCK 512
//#define MS2XL_BASEADDR 0x43C00000
#define WIDTH 32
#define NAME "SHA224"

#elif SHA_256

#define _SHA_256_
#define SIZE_SHA2 256
#define	SIZE_BLOCK 512
//#define MS2XL_BASEADDR 0x43C10000
#define WIDTH 32
#define NAME "SHA256"

#elif SHA_384

#define _SHA_384_
#define SIZE_SHA2 384
#define	SIZE_BLOCK 1024
//#define MS2XL_BASEADDR 0x43C20000
#define WIDTH 64
#define NAME "SHA384"

#elif SHA_512

#define _SHA_512_
#define SIZE_SHA2 512
#define	SIZE_BLOCK 1024
//#define MS2XL_BASEADDR 0x43C30000
#define WIDTH 64
#define NAME "SHA512"

#elif SHA_512_224

#define _SHA_512_224_
#define SIZE_SHA2 224
#define	SIZE_BLOCK 1024
//#define MS2XL_BASEADDR 0x43C40000
#define WIDTH 64
#define NAME "SHA512_224"

#elif SHA_512_256

#define _SHA_512_256_
#define SIZE_SHA2 256
#define	SIZE_BLOCK 1024
//#define MS2XL_BASEADDR 0x43C50000
#define WIDTH 64
#define NAME "SHA512_256"

#else

#define _SHA_256_
#define SIZE_SHA2 256
#define	SIZE_BLOCK 512
//#define MS2XL_BASEADDR 0x43C10000
#define WIDTH 32
#define NAME "SHA256"

#endif

#define SIZE_BYTE 1000000
#define SIZE_BITS SIZE_BYTE * 8
#define SIZE_INPUT SIZE_BITS / 8
#define SIZE_OUTPUT SIZE_SHA2 / 8

#define MAX_LINE_LENGTH SIZE_INPUT
