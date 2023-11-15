/****************************************************************************************/
/*
 *  IMSE.CNM_SPIRS_sha3__xl_1.0: sha3_hw.h 
 *
 *  Created on: 14/09/2023
 *      Author: camacho@imse-cnm.csic.es
 */
/****************************************************************************************/

#ifndef SHA3_HW_H_INCLUDED
#define SHA3_HW_H_INCLUDED

/************************ MS2XL Constant Definitions **********************/

#if defined(G2RISCV)
  #define MS2XL_BASEADDR 0x60080000
#else
  #define MS2XL_BASEADDR 0x43C40000
#endif

#define MEMORY_DEV_PATH "/dev/mem"
#define MS2XL_LENGTH   0x40

#define RESET					1
#define LOAD_PADDING			2
#define START_PADDING			4
#define LOAD					8
#define START					16
#define	READ					32
#define	START_PADDING_DOUBLE	64

#define DATA_IN  0x0		/**< data_in */
#define ADDRESS  0x8		/**< address */
#define CONTROL  0x10		/**< control */
#define DATA_OUT 0x18		/**< data_out */
#define END_OP   0x20		/**< end_op */

/************************************* Include Files ************************************/

#include "params3.h"
#include "mmio.h"

 #if defined(PYNQ)
  #include <pynq_api.h>
 #endif

/****************************************************************************************/
/****************************** MS2XL Function Definitions ******************************/
/****************************************************************************************/

void sha3_ms2xl_init(MMIO_WINDOW ms2xl);
void sha3_ms2xl(unsigned long long int* a, unsigned long long int* b, MMIO_WINDOW ms2xl, unsigned long long int pos_pad, int pad, int DBG);
void sha3_hw(unsigned char* in, unsigned char* out, unsigned long long int length, MMIO_WINDOW ms2xl, int DBG);

/****************************************************************************************/

#endif // SHA3_HW_H_INCLUDED
