/****************************************************************************************/
/*
 *  IMSE.CNM_SPIRS_RoT_DEMO: mmio.h
 *
 *  Updated on: 13/09/2023
 */
/****************************************************************************************/

#ifndef MMIO_INCLUDED
#define MMIO_INCLUDED

#define SUCCESS 1
#define ERROR   0

/************************************* Include Files ************************************/

#if defined(PYNQZ2)
  #include <pynq_api.h>
#endif

  #include <stdio.h>
  #include <string.h>
  #include <stdlib.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <math.h>
  #include <sys/time.h>
  #include <sys/mman.h>


/************************************* Data structures **********************************/

 #define MEMORY_DEV_PATH "/dev/mem"

 #if !defined(STANDALONE)
  typedef struct id_mmio_state_struct {
    char * buffer;
    int file_handle;
    unsigned int length, address_base, virt_base, virt_offset;
  } MMIO_WINDOW;
 #else
  typedef int MMIO_WINDOW;
 #endif


/****************************************************************************************/
/******************************** Function Prototypes ***********************************/
/****************************************************************************************/

 #if !defined(STANDALONE)
	
  int createMMIOWindow(MMIO_WINDOW * state, size_t address_base, size_t length);

  int closeMMIOWindow(MMIO_WINDOW * state);

  int writeMMIO(MMIO_WINDOW * state, void * data, size_t offset, size_t size_data);

  int readMMIO(MMIO_WINDOW * state, void * data, size_t offset, size_t size_data);

 #endif

  unsigned long long Wtime();

/****************************************************************************************/

 #if defined(PYNQ)

  int Set_Clk_Freq( unsigned int clk_index, float * clk_frequency, float * set_clk_frequency);
  
 #endif


#endif  //  MMIO_INCLUDED
