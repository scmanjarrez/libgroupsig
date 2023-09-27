//#include "../rsa/rsa_axi.h"
#include "functions_hw.h"
#include "sha2_hw.h"

unsigned char* ull_to_bytes(unsigned long long* ulls, int len) ;
unsigned char* ui_to_bytes(unsigned int* uis, int len);
unsigned long long* bytes_to_ull(unsigned char *bytes, int len);
unsigned int* bytes_to_uint(unsigned char *bytes, int len);
//unsigned char* mod_exp_hw(unsigned char *base, int base_len, unsigned char *exp, int exp_len, unsigned char *mod, int mod_len);
int load_hw();
unsigned char* hash_message_hw(unsigned char* msg, int msg_len);
