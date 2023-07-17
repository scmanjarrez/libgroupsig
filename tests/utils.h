#ifndef UTILS_H
#define UTILS_H

#define IOK 0
#define IERROR 1

#include <time.h>
#include <stdint.h>

const char* correct_value(int val);

void print_time(char *prefix, clock_t start, clock_t end);

void print_exp_rc(char *prefix, int value);

void print_exp_ptr(char *prefix, void *pointer);

void print_exp_ret(char *prefix, uint32_t value, int expected);

void print_to_str(char *prefix, char *str);

void kty04_test(void);

void ps16_test(void);

/* void dl21seq_test(void); */

#endif
