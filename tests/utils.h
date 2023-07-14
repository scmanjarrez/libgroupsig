#ifndef UTILS_H
#define UTILS_H

#define IOK 0
#define IERROR 1

const char* correct_value(int val);

void print_time(char *prefix, clock_t start, clock_t end);

void print_exp_rc(char *prefix, int value);

void print_exp_ptr(char *prefix, void *pointer);

void print_exp_ret(char *prefix, uint8_t value, int expected);

void print_to_str(char *prefix, char *str);

#endif
