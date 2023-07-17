#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include "utils.h"

const char* correct_value(int val)
{
  if (val == 1)
    return "✔";
  return "𐄂";
}

void print_time(char *prefix, clock_t start, clock_t end) {
  printf("%stime: %.8f sec\n", prefix,
         ((double) (end - start)) / CLOCKS_PER_SEC);
}

void print_exp_rc(char *prefix, int value) {
  printf("%src expected (v:%d==e:%d)?: %s\n",
         prefix, value, IOK, correct_value(value == IOK));
}

void print_exp_ptr(char *prefix, void *pointer) {
  printf("%s expected?: %s\n", prefix, correct_value(pointer != NULL));
}

void print_exp_ret(char *prefix, uint8_t value, int expected) {
  printf("%sreturn expected (v:%d==e:%d)?: %s\n",
         prefix, value, expected, correct_value(value == expected));
}

void print_to_str(char *prefix, char *str) {
  printf("%s to_string:\n%s\n", prefix, str);
}
