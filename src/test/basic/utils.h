#ifndef UTILS_H
#define UTILS_H

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "groupsig.h"

#define SETUP1_T 0
#define SETUP2_T 1
#define SIGN_T 2
#define VERIFY_T 3
#define OPEN_1_T 4
#define OPEN_N_T 5
#define OPEN_VERIFY_T 6
#define REVEAL_1_T 7
#define REVEAL_N_T 8
#define TRACE_1_T 9
#define TRACE_N_T 10
#define CLAIM_T 11
#define CLAIM_VERIFY_T 12
#define PROVE_EQUALITY_T 13
#define PROVE_EQUALITY_VERIFY_T 14
#define BLIND_T 15
#define CONVERT_T 16
#define UNBLIND_T 17
#define LINK_T 18
#define LINK_VERIFY_T 19
#define SEQLINK_T 20
#define SEQLINK_VERIFY_T 21
// Total metrics
#define N_BENCH 22

// Start: 1
#define JOIN_MEM0_T 0
#define JOIN_MGR1_T 1
#define JOIN_MEM2_T 2
#define JOIN_MGR3_T 3
#define JOIN_MEM4_T 4
// Start: 0
#define JOIN_MGR0_T 5
#define JOIN_MEM1_T 6
#define JOIN_MGR2_T 7
#define JOIN_MEM3_T 8
// Total join metrics
#define N_JOIN 9
#define BILLION 1000000000L
#define CLOCK_FREQ 50000000L


void test_libgroupsig(char *scheme);
void benchmark_libgroupsig(char *scheme, int iter);
int multi_mgrkey(char *scheme);
int group1_implemented(char *scheme);
int group2_implemented(char *scheme);
int group3_implemented(char *scheme);
int group4_implemented(char *scheme);
int group5_implemented(char *scheme);
int group6_implemented(char *scheme);
void random_seed();
/* #define RISCV */
#if defined(RISCV)
void save_join(const unsigned char, int, unsigned long, unsigned long, int);
#else
void save_join(const unsigned char, int, struct timespec, struct timespec, int);
#endif

extern uint64_t TIMES[];
extern uint64_t **TIMES_JOIN;
extern int MEMBERS;
extern int ITER;
extern char *PATH;
#endif
