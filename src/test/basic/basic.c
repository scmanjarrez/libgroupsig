#include <ctype.h>
#include <getopt.h>

#include "utils.h"


char *SCHEMES[] = {"bbs04", "ps16", "cpy06",
                   "kty04", "klap20", "gl19",
                   "dl21", "dl21seq"};
const int N_SCHEMES = sizeof(SCHEMES) / sizeof(SCHEMES[0]);


int valid_scheme(char *scheme) {
  for (int i = 0; i < N_SCHEMES; i++) {
    if (!strcmp(scheme, SCHEMES[i])) {
      return 1;
    }
  }
  if (!strcmp(scheme, "all"))
      return 1;
  return 0;
}

int is_digit(char* str) {
  if (!str)
    return 0;
  for (int i = 0; i < strlen(str); i++) {
    if (!isdigit(str[i])) {
      return 0;
    }
  }
  return 1;
}

void load_hw() {
  int v = 1;

#if defined(PYNQZ2)
  int Status;
  FILE *bptr;
  char* bitstream_file = "/home/xilinx/RoT_demo_4.0_Z2/bit/SPIRS_RoT.bit";
  if ((bptr = fopen(bitstream_file, "r"))) {
    fclose(bptr);
  } else {
    printf("\n   Bitstream doesn't exist. Bye ...\n\n");
    exit(ERROR);
  }
  if (v >= 1)
    printf("\n   Loading Bitstream ...");
  Status = PYNQ_loadBitstream(bitstream_file);
  if (Status != SUCCESS) {
    printf("LoadBitstream Failure\n");
    return ERROR;
  }
  if (v >= 1)
    printf(" done \n");
#endif
}

void usage(char *name, int ret) {
  printf("Usage: %s <SCHEME> [OPTS]\n"
         "SCHEME:\n"
         "\tThe scheme can be any of the following values: bbs04, gl19, klap20, ps16, dl21, dl21seq, cpy06, kty04.\n"
         "OPTS:\n"
         "\t-b|--benchmark\t\t Run benchmark instead of tests.\n"
         "\t-i|--iterations N\t Number of benchmark iterations. Default: 5\n"
         "\t-m|--members N\t\t Number of members to register in the group. Default: 10\n"
         "\t-p|--path PATH\t\t Output directory of *csv. Default: '.'\n"
         "\t-h|--help\t\t This message.\n\n",
         name);
  exit(ret);
}

void setup_matrices() {
  TIMES_JOIN = (clock_t **)calloc(N_JOIN, sizeof(clock_t *));
  if (!TIMES_JOIN) {
    fprintf(stderr, "TIMES_JOIN: Memory allocation failed\n");
    exit(1);
  }
  for (int i = 0; i < N_JOIN; i++) {
    TIMES_JOIN[i] = (clock_t *)calloc(MEMBERS, sizeof(clock_t));
    if (!TIMES_JOIN[i]) {
      fprintf(stderr, "TIMES_JOIN[%d]: Memory allocation failed\n", i);
      exit(1);
    }
  }
}

void reset_matrices() {
  memset(TIMES, 0, N_BENCH * sizeof(clock_t));
  for (int i = 0; i < N_JOIN; i++) {
    memset(TIMES_JOIN[i], 0, MEMBERS * sizeof(clock_t));
  }
}

int main(int argc, char **argv) {
#ifdef HW
  load_hw();
#endif

  char *scheme = NULL;
  random_seed();

  int opt;
  int opt_idx = 0;
  int benchmark_flag = 0;
  static struct option long_options[] = {
    {"benchmark", no_argument, 0, 'b'},
    {"iterations", required_argument, 0, 'i'},
    {"members", required_argument, 0, 'm'},
    {"path", required_argument, 0, 'p'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };

  while ((opt = getopt_long(argc, argv, "bhi:m:",
                            long_options, &opt_idx)) != -1) {
    switch (opt) {
    case 'b':
      benchmark_flag = 1;
      break;
    case 'i':
      if (is_digit(optarg))
        ITER = atoi(optarg);
      break;
    case 'm':
      if (is_digit(optarg))
        MEMBERS = atoi(optarg);
      break;
    case 'p':
      PATH = optarg;
      break;
    case 'h':
      usage(argv[0], 0);
      break;
    case '?':
    default:
      usage(argv[0], 1);
    }
  }

  // Remaining arguments are positional
  for (int i = optind; i < argc; i++) {
    if (valid_scheme(argv[i])) {
      scheme = argv[i];
      break;
    }
  }
  if (!scheme) {
    printf("Error: missing scheme\n\n");
    usage(argv[0], 1);
  }

  if (MEMBERS < 3) {
    printf("Error: members must be greater than 3\n\n");
    usage(argv[0], 1);
  }

  setup_matrices();

  if (!benchmark_flag) {
    if (!strcmp(scheme, "all"))
      for (int i = 0; i < N_SCHEMES; i++) {
        printf("#### Testing %s\n", SCHEMES[i]);
        test_libgroupsig(SCHEMES[i]);
      }
    else
      test_libgroupsig(scheme);
  } else {
    if (!strcmp(scheme, "all")) {
      for (int i = 0; i < N_SCHEMES; i++) {
        reset_matrices();
        printf("#### Benchmarking %s\n", SCHEMES[i]);
        for (int j = 0; j < ITER; j++) {
          benchmark_libgroupsig(SCHEMES[i], j);
        }
      }
    } else {
      printf("#### Benchmarking %s\n", scheme);
      for (int j = 0; j < ITER; j++) {
        benchmark_libgroupsig(scheme, j);
      }
    }
  }

  for (int i = 0; i < N_JOIN; i++)
    free(TIMES_JOIN[i]);
  free(TIMES_JOIN);
  return 0;
}
