#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "groupsig.h"
#include "ps16.h"
#include "shim/base64.h"

int CODE = -1;
char *SCHEME = "ps16";
char *DIRE = "./build";
char *AFFIX = "";
char *SIG_PATH = NULL;
char GRPKEY[1024];
char MGRKEY[1024];
char GML[1024];

int file_readable(char* file) {
  FILE *fp = fopen(file, "r");
  if (fp == NULL) {
    return 0;
  } else {
    fclose(fp);
    return 1;
  }
}

void check_ptr(void *ptr, char *msg) {
  if (ptr == NULL) {
    fprintf(stderr, "Error: %s initialization\n", msg);
    exit(1);
  }
}

void scheme_from_code() {
  if (CODE == GROUPSIG_PS16_CODE) {
    SCHEME = "ps16";
  } else {
    fprintf(stderr, "Error: Could not detect scheme from code\n");
    exit(1);
  }
}

void check_size(int size1, int size2, char *msg) {
  if (size1 != size2) {
    fprintf(stderr, "Error: incorrect %s export size (%d): expected %d\n",
            msg, size1, size2);
    exit(1);
  }
}

void check_rc(int rc, char *msg) {
  if (rc != IOK) {
    fprintf(stderr, "Error: %s incorrect return value\n", msg);
    exit(1);
  }
}

void print_data(void *data, int type) {
  char *msg1 = "grpkey_print";
  char *msg2 = "grpkey";
  int (*get_size)(groupsig_key_t *) = &groupsig_grp_key_get_size;
  int (*export)(byte_t **, uint32_t *, groupsig_key_t *) = &groupsig_grp_key_export;
  if (type == 2) {
    msg1 = "memkey_print";
    msg2 = "memkey";
    get_size = &groupsig_mem_key_get_size;
    export = &groupsig_mem_key_export;
  }
  int len = (*get_size)(data);
  int rc = 255;
  byte_t *bytes = NULL;
  uint32_t size;
  rc = (*export)(&bytes, &size, data);
  check_rc(rc, msg1);
  check_size(size, len, msg2);
  char *enc = base64_encode(bytes, size, 1);
  printf("%s\n", enc);
  free(enc);
}


void save_data(void *data, int type) {
  char *msg1 = "grpkey_export";
  char *msg2 = "grpkey";
  int (*get_size)(groupsig_key_t *) = &groupsig_grp_key_get_size;
  int (*export)(byte_t **, uint32_t *, groupsig_key_t *) = &groupsig_grp_key_export;
  char *file = GRPKEY;
  if (type == 1) {
    msg1 = "mgrkey_export";
    msg2 = "mgrkey";
    file = MGRKEY;
    get_size = &groupsig_mgr_key_get_size;
    export = &groupsig_mgr_key_export;
  } else if (type == 3) {
    msg1 = "gml_export";
    msg2 = "gml";
    file = GML;
    export = &gml_export;
  }
  int len;
  if (type != 3)
    len = (*get_size)(data);
  int rc = 255;
  byte_t *bytes = NULL;
  uint32_t size;
  rc = (*export)(&bytes, &size, data);
  check_rc(rc, msg1);
  if (type != 3)
    check_size(size, len, msg2);
  printf("data size: %ld\n", size);
  char *enc = base64_encode(bytes, size, 0);
  printf("save encoded (%ld): %s\n", strlen(enc), enc);
  FILE *fp = fopen(file, "w");
  if (fp != NULL) {
    fwrite(enc, sizeof(char), strlen(enc), fp);
    fclose(fp);
  } else {
    fprintf(stderr, "Error: File %s cannot be written\n", file);
    exit(1);
  }
  /* uint64_t dec_len; */
  /* byte_t *dec_buff = base64_decode(enc, &dec_len); */
  /* printf("save(test) dec_len: %d\n", dec_len); */
  /* groupsig_key_t *test = groupsig_grp_key_import(CODE, dec_buff, dec_len); */
  free(enc);
}

void load_data(void **data, int type) {
  char *msg1 = "grpkey_import";
  groupsig_key_t *(*import)(unsigned char, unsigned char *, unsigned int) = &groupsig_grp_key_import;
  char *file = GRPKEY;
  if (type == 1) {
    msg1 = "mgrkey_import";
    file = MGRKEY;
    import = &groupsig_mgr_key_import;
  } else if (type == 3) {
    msg1 = "gml_import";
    file = GML;
    import = &gml_import;
  } else if (type == 4) {
    msg1 = "sig_import";
    file = SIG_PATH;
    import = &groupsig_signature_import;
  }
  FILE *fp = fopen(file, "r");
  char *enc;
  if (fp != NULL) {
    if (!fscanf(fp, "%ms", &enc)) {
      fclose(fp);
      fprintf(stderr, "Error: %s incorrect format\n", file);
      exit(1);
    }
    fclose(fp);
  } else {
    fprintf(stderr, "Error: %s file cannot be read\n", file);
    exit(1);
  }
  uint64_t dec_len;
  byte_t *dec_buff = base64_decode(enc, &dec_len);
  if (CODE == -1) {
    CODE = dec_buff[0];
    scheme_from_code();
  }
  if (type == 3 && !strlen(dec_buff)) {
    *data = gml_init(CODE);
  } else {
    *data = (*import)(CODE, (unsigned char*) dec_buff, dec_len);
    check_ptr(data, msg1);
  }
  free(dec_buff);
}

int main () {
  sprintf(GRPKEY, "%s/grpkey%s", DIRE, AFFIX);
  sprintf(MGRKEY, "%s/mgrkey%s", DIRE, AFFIX);
  sprintf(GML, "%s/gml%s", DIRE, AFFIX);
  groupsig_key_t *grpkey;
  groupsig_key_t *mgrkey;
  gml_t *gml;
  CODE = GROUPSIG_PS16_CODE;
  int rc = groupsig_init(CODE, time(NULL));
  if (!file_readable(GRPKEY) || !file_readable(MGRKEY)
      || !file_readable(GML)) {
    grpkey = groupsig_grp_key_init(CODE);
    mgrkey = groupsig_mgr_key_init(CODE);
    gml = gml_init(CODE);
    rc = groupsig_setup(CODE, grpkey, mgrkey, gml);
    check_rc(rc, "groupsig_setup");
    message_t *msg0_mem0, *msg1_mem0, *msg2_mem0, *msg3_mem0, *msg4_mem0;
    msg0_mem0 = message_init();
    msg1_mem0 = message_init();
    msg2_mem0 = message_init();
    msg3_mem0 = message_init();
    msg4_mem0 = message_init();
    groupsig_key_t *memkey0;
    memkey0 = groupsig_mem_key_init(grpkey->scheme);
    rc = groupsig_join_mgr(&msg1_mem0, gml, mgrkey, 0, msg0_mem0, grpkey);
    rc = groupsig_join_mem(&msg2_mem0, memkey0, 1, msg1_mem0, grpkey);
    rc = groupsig_join_mgr(&msg3_mem0, gml, mgrkey, 2, msg2_mem0, grpkey);
    rc = groupsig_join_mem(&msg4_mem0, memkey0, 3, msg3_mem0, grpkey);
    save_data(grpkey, 0);
    save_data(mgrkey, 1);
    save_data(gml, 3);
  } else {
    load_data(&grpkey, 0);
    load_data(&mgrkey, 1);
    load_data(&gml, 3);
  }
  print_data(grpkey, 0);
}
