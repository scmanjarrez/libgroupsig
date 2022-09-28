#include "groupsig.h"


void print_gml(byte_t *bytes, uint32_t size) {
  printf("gml size: %d\n", size);
  printf("gml: ");
  if (size != sizeof(uint64_t)) {
    int i = 0;
    for (i = sizeof(uint64_t); i < size; i++)
      {
        if (i > sizeof(uint64_t)) printf(":");
        printf("%02X", bytes[i]);
      }
    printf("\n");
  } else {
    printf("empty\n");
  }
}

int main ()
{
  groupsig_key_t *mgrkey;
  groupsig_key_t *grpkey;
  gml_t *gml;
  gml_entry_t *entry;
  crl_t *crl;
  groupsig_key_t **memkey;
  int rc;
  byte_t *bytes = NULL;
  byte_t *bytes2 = NULL;
  uint32_t size;
  uint32_t size2;

  mgrkey = groupsig_mgr_key_init(GROUPSIG_KTY04_CODE);
  /* printf("mgr: %s\n", groupsig_mgr_key_to_string(mgrkey)); */

  grpkey = groupsig_grp_key_init(GROUPSIG_KTY04_CODE);
  /* printf("grp: %s\n", groupsig_grp_key_to_string(grpkey)); */

  gml = gml_init(GROUPSIG_KTY04_CODE);
  /* entry = gml_entry_init(GROUPSIG_KTY04_CODE); */
  /* rc = gml_insert(gml, entry); */
  /* printf("gml n: %ld\n", gml->n); */
  /* printf("insert rc: %d\n", rc); */
  /* gml_export(&bytes, &size, gml); */
  /* gml_entry_to_string(gml->entries[0]); */
  /* print_gml(bytes, size); */

  /* gml_t *gml2; */
  /* gml2 = gml_import(GROUPSIG_KTY04_CODE, bytes, size); */
  /* gml_export(&bytes2, &size2, gml2); */
  /* print_gml(bytes2, size2); */
  crl = crl_init(GROUPSIG_KTY04_CODE);

  rc = groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);
  printf("rc: %d\n", rc);

  groupsig_mgr_key_free(mgrkey); mgrkey = NULL;
  groupsig_grp_key_free(grpkey); grpkey = NULL;
  gml_free(gml); gml = NULL;
  crl_free(crl); crl = NULL;

  return 0;
}
