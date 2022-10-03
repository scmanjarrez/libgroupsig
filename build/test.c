#include "groupsig.h"
#include "kty04.h"
#include "mem_key.h"
#include "signature.h"


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
  mgrkey = groupsig_mgr_key_init(GROUPSIG_KTY04_CODE);
  /* printf("mgr: %s\n", groupsig_mgr_key_to_string(mgrkey)); */

  groupsig_key_t *grpkey;
  grpkey = groupsig_grp_key_init(GROUPSIG_KTY04_CODE);
  /* printf("grp: %s\n", groupsig_grp_key_to_string(grpkey)); */
  gml_t *gml;
  gml = gml_init(GROUPSIG_KTY04_CODE);
  /* gml_entry_t *entry; */
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
  crl_t *crl;
  crl = crl_init(GROUPSIG_KTY04_CODE);

  int rc;
  rc = groupsig_setup(GROUPSIG_KTY04_CODE, grpkey, mgrkey, gml);

  groupsig_key_t *memkey;
  /* memkey = (groupsig_key_t **) malloc(sizeof(gro4upsig_key_t *)); */
  memkey = groupsig_mem_key_init(grpkey->scheme);

  char *str_aux;

  message_t *m1, *m2;
  m1 = message_init();
  m2 = message_init();

  groupsig_signature_t **sigs;
  sigs = (groupsig_signature_t **)malloc(1*sizeof(groupsig_signature_t*));

  rc = groupsig_join_mem(&m1, memkey, 0, NULL, grpkey);

  rc = groupsig_join_mgr(&m2, gml, mgrkey, 1, m1, grpkey);

  memkey = groupsig_mem_key_import(GROUPSIG_KTY04_CODE, m2->bytes, m2->length);

  message_t *msg;
  msg = message_from_string((char *) "Hello, World!");

  message_t *msg2;
  msg2 = message_from_string((char *) "Hello, Worlds!");

  groupsig_signature_t *sig1;
  sig1 = groupsig_signature_init(grpkey->scheme);
  rc = groupsig_sign(sig1, msg, memkey, grpkey, UINT_MAX);
  printf("sign rc: %d\n", rc);

  groupsig_signature_t *sig2;
  sig2 = groupsig_signature_init(grpkey->scheme);
  rc = groupsig_sign(sig2, msg2, memkey, grpkey, UINT_MAX);
  printf("sign 2 rc: %d\n", rc);

  uint8_t b = 255;
  rc = groupsig_verify(&b, sig1, msg, grpkey);
  printf("verify rc: %d\n", rc);
  printf("verify b: %d\n", b);
  printf("%d\n", b==1);

  uint8_t b2 = 255;
  rc = groupsig_verify(&b2, sig1, msg2, grpkey);
  printf("verify rc: %d\n", rc);
  printf("verify b2: %d\n", b2);
  printf("%d\n", b2==0);

  groupsig_proof_t *p1;
  p1 = groupsig_proof_init(grpkey->scheme);
  sigs[0] = sig1;
  rc = groupsig_prove_equality(p1, memkey, grpkey, sigs, 1);
  printf("proof rc: %d\n", rc);

  uint8_t b3 = 255;
  rc = groupsig_prove_equality_verify(&b3, p1, grpkey, sigs, 1);
  printf("proof verif rc: %d\n", rc);
  printf("proof verif b3: %d\n", b3);
  printf("%d\n", b3==1);

  uint8_t b4 = 255;
  sigs[0] = sig2;
  rc = groupsig_prove_equality_verify(&b4, p1, grpkey, sigs, 1);
  printf("wrong proof verif rc: %d\n", rc);
  printf("wrong proof verif b4: %d\n", b4);
  printf("%d\n", b4==0);
  sigs[0] = sig1;

  uint8_t b5 = 255;
  rc = groupsig_trace(&b5, sig1, grpkey, crl, mgrkey, gml);
  printf("illegal trace rc: %d\n", rc);
  printf("illegal trace b5: %d\n", b5);
  printf("%d\n", b4==0);

  uint64_t id = 255;
  rc = groupsig_open(&id, p1, crl, sig1, grpkey, mgrkey, gml);
  printf("open rc: %d\n", rc);
  printf("open id: %lu\n", id);

  trapdoor_t *trapdoor = NULL;
  trapdoor = trapdoor_init(memkey->scheme);
  rc = groupsig_reveal(trapdoor, crl, gml, 0);
  printf("reveal rc: %d\n", rc);
  str_aux = bigz_get_str16(*(bigz_t *)trapdoor->trap);
  printf("reveal td: %s\n", str_aux);

  uint8_t b6 = 255;
  rc = groupsig_trace(&b6, sig1, grpkey, crl, mgrkey, gml);
  printf("legal trace rc: %d\n", rc);
  printf("legal trace b6: %d\n", b6);
  printf("%d\n", b6==1);

  groupsig_proof_t *p2;
  p2 = groupsig_proof_init(grpkey->scheme);
  rc = groupsig_claim(p2, memkey, grpkey, sig1);
  printf("claim rc: %d\n", rc);

  uint8_t b7 = 255;
  rc = groupsig_claim_verify(&b7, p2, sig1, grpkey);
  printf("claim verif rc: %d\n", rc);
  printf("claim verif b7: %d\n", b7);
  printf("%d\n", b6==1);

  uint8_t b8 = 255;
  rc = groupsig_claim_verify(&b8, p2, sig2, grpkey);
  printf("wrong claim verif rc: %d\n", rc);
  printf("wrong claim verif b8: %d\n", b8);
  printf("%d\n", b8==0);

  groupsig_mgr_key_free(mgrkey); mgrkey = NULL;
  groupsig_grp_key_free(grpkey); grpkey = NULL;
  groupsig_mem_key_free(memkey); memkey = NULL;
  gml_free(gml); gml = NULL;
  crl_free(crl); crl = NULL;
  message_free(m2); m2 = NULL;
  message_free(m1); m1 = NULL;
  trapdoor_free(trapdoor);
  groupsig_proof_free(p1);
  groupsig_proof_free(p2);
  groupsig_signature_free(sig1); sig1 = NULL;
  free(sigs);
  return 0;

}
