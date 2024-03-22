# file "klap20_build"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("#define GROUPSIG_KTY04_CODE 0")
#ffibuilder.cdef('#define GROUPSIG_KTY04_NAME "KTY04"')
ffibuilder.cdef("#define KTY04_JOIN_START 1")
ffibuilder.cdef("#define KTY04_JOIN_SEQ 1")

ffibuilder.cdef("""
int kty04_init();
""")

ffibuilder.cdef("""
int kty04_clear();
""")

ffibuilder.cdef("""
int kty04_setup(
groupsig_key_t *grpkey,
groupsig_key_t *mgrkey,
gml_t *gml);
""")

ffibuilder.cdef("""
int kty04_get_joinseq(uint8_t *seq);
""")

ffibuilder.cdef("""
int kty04_get_joinstart(uint8_t *start);
""")

ffibuilder.cdef("""
int kty04_join_mem(
message_t **mout,
groupsig_key_t *memkey,
int seq,
message_t *min,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int kty04_join_mgr(
message_t **mout,
gml_t *gml,
groupsig_key_t *mgrkey,
int seq,
message_t *min,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int kty04_sign(
groupsig_signature_t *sig,
message_t *msg,
groupsig_key_t *memkey,
groupsig_key_t *grpkey,
unsigned int seed);
""")

ffibuilder.cdef("""
int kty04_verify(
uint8_t *ok,
groupsig_signature_t *sig,
message_t *msg,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int kty04_open(
uint64_t *id,
groupsig_proof_t *proof,
crl_t *crl,
groupsig_signature_t *sig,
groupsig_key_t *grpkey,
groupsig_key_t *mgrkey,
gml_t *gml);
""")

ffibuilder.cdef("""
int kty04_reveal(
trapdoor_t *trap,
crl_t *crl,
gml_t *gml,
uint64_t index);
""")

ffibuilder.cdef("""
int kty04_trace(
uint8_t *ok,
groupsig_signature_t *sig,
groupsig_key_t *grpkey,
crl_t *crl,
groupsig_key_t *mgrkey,
gml_t *gml);
""")

ffibuilder.cdef("""
int kty04_claim(
groupsig_proof_t *proof,
groupsig_key_t *memkey,
groupsig_key_t *grpkey,
groupsig_signature_t *sig);
""")

ffibuilder.cdef("""
int kty04_claim_verify(
uint8_t *ok,
groupsig_proof_t *proof,
groupsig_signature_t *sig,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int kty04_prove_equality(
groupsig_proof_t *proof,
groupsig_key_t *memkey,
groupsig_key_t *grpkey,
groupsig_signature_t **sigs,
uint16_t n_sigs);
""")

ffibuilder.cdef("""
int kty04_prove_equality_verify(
uint8_t *ok,
groupsig_proof_t *proof,
groupsig_key_t *grpkey,
groupsig_signature_t **sigs,
uint16_t n_sigs);
""")
