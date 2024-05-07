# file "cpy06_build"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("#define GROUPSIG_CPY06_CODE 2")
#ffibuilder.cdef('#define GROUPSIG_CPY06_NAME "CPY06"')
ffibuilder.cdef("#define CPY06_JOIN_START 1")
ffibuilder.cdef("#define CPY06_JOIN_SEQ 4")

ffibuilder.cdef("""
int cpy06_init();
""")

ffibuilder.cdef("""
int cpy06_clear();
""")

ffibuilder.cdef("""
int cpy06_setup(
groupsig_key_t *grpkey,
groupsig_key_t *mgrkey,
gml_t *gml);
""")

ffibuilder.cdef("""
int cpy06_get_joinseq(uint8_t *seq);
""")

ffibuilder.cdef("""
int cpy06_get_joinstart(uint8_t *start);
""")

ffibuilder.cdef("""
int cpy06_join_mem(
message_t **mout,
groupsig_key_t *memkey,
int seq,
message_t *min,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int cpy06_join_mgr(
message_t **mout,
gml_t *gml,
groupsig_key_t *mgrkey,
int seq,
message_t *min,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int cpy06_sign(
groupsig_signature_t *sig,
message_t *msg,
groupsig_key_t *memkey,
groupsig_key_t *grpkey,
unsigned int seed);
""")

ffibuilder.cdef("""
int cpy06_verify(
uint8_t *ok,
groupsig_signature_t *sig,
message_t *msg,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int cpy06_open(
uint64_t *id,
groupsig_proof_t *proof,
crl_t *crl,
groupsig_signature_t *sig,
groupsig_key_t *grpkey,
groupsig_key_t *mgrkey,
gml_t *gml);
""")

ffibuilder.cdef("""
int cpy06_reveal(
trapdoor_t *trap,
crl_t *crl,
gml_t *gml,
uint64_t index);
""")

ffibuilder.cdef("""
int cpy06_trace(
uint8_t *ok,
groupsig_signature_t *sig,
groupsig_key_t *grpkey,
crl_t *crl,
groupsig_key_t *mgrkey,
gml_t *gml);
""")

ffibuilder.cdef("""
int cpy06_claim(
groupsig_proof_t *proof,
groupsig_key_t *memkey,
groupsig_key_t *grpkey,
groupsig_signature_t *sig);
""")

ffibuilder.cdef("""
int cpy06_claim_verify(
uint8_t *ok,
groupsig_proof_t *proof,
groupsig_signature_t *sig,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int cpy06_prove_equality(
groupsig_proof_t *proof,
groupsig_key_t *memkey,
groupsig_key_t *grpkey,
groupsig_signature_t **sigs,
uint16_t n_sigs);
""")

ffibuilder.cdef("""
int cpy06_prove_equality_verify(
uint8_t *ok,
groupsig_proof_t *proof,
groupsig_key_t *grpkey,
groupsig_signature_t **sigs,
uint16_t n_sigs);
""")
