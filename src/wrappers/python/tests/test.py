from pygroupsig import constants, groupsig, crl, memkey
from base64 import b64encode
import hashlib
import sys


def usage():
    print(f"Usage: python3 {sys.argv[0]} [kty04]\nBy default, cpy06 test is executed")
    sys.exit()


def register_cpy06(gk, mk, gg):
    msg1 = groupsig.join_mem(0, gk)
    msg2 = groupsig.join_mgr(1, mk, gk, gml=gg, msgin=msg1["msgout"])
    msg3 = groupsig.join_mem(2, gk, memkey=msg1["memkey"], msgin=msg2)
    msg4 = groupsig.join_mgr(3, mk, gk, gml=gg, msgin=msg3["msgout"])
    msg5 = groupsig.join_mem(4, gk, memkey=msg3["memkey"],  msgin=msg4)
    mekey = msg5["memkey"]
    return mekey

def register_kty04(gk, mk, gg):
    msg1 = groupsig.join_mem(0, gk)
    msg2 = groupsig.join_mgr(1, mk, gk, gml=gg, msgin=msg1["msgout"])
    mekeyb64 = b64encode(
        b''.join([msg2.bytes[idx].to_bytes(1, 'big') for idx in range(msg2.length)])
    )
    mekey = memkey.memkey_import(code, mekeyb64)
    return mekey

code = constants.CPY06_CODE
register = register_cpy06
if len(sys.argv) > 1:
    if sys.argv[1] == "kty04":
        code = constants.KTY04_CODE
        register = register_kty04
    elif sys.argv[1] in ["-h", "--help"]:
        usage()

print(f"Running test for scheme '{code}'")
groupsig.init(code, 0)
group = groupsig.setup(code)
c = crl.crl_init(code)

mkey = group['mgrkey']
gkey = group['grpkey']
g = group['gml']
text1 = b"Working. Finally!"
text2 = b"That took a lot!"
digest1 = hashlib.sha256(text1).hexdigest()
digest2 = hashlib.sha256(text2).hexdigest()

# User1
mekey0 = register(gkey, mkey, g)
sig_0 = groupsig.sign(digest1, mekey0, gkey)
ver_0 = groupsig.verify(sig_0, digest1, gkey)
print("Test: signature matching message (exp: True) ->", ver_0)

# User2
mekey1 = register(gkey, mkey, g)
sig_1 = groupsig.sign(digest1, mekey1, gkey)
ver_1 = groupsig.verify(sig_1, digest2, gkey)
print("Test: signature not matching message (exp: False) ->", ver_1)

gsclaim_0 = groupsig.claim(sig_0, mekey0, gkey)
claim_proof_0 = gsclaim_0["proof"]
gver_0 = groupsig.claim_verify(claim_proof_0, sig_0, gkey)
print("Test: claiming signature using matching identity (exp: True) ->", gver_0)

gver_00 = groupsig.claim_verify(claim_proof_0, sig_1, gkey)
print("Test: claiming signature using unclaimed signature (exp: False) ->", gver_00)

gsclaim_1 = groupsig.claim(sig_1, mekey0, gkey)
claim_proof_1 = gsclaim_1["proof"]
gver_1 = groupsig.claim_verify(claim_proof_1, sig_1, gkey)
print("Test: claiming signature using not matching identity (exp: False) ->", gver_1)

gsopen_0 = groupsig.open(sig_0, mkey, gkey, g, c)
open_proof_0 = gsopen_0["proof"]
gstrev_0 = groupsig.reveal(gsopen_0["index"], gkey, g, c)
gstrace_0 = groupsig.trace(sig_0, gkey, g, c)
print("Test: tracing revoked identity (exp: True) ->", gstrace_0)

gstrace_1 = groupsig.trace(sig_1, gkey, g, c)
print("Test: tracing not revoked identity (exp: False) ->", gstrace_1)

# Interesting notes to debug C library while using python wrapper
# The original information comes from https://johnfoster.pge.utexas.edu/blog/posts/debugging-cc%2B%2B-libraries-called-by-python/
# > First, in two separate terminal windows, launch ipython and lldb. At the IPython prompt, type:
# >> In [1]: !ps aux | grep -i ipython
# > In another terminal, type
# >> gdb -p <pid>
# >>  (gdb) b function_func_interest
# >>  (gdb) continue
# > In the ipython terminal, run the code
# >> In [1]: run pythoncode.py
# Now, in the gdb terminal debug the C code
# >>  (gdb) # debug here

# Interesting note, if you want to allow gdb to attach to other processes (inside container),
# you need to add SYS_PTRACE capabilities: --cap-add=SYS_PTRACE
# The original information comes from https://stackoverflow.com/a/45171694/4305230
