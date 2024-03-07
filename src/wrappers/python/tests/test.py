from pygroupsig import constants, groupsig, crl, memkey
from base64 import b64encode
import hashlib

code = constants.KTY04_CODE
# code = constants.CPY06_CODE

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
msg1_0 = groupsig.join_mem(0, gkey)
msg2_0 = groupsig.join_mgr(1, mkey, gkey, gml=g, msgin=msg1_0["msgout"])
mekeyb64_0 = b64encode(
    b''.join([msg2_0.bytes[idx].to_bytes(1, 'big') for idx in range(msg2_0.length)])
)
mekey0 = memkey.memkey_import(code, mekeyb64_0)
sig_0 = groupsig.sign(digest1, mekey0, gkey)
ver_0 = groupsig.verify(sig_0, digest1, gkey)
print("Test: signature matching message (ex: True) ->", ver_0)

# User2
msg1_1 = groupsig.join_mem(0, gkey)
msg2_1 = groupsig.join_mgr(1, mkey, gkey, gml=g, msgin=msg1_1["msgout"])
mekeyb64_1 = b64encode(
    b''.join([msg2_1.bytes[idx].to_bytes(1, 'big') for idx in range(msg2_1.length)])
)
mekey1 = memkey.memkey_import(code, mekeyb64_1)
sig_1 = groupsig.sign(digest1, mekey1, gkey)
ver_1 = groupsig.verify(sig_1, digest2, gkey)
print("Test: signature not matching message (ex: False) ->", ver_1)

# import pdb; pdb.set_trace()
gsclaim_0 = groupsig.claim(sig_0, mekey0, gkey)
claim_proof_0 = gsclaim_0["proof"]
gver_0 = groupsig.claim_verify(claim_proof_0, sig_0, gkey)
print("Test: claiming signature using matching identity (ex: True) ->", gver_0)

gver_00 = groupsig.claim_verify(claim_proof_0, sig_1, gkey)
print("Test: claiming signature using unclaimed signature (ex: False) ->", gver_00)

gsclaim_1 = groupsig.claim(sig_1, mekey0, gkey)
claim_proof_1 = gsclaim_1["proof"]
gver_1 = groupsig.claim_verify(claim_proof_1, sig_1, gkey)
print("Test: claiming signature using not matching identity (ex: False) ->", gver_1)

gsopen_0 = groupsig.open(sig_0, mkey, gkey, g, c)
open_proof_0 = gsopen_0["proof"]
gstrev_0 = groupsig.reveal(gsopen_0["index"], gkey, g, c)
gstrace_0 = groupsig.trace(sig_0, gkey, g, c)
print("Test: tracing revoked identity (ex: True) ->", gstrace_0)

gstrace_1 = groupsig.trace(sig_1, gkey, g, c)
print("Test: tracing not revoked identity (ex: False) ->", gstrace_1)

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
