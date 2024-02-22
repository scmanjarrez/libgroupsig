from pygroupsig import constants, groupsig, crl#, gml, grpkey, mgrkey, signature
# from _groupsig import lib

code = constants.KTY04_CODE

groupsig.init(code, 0)
group = groupsig.setup(code)
c = crl.crl_init(code)

mkey = group['mgrkey']
gkey = group['grpkey']
g = group['gml']

import pdb; pdb.set_trace()

msg1 = groupsig.join_mem(0, gkey)
