import argparse
from base64 import b64encode
from hashlib import sha256

from _groupsig import ffi
from otsclient.args import parse_ots_args
from pygroupsig import constants, groupsig, memkey, signature


SCHEMES = {
    "bbs04": constants.BBS04_CODE,
    "ps16": constants.PS16_CODE,
    "cpy06": constants.CPY06_CODE,
    "kty04": constants.KTY04_CODE,
    "klap20": constants.KLAP20_CODE,
    "gl19": constants.GL19_CODE,
    "dl21": constants.DL21_CODE,
    "dl21seq": constants.DL21SEQ_CODE,
}
UINT_MAX = 2**32 - 1


class GroupSig:
    def __init__(self, scheme):
        if scheme not in SCHEMES:
            print("Error: Invalid scheme")
            exit(1)
        self.scheme = scheme
        self.code = SCHEMES[scheme]
        self.multi = scheme in ["klap20", "gl19"]
        self.req_json = scheme in ["dl21", "dl21seq"]
        self.memkeys = []

    def setup(self):
        groupsig.init(self.code)
        self.group = groupsig.setup(self.code)
        if self.multi:
            group2 = groupsig.setup(self.code, self.group["grpkey"])
            self.mgrkey2 = group2[
                "mgrkey"
            ]  # only used in specific functions
        self.mgrkey = self.group["mgrkey"]
        self.grpkey = self.group["grpkey"]
        if self.has_gml():
            self.gml = self.group["gml"]
        else:
            self.gml = ffi.NULL

    def register(self):
        start = groupsig.get_joinstart(self.code)
        seq = groupsig.get_joinseq(self.code)
        if start == 1 and seq == 1:  # kty
            msg1 = groupsig.join_mem(0, self.grpkey)
            msg2 = groupsig.join_mgr(
                1,
                self.mgrkey,
                self.grpkey,
                gml=self.gml,
                msgin=msg1["msgout"],
            )
            mekeyb64 = b64encode(
                b"".join(
                    [
                        msg2.bytes[idx].to_bytes(1, "big")
                        for idx in range(msg2.length)
                    ]
                )
            )
            usk = memkey.memkey_import(self.code, mekeyb64)
            self.memkeys.append(usk)
        else:
            phase = 0
            msg2 = ffi.NULL
            usk = ffi.NULL
            if start:
                msg2 = groupsig.join_mem(phase, self.grpkey)
                usk = msg2["memkey"]
                phase += 1
            while phase < seq:
                msg1 = groupsig.join_mgr(
                    phase,
                    self.mgrkey,
                    self.grpkey,
                    gml=self.gml,
                    msgin=(
                        msg2["msgout"] if msg2 != ffi.NULL else msg2
                    ),
                )
                phase += 1
                msg2 = groupsig.join_mem(
                    phase, self.grpkey, msgin=msg1, memkey=usk
                )
                phase += 1
                usk = msg2["memkey"]
            self.memkeys.append(usk)

    def sign(self, file, identity=0):
        assert identity < len(self.memkeys)
        msg = self._digest(file)
        if self.req_json:
            msg = f'{{ "scope": "scp", "message": "{msg}" }}'
        return groupsig.sign(
            msg,
            self.memkeys[identity],
            self.grpkey,
            UINT_MAX,
        )

    def verify(self, file, signature):
        msg = self._digest(file)
        if self.req_json:
            msg = f'{{ "scope": "scp", "message": "{msg}" }}'
        return groupsig.verify(signature, msg, self.grpkey)

    def export(self, sig, output):
        exp = signature.signature_export(sig)
        with open(output, "w") as f:
            f.write(exp)

    def _digest(self, file):
        with open(file, "rb") as f:
            return sha256(f.read()).hexdigest()

    def has_gml(self):
        return self.scheme not in ["gl19", "dl21", "dl21seq"]

    def has_crl(self):
        return self.scheme in ["kty04", "cpy06"]


def main(args):
    print("# Creating GroupSig1\n")
    gs1 = GroupSig(args.scheme)
    gs1.setup()

    print("# Creating GroupSig2\n")
    gs2 = GroupSig(args.scheme)
    gs2.setup()

    print("# Registering userA in GroupSig1\n")
    gs1.register()

    print("# Signing file1 with userA identity\n")
    sig = gs1.sign(args.file1, 0)

    print("# Checking signature with GroupSig1 grpkey")
    ret = gs1.verify(args.file1, sig)
    print(f"Signature: {'valid' if ret else 'invalid'}\n")

    print("# Storing signature")
    gs1.export(sig, args.output)

    print("# Checking signature with GroupSig1 grpkey, but file2")
    ret = gs1.verify(args.file2, sig)
    print(f"Signature: {'valid' if ret else 'invalid'}\n")

    print("# Checking signature with GroupSig2 grpkey")
    ret = gs2.verify(args.file1, sig)
    print(f"Signature: {'valid' if ret else 'invalid'}\n")

    print("# Generating timestamp (opentimestamp)")
    otsargs = parse_ots_args(["stamp", args.output])
    otsargs.cmd_func(otsargs)

    otsargs = parse_ots_args(["verify", f"{args.output}.ots"])
    otsargs.cmd_func(otsargs)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file1")
    parser.add_argument("file2")
    parser.add_argument(
        "-s", "--scheme", choices=SCHEMES, default="ps16"
    )
    parser.add_argument("-o", "--output", default="file.sig")
    args = parser.parse_args()

    main(args)
