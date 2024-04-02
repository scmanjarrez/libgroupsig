import unittest
import string
import tempfile
from _groupsig import ffi

from pygroupsig import groupsig
from pygroupsig import grpkey
from pygroupsig import mgrkey
from pygroupsig import memkey
from pygroupsig import identity
from pygroupsig import message
from pygroupsig import signature
from pygroupsig import gml
from pygroupsig import crl
from pygroupsig import constants

# Tests for group operations
class TestCommon(unittest.TestCase):
    # Non-test functions
    def addMember(self):
        msg1 = groupsig.join_mem(0, self.grpkey)
        msg2 = groupsig.join_mgr(1, self.mgrkey, self.grpkey, gml = self.gml, msgin=msg1["msgout"])
        msg3 = groupsig.join_mem(2, self.grpkey, memkey=msg1["memkey"], msgin=msg2)
        msg4 = groupsig.join_mgr(3, self.mgrkey, self.grpkey, gml = self.gml, msgin=msg3["msgout"])
        msg5 = groupsig.join_mem(4, self.grpkey, msgin = msg4, memkey=msg3["memkey"])
        usk = msg5['memkey']
        self.memkeys.append(usk)

    def setUp(self):
        self.code = constants.CPY06_CODE
        groupsig.init(self.code, 0)
        group = groupsig.setup(self.code)
        self.mgrkey = group['mgrkey']
        self.grpkey = group['grpkey']
        self.gml = group['gml']
        self.crl = crl.crl_init(self.code)
        self.memkeys = []

    def tearDown(self):
        groupsig.clear(self.code)


# Tests for group operations
class TestGroupOps(TestCommon):

    # Creates a group
    def test_groupCreate(self):
        self.assertNotEqual(self.grpkey, ffi.NULL)
        self.assertNotEqual(self.mgrkey, ffi.NULL)
        self.assertNotEqual(self.crl, ffi.NULL)
        self.assertEqual(groupsig.get_joinseq(self.code), 4)
        self.assertEqual(groupsig.get_joinstart(self.code), 1)

    # Adds one member
    def test_addMember(self):
        n_members = len(self.memkeys)
        self.addMember()
        self.assertEqual(len(self.memkeys), n_members+1)
        self.assertNotEqual(self.memkeys[n_members], ffi.NULL)

    # Accepts a valid signature for a message passed as a string
    def test_acceptValidSignatureString(self):
        self.addMember()
        sig = groupsig.sign("Hello, World!", self.memkeys[0], self.grpkey)
        b = groupsig.verify(sig, "Hello, World!", self.grpkey)
        self.assertTrue(b)

    # Rejects a valid signature for a different message, also passed as a string
    def test_rejectValidSignatureWrongMessageString(self):
        self.addMember()
        sig = groupsig.sign("Hello, World!", self.memkeys[0], self.grpkey)
        b = groupsig.verify(sig, "Hello, Worlds!", self.grpkey)
        self.assertFalse(b)

    # Accepts a valid signature for a message passed as a byte array
    def test_acceptValidSignatureBytes(self):
        self.addMember()
        sig = groupsig.sign(b"Hello, World!", self.memkeys[0], self.grpkey)
        b = groupsig.verify(sig, b"Hello, World!", self.grpkey)
        self.assertTrue(b)

    # Rejects a valid signature for a different message, also passed as a byte array
    def test_rejectValidSignatureWrongMessageBytes(self):
        self.addMember()
        sig = groupsig.sign(b"Hello, World!", self.memkeys[0], self.grpkey)
        b = groupsig.verify(sig, b"Hello, Worlds!", self.grpkey)
        self.assertFalse(b)

    # Successfully opens a signature
    def test_openSignature(self):
        self.addMember()
        self.addMember()
        sig = groupsig.sign(b"Hello, World!", self.memkeys[1], self.grpkey)
        gsopen = groupsig.open(sig, self.mgrkey, self.grpkey, gml = self.gml)
        self.assertEqual(gsopen["index"], 1)

    # Generate a claim (proof) of a signature and verifies it
    def test_claimValidSignature(self):
        self.addMember()
        sig = groupsig.sign(b"Hello, World!", self.memkeys[0], self.grpkey)
        claim = groupsig.claim(sig, self.memkeys[0], self.grpkey)
        ver = groupsig.claim_verify(claim["proof"], sig, self.grpkey)
        self.assertTrue(ver)

    # Generate a claim (proof) of a signature and verifies it with wrong parameters
    def test_claimWrongSignature(self):
        self.addMember()
        self.addMember()
        msg1 = b"Hello, World!"
        msg2 = b"Hello, Worlds!"
        sig1 = groupsig.sign(msg1, self.memkeys[0], self.grpkey)
        # same user, different message
        sig2 = groupsig.sign(msg2, self.memkeys[0], self.grpkey)
        # different user, same message
        sig3 = groupsig.sign(msg1, self.memkeys[1], self.grpkey)
        claim = groupsig.claim(sig1, self.memkeys[0], self.grpkey)
        # verify claim with other signature (different message)
        ver1 = groupsig.claim_verify(claim["proof"], sig2, self.grpkey)
        self.assertFalse(ver1)
        # verify claim with other signature (different user)
        ver2 = groupsig.claim_verify(claim["proof"], sig3, self.grpkey)
        self.assertFalse(ver2)

    # Trace a revealed user
    def test_traceValidSignature(self):
        self.addMember()
        sig = groupsig.sign(b"Hello, World!", self.memkeys[0], self.grpkey)
        gsopen = groupsig.open(sig, self.mgrkey, self.grpkey, gml = self.gml)
        self.assertEqual(gsopen["index"], 0)
        _ = groupsig.reveal(gsopen["index"], self.grpkey, self.gml, self.crl)
        gstrace = groupsig.trace(sig, self.grpkey, self.gml, self.crl)
        self.assertTrue(gstrace)

    # Trace a not revealed user
    def test_traceWrongSignature(self):
        self.addMember()
        sig = groupsig.sign(b"Hello, World!", self.memkeys[0], self.grpkey)
        gstrace = groupsig.trace(sig, self.grpkey, self.gml, self.crl)
        self.assertFalse(gstrace)

    # Generate a claim (proof) of two signatures and verify it
    def test_proveEqualityValidSignature(self):
        self.addMember()
        sig1 = groupsig.sign(b"Hello, World!", self.memkeys[0], self.grpkey)
        sig2 = groupsig.sign(b"Hello, Worlds!", self.memkeys[0], self.grpkey)
        sigs = [sig1, sig2]
        prove = groupsig.prove_equality(self.memkeys[0], self.grpkey, sigs)
        ver = groupsig.prove_equality_verify(prove["proof"], self.grpkey, sigs)
        self.assertTrue(ver)

    def test_proveEqualityWrongSignature(self):
        self.addMember()
        self.addMember()
        sig1 = groupsig.sign(b"Hello, World!", self.memkeys[0], self.grpkey)
        sig2 = groupsig.sign(b"Hello, Worlds!", self.memkeys[0], self.grpkey)
        sigs = [sig1, sig2]
        prove1 = groupsig.prove_equality(self.memkeys[0], self.grpkey, sigs)
        sigs = [sig2, sig1]
        ver1 = groupsig.prove_equality_verify(prove1["proof"], self.grpkey, sigs)
        self.assertFalse(ver1)
        sigs = [sig1, sig1]
        ver2 = groupsig.prove_equality_verify(prove1["proof"], self.grpkey, sigs)
        self.assertFalse(ver2)
        sigs = [sig1, sig2]
        prove2 = groupsig.prove_equality(self.memkeys[1], self.grpkey, sigs)
        ver2 = groupsig.prove_equality_verify(prove2["proof"], self.grpkey, sigs)
        self.assertFalse(ver2)

# Tests for signature operations
class TestSignatureOps(TestCommon):

    # Creates a group, adds a member and generates a signature
    def setUp(self):
        super().setUp()
        self.addMember()
        self.sig = groupsig.sign("Hello, World!", self.memkeys[0], self.grpkey)

    # Exports and reimports a signature, and it verifies correctly
    def test_sigExportImport(self):
        sig_str = signature.signature_export(self.sig)
        sig = signature.signature_import(self.code, sig_str)
        b = groupsig.verify(sig, "Hello, World!", self.grpkey)
        self.assertTrue(b)

    # Prints a string (this just checks the produced string is not empty)
    def test_sigToString(self):
        sig_str = signature.signature_to_string(self.sig)
        self.assertGreater(len(sig_str), 0)
        self.assertTrue(set(sig_str).issubset(set(string.printable)))

# Tests for group key operations
class TestGrpkeyOps(TestCommon):

    # Exports and reimports a group key
    def test_grpkeyExportImport(self):
        grpkey_str = grpkey.grpkey_export(self.grpkey)
        gpk = grpkey.grpkey_import(self.code, grpkey_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # grp keys would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, gpk)

# Tests for manager key operations
class TestManagerkeyOps(TestCommon):

    # Exports and reimports an manager key
    def test_mgrkeyExportImport(self):
        mgrkey_str = mgrkey.mgrkey_export(self.mgrkey)
        ikey = mgrkey.mgrkey_import(self.code, mgrkey_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # manager keys would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, ikey)

# Tests for member key operations
class TestMemkeyOps(TestCommon):

    # Exports and reimports a member key
    def test_memkeyExportImport(self):
        self.addMember()
        memkey_str = memkey.memkey_export(self.memkeys[0])
        mkey = memkey.memkey_import(self.code, memkey_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # mem keys would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, mkey)

# Tests for GML operations
class TestGmlOps(TestCommon):

    # Exports and reimports a member key
    def test_gmlExportImport(self):
        self.addMember()
        gml_str = gml.gml_export(self.gml)
        _gml = gml.gml_import(self.code, gml_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # GMLs would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, _gml)

# Tests for CRL operations
class TestCrlOps(TestCommon):

    # Creates a group, adds a member, generates and revokes a signature
    def setUp(self):
        super().setUp()
        self.addMember()
        self.addMember()
        self.sig1 = groupsig.sign("Hello, World!", self.memkeys[0], self.grpkey)
        gsopen1 = groupsig.open(self.sig1, self.mgrkey, self.grpkey, gml = self.gml)
        _ = groupsig.reveal(gsopen1["index"], self.grpkey, self.gml, self.crl)
        self.sig2 = groupsig.sign("Hello, World!", self.memkeys[1], self.grpkey)
        gsopen2 = groupsig.open(self.sig2, self.mgrkey, self.grpkey, gml = self.gml)
        _ = groupsig.reveal(gsopen2["index"], self.grpkey, self.gml, self.crl)

    # Exports and reimports a member key
    def test_crlExportImport(self):
        with tempfile.NamedTemporaryFile(mode="r") as fp:
            crl.crl_export(self.crl, fp.name)
            _crl = crl.crl_import(self.code, fp.name)
            self.assertEqual(len(fp.readlines()), 2)
            # This is quite useless, as import returns an exception if the FFI
            # method returns ffi.NULL. Maybe implementing a cmp function for
            # GMLs would be good for testing this (and also in general?)
            self.assertIsNot(ffi.NULL, _crl)

# Define test suites
def suiteGroupOps():
    suiteGroupOps = unittest.TestSuite()
    suiteGroupOps.addTest(TestGroupOps('test_groupCreate'))
    suiteGroupOps.addTest(TestGroupOps('test_addMember'))
    suiteGroupOps.addTest(TestGroupOps('test_acceptValidSignatureString'))
    suiteGroupOps.addTest(TestGroupOps('test_rejectValidSignatureWrongMessageString'))
    suiteGroupOps.addTest(TestGroupOps('test_acceptValidSignatureBytes'))
    suiteGroupOps.addTest(TestGroupOps('test_rejectValidSignatureWrongMessageBytes'))
    suiteGroupOps.addTest(TestGroupOps('test_openSignature'))
    suiteGroupOps.addTest(TestGroupOps('test_claimValidSignature'))
    suiteGroupOps.addTest(TestGroupOps('test_claimWrongSignature'))
    suiteGroupOps.addTest(TestGroupOps('test_traceValidSignature'))
    suiteGroupOps.addTest(TestGroupOps('test_traceWrongSignature'))
    suiteGroupOps.addTest(TestGroupOps('test_proveEqualityValidSignature'))
    suiteGroupOps.addTest(TestGroupOps('test_proveEqualityWrongSignature'))
    return suiteGroupOps

def suiteSigOps():
    suiteSigOps = unittest.TestSuite()
    suiteSigOps.addTest(TestSignatureOps('test_sigExportImport'))
    suiteSigOps.addTest(TestSignatureOps('test_sigToString'))
    return suiteSigOps

def suiteGrpkeyOps():
    suiteGrpkeyOps = unittest.TestSuite()
    suiteGrpkeyOps.addTest(TestGrpkeyOps('test_grpkeyExportImport'))
    return suiteGrpkeyOps

def suiteManagerkeyOps():
    suiteManagerkeyOps = unittest.TestSuite()
    suiteManagerkeyOps.addTest(TestManagerkeyOps('test_mgrkeyExportImport'))
    return suiteManagerkeyOps

def suiteMemkeyOps():
    suiteMemkeyOps = unittest.TestSuite()
    suiteMemkeyOps.addTest(TestMemkeyOps('test_memkeyExportImport'))
    return suiteMemkeyOps

def suiteGmlOps():
    suiteGmlOps = unittest.TestSuite()
    suiteGmlOps.addTest(TestGmlOps('test_gmlExportImport'))
    return suiteGmlOps

def suiteCrlOps():
    suiteCrlOps = unittest.TestSuite()
    suiteCrlOps.addTest(TestCrlOps('test_crlExportImport'))
    return suiteCrlOps

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(suiteGroupOps())
    runner.run(suiteSigOps())
    runner.run(suiteGrpkeyOps())
    runner.run(suiteManagerkeyOps())
    runner.run(suiteMemkeyOps())
    runner.run(suiteGmlOps())
    runner.run(suiteCrlOps())
