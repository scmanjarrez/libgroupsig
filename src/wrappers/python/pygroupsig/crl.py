from _groupsig import lib, ffi
import base64

def crl_init(code):
    """
    Initializes a Certificate Revocation List (CRL) for schemes of the given type.

    Parameters:
        code: The code of the scheme.
    Returns:
        A native object representing the CRL. Throws an Exception on error.
    """
    crl = lib.crl_init(code)
    if crl == ffi.NULL:
        raise Exception('Error initializing CRL.')
    return crl

def crl_free(crl):
    """
    Frees the native memory used to represent the given CRL.

    Parameters:
        crl: The CRL structure to free.
    Returns:
        IOK (1) or IERROR (0)
    """
    return lib.crl_free(crl)
