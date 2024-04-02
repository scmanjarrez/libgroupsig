from _groupsig import lib, ffi
from . import constants

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

def crl_export(crl, file):
    """
    Exports a CRL to a Base64 string.

    Parameters:
        crl: The CRL to export.
    Returns:
        A Base64 string. On error, an Exception is thrown.
    """
    fp = ffi.new("char []", file.encode())
    if lib.crl_export(crl, fp, lib.CRL_FILE) == constants.IERROR:
        raise Exception('Error exporting CRL.')

def crl_import(code, file):
    """
    Imports a CRL from a Base64 string.

    Parameters:
        code: The code of the scheme related to this GML.
        b64crl: The Base64 string.
    Returns:
        The imported CRL native data structure. Throws an Exception on error.
    """
    fp = ffi.new("char []", file.encode())
    crl = lib.crl_import(code, lib.CRL_FILE, fp)
    if crl == ffi.NULL:
        raise Exception('Error importing CRL.')
    return crl
