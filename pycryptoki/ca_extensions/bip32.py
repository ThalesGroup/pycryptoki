"""
BIP32 Functions
"""
from ctypes import string_at, byref

from pycryptoki.attributes import Attributes
from pycryptoki.common_utils import AutoCArray
from pycryptoki.cryptoki.func_defs import CA_Bip32ExportPublicKey, CA_Bip32ImportPublicKey
from pycryptoki.cryptoki.c_defs import CK_ULONG, CK_BYTE
from pycryptoki.defines import CKR_OK, CKG_BIP32_MAX_SERIALIZED_LEN
from pycryptoki.exceptions import make_error_handle_function


def ca_bip32_import_public_key(session, key_data, attributes):
    """
    Imports a BIP32 Key to the HSM.

    :param int session: Session handle.
    :param bytes key_data: Key data, in bytes (base58 encoded)
    :param dict attributes: Attributes for the key.
    :return: retcode, key_handle.
    """
    attrs = Attributes(attributes).get_c_struct()
    c_key_data = AutoCArray(ctype=CK_BYTE, data=key_data)
    key_handle = CK_ULONG()
    ret = CA_Bip32ImportPublicKey(
        session, c_key_data.array, len(c_key_data), attrs, len(attributes), byref(key_handle)
    )
    if ret != CKR_OK:
        return ret, None

    return ret, key_handle.value


ca_bip32_import_public_key_ex = make_error_handle_function(ca_bip32_import_public_key)


def ca_bip32_export_public_key(session, key):
    """
    Exports a BIP32 Key from the HSM.

    :param int session: Session handle.
    :return: retcode, key data (base58 encoded bytestring)
    """
    c_key_data = AutoCArray(ctype=CK_BYTE, size=CK_ULONG(CKG_BIP32_MAX_SERIALIZED_LEN))
    ret = CA_Bip32ExportPublicKey(session, key, c_key_data.array, c_key_data.size)
    if ret != CKR_OK:
        return ret, None

    return ret, string_at(c_key_data.array, c_key_data.size.contents.value)


ca_bip32_export_public_key_ex = make_error_handle_function(ca_bip32_export_public_key)
