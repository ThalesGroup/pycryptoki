"""
Backup related commands
"""
import logging
from ctypes import byref, c_ulong

from .common_utils import AutoCArray, refresh_c_arrays
from .cryptoki import CA_OpenSecureToken, CA_CloseSecureToken, CA_Extract, CA_Insert, \
    CK_ULONG, \
    CA_SIMExtract, CK_BYTE, string_at, create_string_buffer, POINTER, cast, pointer, \
    CK_BYTE_PTR, c_ubyte, CA_SIMInsert
from .defines import (CKA_SIM_NO_AUTHORIZATION, CKA_SIM_PASSWORD, CKA_SIM_CHALLENGE,
                      CKA_SIM_SECURE_PORT, CKA_SIM_PORTABLE_NO_AUTHORIZATION,
                      CKA_SIM_PORTABLE_PASSWORD, CKA_SIM_PORTABLE_CHALLENGE,
                      CKA_SIM_PORTABLE_SECURE_PORT)
from .exceptions import make_error_handle_function
from .mechanism import parse_mechanism

logger = logging.getLogger(__name__)

SIM_AUTH_FORMS = (CKA_SIM_NO_AUTHORIZATION,
                  CKA_SIM_PASSWORD,
                  CKA_SIM_CHALLENGE,
                  CKA_SIM_SECURE_PORT,
                  CKA_SIM_PORTABLE_NO_AUTHORIZATION,
                  CKA_SIM_PORTABLE_PASSWORD,
                  CKA_SIM_PORTABLE_CHALLENGE,
                  CKA_SIM_PORTABLE_SECURE_PORT)


def ca_open_secure_token(h_session, storage_path, dev_ID, mode):
    """

    :param int h_session: Session handle
    :param storage_path:
    :param dev_ID:
    :param mode:

    """
    number_of_elems = CK_ULONG(0)
    ph_ID = CK_ULONG(0)
    ret = CA_OpenSecureToken(h_session, storage_path, dev_ID, mode, byref(number_of_elems),
                             byref(ph_ID))

    return ret, number_of_elems.value, ph_ID.value


ca_open_secure_token_ex = make_error_handle_function(ca_open_secure_token)


def ca_close_secure_token(h_session, h_ID):
    """

    :param int h_session: Session handle
    :param h_ID:

    """

    ret = CA_CloseSecureToken(h_session, h_ID)
    return ret


ca_close_secure_token_ex = make_error_handle_function(ca_close_secure_token)


def ca_extract(h_session, mechanism):
    """

    :param int h_session: Session handle
    :param mechanism: See the :py:func:`~pycryptoki.mechanism.parse_mechanism` function
        for possible values.
    """

    mech = parse_mechanism(mechanism)
    ret = CA_Extract(h_session, mech)

    return ret


ca_extract_ex = make_error_handle_function(ca_extract)


def ca_insert(h_session, mechanism):
    """

    :param int h_session: Session handle
    :param mechanism: See the :py:func:`~pycryptoki.mechanism.parse_mechanism` function
        for possible values.
    """
    mech = parse_mechanism(mechanism)
    ret = CA_Insert(h_session, mech)
    return ret


ca_insert_ex = make_error_handle_function(ca_insert)


def ca_sim_extract(h_session, key_handles, authform, auth_secrets=None, subset_size=0,
                   delete_after_extract=False):
    """
    Extract multiple keys to a wrapped blob. The returned blob can then be written into
    a file.

    :param int h_session: Session handle
    :param list[int] key_handles: List of key handles to extract
    :param int authform: Type of authentication to use. See :class:`pycryptoki.backup.SIM_AUTH`
        for details
    :param list(str) auth_secrets: Authorization secrets to use (Length will correspond to the
        ``N`` value in ckdemo)
    :param int subset_size: Subset size required for key use (Corresponds to the ``M`` value in
        ckdemo)
    :param bool delete_after_extract: If true, will destroy the original keys after they have been
        extracted.
    :return: retcode, blob_data tuple.
    """

    if auth_secrets is None:
        auth_secrets = []

    if authform not in SIM_AUTH_FORMS:
        raise ValueError("Invalid authform, import and use SIM_AUTH to select an authentication "
                         "type.")

    if subset_size > len(auth_secrets):
        raise ValueError("Subset size cannot be larger than the N value (length of auth secrets)")

    auth_secret_sizes = AutoCArray(data=[c_ulong(len(x)) for x in auth_secrets])
    c_auth_secrets = AutoCArray(data=[cast(pointer(create_string_buffer(x, len(x))),
                                         CK_BYTE_PTR) for x in auth_secrets],
                              ctype=POINTER(CK_BYTE))
    c_key_handles = AutoCArray(key_handles)
    blob_data = AutoCArray(ctype=c_ubyte)

    @refresh_c_arrays(1)
    def extract():
        """
        Closure to allow us to get the size of the blob_data.
        """
        blobarr, bloblen = blob_data.array, blob_data.size
        return CA_SIMExtract(h_session,
                             len(c_key_handles), c_key_handles.array,
                             CK_ULONG(len(auth_secrets)), CK_ULONG(subset_size),
                             authform,
                             auth_secret_sizes.array, c_auth_secrets.array,
                             delete_after_extract,
                             bloblen, blobarr)

    ret = extract()
    if ret == 0:
        ret_blob_data = string_at(blob_data.array, len(blob_data))
    else:
        ret_blob_data = None
    return ret, ret_blob_data


ca_sim_extract_ex = make_error_handle_function(ca_sim_extract)


def ca_sim_insert(h_session, blob_data, authform, auth_secrets=None):
    """
    Insert keys into the HSM from blob data that was wrapped off using SIM.

    :param int h_session: Session handle
    :param str blob_data: Read in raw wrapped data. Typically read in from a file.
    :param int authform: Type of authentication to use. See :class:`pycryptoki.backup.SIM_AUTH`
        for details
    :param list[str] auth_secrets: Authorization secrets to use (Length will correspond to the
        ``N`` value in ckdemo)
    :return: retcode, keys tuple, where ``keys`` is a list of integers.
    """

    if auth_secrets is None:
        auth_secrets = []

    if authform not in SIM_AUTH_FORMS:
        raise ValueError("Invalid authform, import and use SIM_AUTH to select an authentication "
                         "type.")

    auth_secret_sizes = AutoCArray(data=[c_ulong(len(x)) for x in auth_secrets])
    c_auth_secrets = AutoCArray(data=[cast(pointer(create_string_buffer(x, len(x))),
                                         CK_BYTE_PTR) for x in auth_secrets],
                              ctype=POINTER(CK_BYTE))
    c_key_handles = AutoCArray()
    c_blob_data = create_string_buffer(blob_data, len(blob_data))

    @refresh_c_arrays(1)
    def insert():
        """
        Closure to allow us to get the size of the blob_data.
        """
        key_array, key_array_len = c_key_handles.array, c_key_handles.size
        return CA_SIMInsert(h_session,
                            CK_ULONG(len(auth_secrets)), authform,
                            auth_secret_sizes.array, c_auth_secrets.array,
                            len(blob_data), cast(c_blob_data, POINTER(CK_BYTE)),
                            key_array_len, key_array)

    ret = insert()
    if ret == 0:
        handles = [int(x) for x in c_key_handles]
    else:
        handles = None
    return ret, handles


ca_sim_insert_ex = make_error_handle_function(ca_sim_insert)
