from ctypes import byref
import logging

from pycryptoki.cryptoki import CA_OpenSecureToken, CA_CloseSecureToken, CA_Extract, CA_Insert, CK_ULONG
from pycryptoki.mechanism import get_c_struct_from_mechanism, \
    get_python_dict_from_c_mechanism
from pycryptoki.test_functions import make_error_handle_function

logger = logging.getLogger(__name__)

'''
CK_SESSION_HANDLE hSession,
                                  CK_ULONG storagePath,
                                  CK_ULONG devID,
                                  CK_ULONG mode,
                                  CK_ULONG_PTR numberOfElems,
                                  CK_ULONG_PTR phID
'''


def ca_open_secure_token(h_session, storage_path, dev_ID, mode):
    """

    :param h_session:
    :param storage_path:
    :param dev_ID:
    :param mode:

    """
    number_of_elems = CK_ULONG(0)
    ph_ID = CK_ULONG(0)
    ret = CA_OpenSecureToken(h_session, storage_path, dev_ID, mode, byref(number_of_elems), byref(ph_ID))

    return ret, number_of_elems.value, ph_ID.value


ca_open_secure_token_ex = make_error_handle_function(ca_open_secure_token)

'''
CK_SESSION_HANDLE hSession, CK_ULONG hID
'''


def ca_close_secure_token(h_session, h_ID):
    """

    :param h_session:
    :param h_ID:

    """

    ret = CA_CloseSecureToken(h_session, h_ID)
    return ret


ca_close_secure_token_ex = make_error_handle_function(ca_close_secure_token)


def ca_extract(h_session, py_mechanism_dict, params_type_string):
    """

    :param h_session:
    :param py_mechanism_dict:
    :param params_type_string:

    """

    c_mechanism = get_c_struct_from_mechanism(py_mechanism_dict, params_type_string)

    ret = CA_Extract(h_session, c_mechanism)

    py_dictionary = get_python_dict_from_c_mechanism(c_mechanism, params_type_string)
    return ret, py_dictionary


ca_extract_ex = make_error_handle_function(ca_extract)

# CA_Insert( CK_SESSION_HANDLE hSession,
#                           CK_MECHANISM_PTR pMechanism )

def ca_insert(h_session, py_mechanism_dict, params_type_string):
    """

    :param h_session:
    :param py_mechanism_dict:
    :param params_type_string:

    """

    c_mechanism = get_c_struct_from_mechanism(py_mechanism_dict, params_type_string)
    ret = CA_Insert(h_session, c_mechanism)
    py_dictionary = get_python_dict_from_c_mechanism(c_mechanism, params_type_string)
    return ret, py_dictionary


ca_insert_ex = make_error_handle_function(ca_insert)
