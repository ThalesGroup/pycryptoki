import logging
from ctypes import byref

from .cryptoki import CA_OpenSecureToken, CA_CloseSecureToken, CA_Extract, CA_Insert, CK_ULONG
from .mechanism import Mechanism
from .test_functions import make_error_handle_function

logger = logging.getLogger(__name__)


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


# noinspection PyIncorrectDocstring
def ca_extract(h_session, mech_type, mech_params):
    """

    :param mech_params:
    :param int h_session: Session handle
    """

    mech = Mechanism(mech_type, params=mech_params)

    cmech = mech.to_c_mech()
    ret = CA_Extract(h_session, cmech)

    return ret


ca_extract_ex = make_error_handle_function(ca_extract)


def ca_insert(h_session, mech_type, mech_params):
    """

    :param int h_session: Session handle
    :param py_mechanism_dict:
    :param params_type_string:

    """
    mech = Mechanism(mech_type, params=mech_params)

    cmech = mech.to_c_mech()
    ret = CA_Insert(h_session, cmech)
    return ret


ca_insert_ex = make_error_handle_function(ca_insert)
