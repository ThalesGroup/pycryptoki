"""
Module to work with sessions, specifically dealing with ca_extension functions
"""

import logging
from ctypes import byref

from pycryptoki.cryptoki import CK_ULONG, CK_SESSION_HANDLE, CA_GetSessionInfo
from pycryptoki.defines import CKR_OK
from pycryptoki.exceptions import make_error_handle_function


LOG = logging.getLogger(__name__)


def ca_get_session_info(session):
    """
    ca extension function that returns session information

    :param session: session handle
    :return: tuple of return code and session info dict
    """
    session_info = {}
    h_session = CK_SESSION_HANDLE(session)
    aid_hi = CK_ULONG()
    aid_lo = CK_ULONG()
    container = CK_ULONG()
    auth_level = CK_ULONG()
    ret = CA_GetSessionInfo(h_session, byref(aid_hi), byref(aid_lo), byref(container), byref(auth_level))
    if ret != CKR_OK:
        return ret, None

    session_info['aidHigh'] = aid_hi.value
    session_info['aidLow'] = aid_lo.value
    session_info['containerNumber'] = container.value
    session_info['authenticationLevel'] = auth_level.value

    return ret, session_info


ca_get_session_info_ex = make_error_handle_function(ca_get_session_info)

