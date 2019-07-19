"""
Module to work with sessions, specifically dealing with ca_extension functions
"""

import logging
import sys
from ctypes import byref, string_at

from pycryptoki.cryptoki import (
    CK_ULONG,
    CK_SESSION_HANDLE,
    CA_GetSessionInfo,
    Structure,
    CK_BYTE,
    CA_GetApplicationID,
    CK_APPLICATION_ID,
    sizeof,
    CK_SLOT_ID,
    CA_OpenApplicationIDV2,
    CA_CloseApplicationIDV2,
)
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
    ret = CA_GetSessionInfo(
        h_session, byref(aid_hi), byref(aid_lo), byref(container), byref(auth_level)
    )
    if ret != CKR_OK:
        return ret, None

    session_info["aidHigh"] = aid_hi.value
    session_info["aidLow"] = aid_lo.value
    session_info["containerNumber"] = container.value
    session_info["authenticationLevel"] = auth_level.value

    return ret, session_info


ca_get_session_info_ex = make_error_handle_function(ca_get_session_info)


def ca_get_application_id():
    """
    Get the current process's AccessID.

    :return: retcode, bytestring tuple.
    """
    dest = CK_APPLICATION_ID()
    rv = CA_GetApplicationID(byref(dest))
    if rv != CKR_OK:
        return rv, None
    return rv, string_at(dest.id, sizeof(dest.id))


ca_get_application_id_ex = make_error_handle_function(ca_get_application_id)


def ca_open_application_id_v2(slot, appid):
    """
    Set the current process's AccessID.

    :param slot: Slot #. 
    :param appid: bytestring of length 16. 
    :return: Retcode.
    """
    access_id = CK_APPLICATION_ID(appid)
    return CA_OpenApplicationIDV2(CK_SLOT_ID(slot), access_id)


ca_open_application_id_v2_ex = make_error_handle_function(ca_open_application_id_v2)


def ca_close_application_id_v2(slot, appid):
    """
    Set the current process's AccessID.

    :param slot: Slot #. 
    :param appid: bytestring of length 16. 
    :return: Retcode.
    """
    access_id = CK_APPLICATION_ID(appid)
    return CA_CloseApplicationIDV2(CK_SLOT_ID(slot), access_id)


ca_close_application_id_v2_ex = make_error_handle_function(ca_close_application_id_v2)
