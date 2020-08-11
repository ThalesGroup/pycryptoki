"""
Module to work with sessions, specifically dealing with ca_extension functions
"""

import logging
from ctypes import byref, string_at, sizeof

from pycryptoki.conversions import from_bytestring
from pycryptoki.cryptoki import (
    CK_FLAGS,
    CK_NOTIFY,
    CK_ULONG,
    CK_SESSION_HANDLE,
    CA_GetSessionInfo,
    CA_GetApplicationID,
    CK_APPLICATION_ID,
    CK_SLOT_ID,
    CA_OpenApplicationIDV2,
    CA_CloseApplicationIDV2,
    CA_SetApplicationIDV2,
)
from pycryptoki.cryptoki.func_defs import (
    CA_RandomizeApplicationID,
    CA_OpenSessionWithAppIDV2,
    CA_OpenApplicationIDForContainerV2,
    CA_CloseApplicationIDForContainerV2,
    CA_GetUserContainerNumber,
    CA_SessionCancel,
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


def ca_randomize_application_id():
    """Randomize the application ID in use"""
    return CA_RandomizeApplicationID()


ca_randomize_application_id_ex = make_error_handle_function(ca_randomize_application_id)


def ca_get_application_id():
    """
    Get the current process's AccessID.

    :return: retcode, bytestring tuple.
    """
    dest = CK_APPLICATION_ID()
    ret = CA_GetApplicationID(byref(dest))
    if ret != CKR_OK:
        return ret, None
    return ret, string_at(dest.id, sizeof(dest.id))


ca_get_application_id_ex = make_error_handle_function(ca_get_application_id)


def ca_open_application_id_v2(slot, appid):
    """
    Open the given AccessID for the target slot.

    :param slot: Slot #.
    :param appid: bytestring of length 16.
    :return: Retcode.
    """
    appid = from_bytestring(appid)
    access_id = CK_APPLICATION_ID(appid)
    return CA_OpenApplicationIDV2(CK_SLOT_ID(slot), byref(access_id))


ca_open_application_id_v2_ex = make_error_handle_function(ca_open_application_id_v2)


def ca_close_application_id_v2(slot, appid):
    """
    Close the AccessID associated with the given slot.

    :param slot: Slot #.
    :param appid: bytestring of length 16.
    :return: Retcode.
    """
    appid = from_bytestring(appid)
    access_id = CK_APPLICATION_ID(appid)
    return CA_CloseApplicationIDV2(CK_SLOT_ID(slot), byref(access_id))


ca_close_application_id_v2_ex = make_error_handle_function(ca_close_application_id_v2)


def ca_set_application_id_v2(appid):
    """
    Set the Current process's AccessID.

    :param appid: bytestring of length 16
    :return: Retcode
    """
    appid = from_bytestring(appid)
    access_id = CK_APPLICATION_ID(appid)
    return CA_SetApplicationIDV2(byref(access_id))


ca_set_application_id_v2_ex = make_error_handle_function(ca_set_application_id_v2)


def ca_open_session_with_app_id_v2(slot, flags, appid, notify=None, application=None):
    """
    Open a session with an app ID

    :param slot: slot number
    :param flags: session flags
    :param appid: bytestring of length 16
    :param notify: CK_NOTIFY callback (frequently unused in practice)
    :param application: also frequently unused in practice
    :return:
    """
    appid = from_bytestring(appid)
    access_id = CK_APPLICATION_ID(appid)
    h_session = CK_SESSION_HANDLE()
    if notify is None:
        notify = CK_NOTIFY(0)
    ret = CA_OpenSessionWithAppIDV2(
        CK_SLOT_ID(slot), CK_FLAGS(flags), byref(access_id), application, notify, byref(h_session)
    )

    if ret != CKR_OK:
        return ret, None

    return ret, h_session


ca_open_session_with_app_id_v2_ex = make_error_handle_function(ca_open_session_with_app_id_v2)


def ca_open_application_id_for_container_v2(slot, appid, container):
    """
    Open an access ID for the container. This differs from CA_OpenApplicationID in that it
    facilitates the opening of an app ID for a container which was not directly accessible via slot,
    as was the case for pre-PPSO HSMs. Because slots map 1:1 to containers with PPSO FW, this is
    functionally the same as CA_OpenApplicationIDV2.

    :param slot: slot number
    :param appid: bytestring of length 16
    :param container: container number corresponding to slot. Can use CA_GetUserContainerNumber to
                      get container number
    """
    appid = from_bytestring(appid)
    access_id = CK_APPLICATION_ID(appid)
    return CA_OpenApplicationIDForContainerV2(
        CK_SLOT_ID(slot), byref(access_id), CK_ULONG(container)
    )


ca_open_application_id_for_container_v2_ex = make_error_handle_function(
    ca_open_application_id_for_container_v2
)


def ca_close_application_id_for_container_v2(slot, appid, container):
    """Close an access ID for the container"""
    appid = from_bytestring(appid)
    access_id = CK_APPLICATION_ID(appid)
    return CA_CloseApplicationIDForContainerV2(
        CK_SLOT_ID(slot), byref(access_id), CK_ULONG(container)
    )


ca_close_application_id_for_container_v2_ex = make_error_handle_function(
    ca_close_application_id_for_container_v2
)


def ca_session_cancel(h_session, flags):
    """
    User cancels ongoing crypto operation

    :param h_session: session handle
    :param flags: session flags
    :return: Ret code
    """
    return CA_SessionCancel(CK_SESSION_HANDLE(h_session), CK_FLAGS(flags))


ca_session_cancel_ex = make_error_handle_function(ca_session_cancel)
