"""
Methods responsible for managing a user's session and login/c_logout
"""
import logging
import re
from ctypes import cast, c_char_p, c_void_p, create_string_buffer, \
    byref, pointer

# cryptoki constants
from .cryptoki import (CK_ULONG,
                       CK_BBOOL,
                       CK_SLOT_ID,
                       CK_SLOT_INFO,
                       CK_SESSION_HANDLE,
                       CK_FLAGS,
                       CK_NOTIFY,
                       CK_SESSION_INFO,
                       CK_USER_TYPE,
                       CK_TOKEN_INFO,
                       CK_VOID_PTR,
                       CK_BYTE)

# Cryptoki Functions
from .cryptoki import (C_Initialize,
                       C_GetSlotList,
                       C_GetSlotInfo,
                       C_CloseAllSessions,
                       C_GetSessionInfo,
                       C_OpenSession,
                       C_Login,
                       C_Logout,
                       C_CloseSession,
                       C_InitPIN,
                       CA_FactoryReset,
                       C_GetTokenInfo,
                       C_Finalize,
                       C_SetPIN,
                       CA_OpenApplicationID,
                       CA_CloseApplicationID,
                       CA_Restart,
                       CA_SetApplicationID)

from .common_utils import AutoCArray, refresh_c_arrays
from .defines import CKR_OK, CKF_RW_SESSION, CKF_SERIAL_SESSION
from .test_functions import make_error_handle_function

LOG = logging.getLogger(__name__)


def c_initialize():
    """Calls C_Initialize to c_initialize the board


    :returns: The result code

    """
    # INITIALIZE
    LOG.info("C_Initialize: Initializing HSM")
    ret = C_Initialize(0)
    return ret


c_initialize_ex = make_error_handle_function(c_initialize)


def c_finalize():
    """Calls C_Finalize


    :returns: The result code

    """
    LOG.info("C_Finalize: Finalizing HSM")
    ret = C_Finalize(0)
    return ret


c_finalize_ex = make_error_handle_function(c_finalize)


def c_open_session(slot_num, flags=(CKF_SERIAL_SESSION | CKF_RW_SESSION)):
    """Opens a session on a given slot

    :param slot_num: The slot to get a session on
    :param flags: The flags to open the session with
        (Default value = (CKF_SERIAL_SESSION | CKF_RW_SESSION)
    :returns: The result code, the session handle

    """
    # OPEN SESSION
    arg3 = create_string_buffer("Application")
    h_session = CK_SESSION_HANDLE()
    arg3 = cast(arg3, c_void_p)
    # CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR)
    ret = C_OpenSession(CK_SLOT_ID(slot_num), CK_FLAGS(flags),
                        cast(arg3, CK_VOID_PTR), CK_NOTIFY(0),
                        pointer(h_session))
    LOG.info("C_OpenSession: Opening Session. slot=" + str(slot_num))

    return ret, h_session.value


c_open_session_ex = make_error_handle_function(c_open_session)


def login(h_session, slot_num=1, password=None, user_type=1):
    """Login to the HSM

    :param h_session: Current session
    :param slot_num: Slot index to login on (Default value = 1)
    :param password: Password to login with (Default value = "userpin")
    :param user_type: User type to login as (Default value = 1)
    :returns: The result code

    """
    # LOGIN
    LOG.info("C_Login: "
             "user_type=%s, "
             "slot=%s, "
             "password=%s", user_type, slot_num, password)
    if password == '':
        password = None

    user_type = CK_USER_TYPE(long(user_type))
    password = AutoCArray(data=password, ctype=CK_BYTE)

    ret = C_Login(h_session, user_type, password.array, password.size.contents)

    return ret


login_ex = make_error_handle_function(login)


def get_slot_info(description):
    """Returns a slot with a certain descriptor

    Limitation: Only returns the first slot it finds that fits the description

    :param description: The name of the slot to find
    :returns: THe result code, a Python dictionary representing the slots

    """
    ret, slot_dict = get_slot_dict()

    return_dict = {}

    for key in slot_dict:
        if re.match(description, slot_dict[key]):
            return_dict[key] = slot_dict[key]

    return ret, return_dict


get_slot_info_ex = make_error_handle_function(get_slot_info)


def c_get_session_info(session):
    """

    :param session: return:

    """
    session_info = {}
    c_session_info = CK_SESSION_INFO()
    ret = C_GetSessionInfo(CK_SESSION_HANDLE(session), byref(c_session_info))

    if ret == CKR_OK:
        session_info['state'] = c_session_info.state
        session_info['flags'] = c_session_info.flags
        session_info['slotID'] = c_session_info.slotID
        session_info['usDeviceError'] = c_session_info.usDeviceError

    return ret, session_info


c_get_session_info_ex = make_error_handle_function(c_get_session_info)


def c_get_token_info(slot_id):
    """Gets the token info for a given slot id

    :param slot_id: Slot index to get the token info for
    :returns: The result code, A python dictionary representing the token info

    """
    token_info = {}
    c_token_info = CK_TOKEN_INFO()
    LOG.info("Getting token info. slot=" + str(slot_id))
    ret = C_GetTokenInfo(CK_ULONG(slot_id), byref(c_token_info))

    if ret == CKR_OK:
        token_info['label'] = str(cast(c_token_info.label, c_char_p).value)[0:32].strip()
        token_info['manufacturerID'] = str(cast(c_token_info.manufacturerID,
                                                c_char_p).value)[0:32].strip()
        token_info['model'] = str(cast(c_token_info.model,
                                       c_char_p).value)[0:16].strip()
        token_info['serialNumber'] = int(str(cast(c_token_info.serialNumber,
                                                  c_char_p).value)[0:16].strip())
        token_info['flags'] = c_token_info.flags
        token_info['ulFreePrivateMemory'] = c_token_info.ulFreePrivateMemory
        token_info['ulTotalPrivateMemory'] = c_token_info.ulTotalPrivateMemory
        token_info['ulMaxSessionCount'] = c_token_info.usMaxSessionCount
        token_info['ulSessionCount'] = c_token_info.usSessionCount
        token_info['ulMaxRwSessionCount'] = c_token_info.usMaxRwSessionCount
        token_info['ulRwSessionCount'] = c_token_info.usRwSessionCount
        token_info['ulMaxPinLen'] = c_token_info.usMaxPinLen
        token_info['ulMinPinLen'] = c_token_info.usMinPinLen
        token_info['ulTotalPublicMemory'] = c_token_info.ulTotalPublicMemory
        token_info['ulFreePublicMemory'] = c_token_info.ulFreePublicMemory
        token_info['hardwareVersion'] = c_token_info.hardwareVersion
        token_info['firmwareVersion'] = c_token_info.firmwareVersion
        token_info['utcTime'] = str(cast(c_token_info.utcTime, c_char_p).value)[0:16].strip()

    return ret, token_info


c_get_token_info_ex = make_error_handle_function(c_get_token_info)


def get_slot_dict():
    """Compiles a dictionary of the available slots


    :returns: A python dictionary of the available slots

    """
    slot_list = AutoCArray()

    @refresh_c_arrays(1)
    def _get_slot_list():
        """
        Closure to refresh properties.
        """
        return C_GetSlotList(CK_BBOOL(0), slot_list.array, slot_list.size)

    ret = _get_slot_list()
    if ret != CKR_OK:
        return ret, None

    slot_info = CK_SLOT_INFO()
    slot_dict = {}
    for slot in slot_list:
        C_GetSlotInfo(slot, byref(slot_info))
        slot_description = str(cast(slot_info.slotDescription, c_char_p).value)[0:63].strip()
        slot_dict[slot] = slot_description

    return ret, slot_dict


get_slot_dict_ex = make_error_handle_function(get_slot_dict)


def c_close_session(h_session):
    """Closes a session

    :param h_session: The session to close
    :returns: The result code

    """
    # CLOSE SESSION
    LOG.info("C_CloseSession: Closing session " + str(h_session))
    ret = C_CloseSession(h_session)
    return ret


c_close_session_ex = make_error_handle_function(c_close_session)


def c_logout(h_session):
    """Logs out of a given session

    :param h_session: The session to log out from
    :returns: The result code

    """
    LOG.info("C_Logout: Logging out of session " + str(h_session))
    ret = C_Logout(h_session)
    return ret


c_logout_ex = make_error_handle_function(c_logout)


def c_init_pin(h_session, pin):
    """Initializes the PIN

    :param h_session: Current session
    :param pin: pin to c_initialize
    :returns: THe result code

    """

    LOG.info("C_InitPIN: Initializing PIN to " + str(pin))
    pin = AutoCArray(data=pin)
    ret = C_InitPIN(h_session, pin.array, pin.size.contents)
    return ret


c_init_pin_ex = make_error_handle_function(c_init_pin)


def ca_factory_reset(slot):
    """Does a factory reset on a given slot

    :param slot: The slot to do a factory reset on
    :returns: The result code

    """
    LOG.info("CA_FactoryReset: Factory Reset. slot=" + str(slot))
    ret = CA_FactoryReset(CK_SLOT_ID(slot), CK_ULONG(0))
    return ret


ca_factory_reset_ex = make_error_handle_function(ca_factory_reset)


def c_set_pin(h_session, old_pass, new_pass):
    """Allows a user to change their PIN

    :param h_session: Session of the user
    :param old_pass: The user's old password
    :param new_pass: The user's desired new password
    :returns: The result code

    """
    LOG.info("C_SetPIN: Changing password. "
             "old_pass=" + str(old_pass) + ", new_pass=" + str(new_pass))

    old_pass = AutoCArray(data=old_pass)
    new_pass = AutoCArray(data=new_pass)

    ret = C_SetPIN(h_session,
                   old_pass.array, old_pass.size.contents,
                   new_pass.array, new_pass.size.contents)
    return ret


c_set_pin_ex = make_error_handle_function(c_set_pin)


def c_close_all_sessions(slot):
    """Closes all the sessions on a given slot

    :param slot: The slot to close all sessions on
    :returns: The result code

    """

    LOG.info("C_CloseAllSessions: Closing all sessions. slot=" + str(slot))
    ret = C_CloseAllSessions(CK_ULONG(slot))
    return ret


c_close_all_sessions_ex = make_error_handle_function(c_close_all_sessions)


def ca_openapplicationID(slot, id_high, id_low):
    """

    :param slot:
    :param id_high:
    :param id_low:

    """
    uid_high = CK_ULONG(id_high)
    uid_low = CK_ULONG(id_low)

    LOG.info("CA_OpenApplicationID: Attempting to open App ID %s:%s", id_high, id_low)

    ret = CA_OpenApplicationID(CK_ULONG(slot), uid_high, uid_low)

    LOG.info("CA_OpenApplicationID: Ret Value: %s", ret)

    return ret


ca_openapplicationID_ex = make_error_handle_function(ca_openapplicationID)


def ca_closeapplicationID(slot, id_high, id_low):
    """

    :param slot:
    :param id_high:
    :param id_low:

    """
    uid_high = CK_ULONG(id_high)
    uid_low = CK_ULONG(id_low)

    LOG.info("CA_CloseApplicationID: Attempting to close App ID %s:%s", id_high, id_low)

    ret = CA_CloseApplicationID(CK_ULONG(slot), uid_high, uid_low)

    LOG.info("CA_CloseApplicationID: Ret Value: %s", ret)

    return ret


ca_closeapplicationID_ex = make_error_handle_function(ca_closeapplicationID)


def ca_setapplicationID(id_high, id_low):
    """Set the App ID for the current application.

    :param id_high:
    :param id_low:

    """
    uid_high = CK_ULONG(id_high)
    uid_low = CK_ULONG(id_low)

    LOG.info("CA_SetApplicationID: Attempting to set App ID %s:%s", id_high, id_low)

    ret = CA_SetApplicationID(uid_high, uid_low)

    LOG.info("CA_SetApplicationID: Ret Value: %s", ret)

    return ret


ca_setapplicationID_ex = make_error_handle_function(ca_setapplicationID)


def ca_restart(slot):
    """

    :param slot:

    """
    LOG.info("CA_Restart: attempting to restart")

    ret = CA_Restart(CK_ULONG(slot))

    LOG.info("CA_Restart: Ret Value: %s", ret)

    return ret


ca_restart_ex = make_error_handle_function(ca_restart)
