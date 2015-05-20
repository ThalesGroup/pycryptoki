"""
Methods responsible for managing a user's session and login/c_logout
"""
from ctypes import cast, c_char_p, c_void_p, create_string_buffer, \
    byref, pointer
import logging
import re

from cryptoki import C_Initialize, CK_ULONG, C_GetSlotList, CK_BBOOL, CK_SLOT_ID, \
    CK_SLOT_INFO, C_GetSlotInfo, C_CloseAllSessions, C_GetSessionInfo, CK_SESSION_HANDLE, \
    CK_SESSION_INFO, C_OpenSession, CK_FLAGS, CK_NOTIFY, C_Login, CK_USER_TYPE, C_Logout, \
    C_CloseSession, C_InitPIN, CA_FactoryReset, \
    C_GetTokenInfo, CK_TOKEN_INFO, C_Finalize, C_SetPIN, CA_DeleteContainerWithHandle, CA_OpenApplicationID, \
    CA_CloseApplicationID, CA_Restart, CA_SetApplicationID
from defines import CKR_OK
from pycryptoki.cryptoki import CA_CreateContainer, CK_VOID_PTR, \
    CK_BYTE_PTR
from pycryptoki.defines import CKF_RW_SESSION, CKF_SERIAL_SESSION
from pycryptoki.test_functions import make_error_handle_function

logger = logging.getLogger(__name__)


def c_initialize():
    """Calls C_Initialize to c_initialize the board


    :returns: The result code

    """
    # INITIALIZE
    logger.info("C_Initialize: Initializing HSM")
    ret = C_Initialize(0)
    return ret


c_initialize_ex = make_error_handle_function(c_initialize)


def c_finalize():
    """Calls C_Finalize


    :returns: The result code

    """
    logger.info("C_Finalize: Finalizing HSM")
    ret = C_Finalize(0)
    return ret


c_finalize_ex = make_error_handle_function(c_finalize)


def c_open_session(slot_num, flags=(CKF_SERIAL_SESSION | CKF_RW_SESSION)):
    """Opens a session on a given slot

    :param slot_num: The slot to get a session on
    :param flags: The flags to open the session with (Default value = (CKF_SERIAL_SESSION | CKF_RW_SESSION)
    :returns: The result code, the session handle

    """
    # OPEN SESSION
    arg3 = create_string_buffer("Application")
    h_session = CK_SESSION_HANDLE()
    arg3 = cast(arg3, c_void_p)  # CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR)
    ret = C_OpenSession(CK_SLOT_ID(slot_num), CK_FLAGS(flags), cast(arg3, CK_VOID_PTR), CK_NOTIFY(0),
                        pointer(h_session))
    logger.info("C_OpenSession: Opening Session. slot=" + str(slot_num))

    return ret, h_session.value


c_open_session_ex = make_error_handle_function(c_open_session)


def login(h_session, slot_num=1, password="userpin", user_type=1):
    """Login to the HSM

    :param h_session: Current session
    :param slot_num: Slot index to login on (Default value = 1)
    :param password: Password to login with (Default value = "userpin")
    :param user_type: User type to login as (Default value = 1)
    :returns: The result code

    """
    # LOGIN
    user_type = long(user_type)
    pb_password = c_char_p(password)
    logger.info(
        "C_Login: Logging In. user_type=" + str(user_type) + ", slot=" + str(slot_num) + ", password=" + password)
    ret = C_Login(h_session, CK_USER_TYPE(user_type), cast(pb_password, CK_BYTE_PTR), CK_ULONG(len(password)))
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
    logger.info("Getting token info. slot=" + str(slot_id))
    ret = C_GetTokenInfo(CK_ULONG(slot_id), byref(c_token_info))

    if ret == CKR_OK:
        token_info['label'] = str(cast(c_token_info.label, c_char_p).value)[0:32].strip()
        token_info['manufacturerID'] = str(cast(c_token_info.manufacturerID, c_char_p).value)[0:32].strip()
        token_info['model'] = str(cast(c_token_info.model, c_char_p).value)[0:16].strip()
        token_info['serialNumber'] = int(str(cast(c_token_info.serialNumber, c_char_p).value)[0:16].strip())
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
    us_count = CK_ULONG(0)
    ret = C_GetSlotList(CK_BBOOL(0), None, byref(us_count))
    if ret != CKR_OK: return ret
    num_slots = (us_count.value + 1)
    slot_list = (CK_SLOT_ID * num_slots)()
    ret = C_GetSlotList(CK_BBOOL(0), slot_list, byref(us_count))
    if ret != CKR_OK: return ret
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
    logger.info("C_CloseSession: Closing session " + str(h_session))
    ret = C_CloseSession(h_session)
    return ret


c_close_session_ex = make_error_handle_function(c_close_session)


def c_logout(h_session):
    """Logs out of a given session

    :param h_session: The session to log out from
    :returns: The result code

    """
    logger.info("C_Logout: Logging out of session " + str(h_session))
    ret = C_Logout(h_session)
    return ret


c_logout_ex = make_error_handle_function(c_logout)


def c_init_pin(h_session, pin):
    """Initializes the PIN

    :param h_session: Current session
    :param pin: pin to c_initialize
    :returns: THe result code

    """

    logger.info("C_InitPIN: Initializing PIN to " + str(pin))
    if pin == '':
        ret = C_InitPIN(h_session, None, CK_ULONG(0))
    else:
        ret = C_InitPIN(h_session, cast(create_string_buffer(pin), CK_BYTE_PTR), CK_ULONG(len(pin)))
    return ret


c_init_pin_ex = make_error_handle_function(c_init_pin)


def ca_factory_reset(slot):
    """Does a factory reset on a given slot

    :param slot: The slot to do a factory reset on
    :returns: The result code

    """
    logger.info("CA_FactoryReset: Factory Reset. slot=" + str(slot))
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
    logger.info("C_SetPIN: Changing password. old_pass=" + str(old_pass) + ", new_pass=" + str(new_pass))
    if old_pass == '' and new_pass == '':
        ret = C_SetPIN(h_session, None, CK_ULONG(0),
                       None, CK_ULONG(0))
        return ret
    else:
        ret = C_SetPIN(h_session, cast(create_string_buffer(old_pass), CK_BYTE_PTR), CK_ULONG(len(old_pass)),
                       cast(create_string_buffer(new_pass), CK_BYTE_PTR), CK_ULONG(len(new_pass)))
        return ret


c_set_pin_ex = make_error_handle_function(c_set_pin)


def c_close_all_sessions(slot):
    """Closes all the sessions on a given slot

    :param slot: The slot to close all sessions on
    :returns: The result code

    """

    logger.info("C_CloseAllSessions: Closing all sessions. slot=" + str(slot))
    ret = C_CloseAllSessions(CK_ULONG(slot))
    return ret


c_close_all_sessions_ex = make_error_handle_function(c_close_all_sessions)


def ca_create_container(h_session, storage_size, password='userpin', label='Inserted Token'):
    """Inserts a token into a slot without a Security Officer on the token

    :param h_session: Current session
    :param storage_size: The storage size of the token (0 for undefined/unlimited)
    :param password: The password associated with the token (Default value = 'userpin')
    :param label: The label associated with the token (Default value = 'Inserted Token')
    :returns: The result code, The container number

    """

    if password == '':
        container_number = CK_ULONG()
        logger.info("CA_CreateContainer: Inserting token with no SO storage_size=" + str(
            storage_size) + ", pin=" + password + ", label=" + label)
        ret = CA_CreateContainer(h_session, CK_ULONG(0), cast(create_string_buffer(label), CK_BYTE_PTR),
                                 CK_ULONG(len(label)), None,
                                 CK_ULONG(0), CK_ULONG(-1), CK_ULONG(-1), CK_ULONG(0), CK_ULONG(0),
                                 CK_ULONG(storage_size), byref(container_number))
        logger.info("CA_CreateContainer: Inserted token into slot " + str(container_number.value))
        return ret, container_number.value
    else:
        container_number = CK_ULONG()
        logger.info("CA_CreateContainer: Inserting token with no SO storage_size=" + str(
            storage_size) + ", pin=" + password + ", label=" + label)
        ret = CA_CreateContainer(h_session, CK_ULONG(0), cast(create_string_buffer(label), CK_BYTE_PTR),
                                 CK_ULONG(len(label)), cast(create_string_buffer(password), CK_BYTE_PTR),
                                 CK_ULONG(len(password)), CK_ULONG(-1), CK_ULONG(-1), CK_ULONG(0), CK_ULONG(0),
                                 CK_ULONG(storage_size), byref(container_number))
        logger.info("CA_CreateContainer: Inserted token into slot " + str(container_number.value))
        return ret, container_number.value


ca_create_container_ex = make_error_handle_function(ca_create_container)


def ca_delete_container_with_handle(h_session, container_handle):
    """

    :param h_session:
    :param container_handle:

    """
    container_number = CK_ULONG(container_handle)
    logger.info(
        "CA_DeleteContainerWithHandle: Attempting to delete container with handle: {0}".format(container_handle))

    ret = CA_DeleteContainerWithHandle(h_session, container_number)

    logger.info("CA_DeleteContainerWithHandle: Ret Value: {0}".format(ret))

    return ret


ca_delete_container_with_handle_ex = make_error_handle_function(ca_delete_container_with_handle)


def ca_openapplicationID(slot, id_high, id_low):
    """

    :param slot:
    :param id_high:
    :param id_low:

    """
    uid_high = CK_ULONG(id_high)
    uid_low = CK_ULONG(id_low)

    logger.info("CA_OpenApplicationID: Attempting to open App ID {0}:{1}".format(id_high, id_low))

    ret = CA_OpenApplicationID(CK_ULONG(slot), uid_high, uid_low)

    logger.info("CA_OpenApplicationID: Ret Value: {0}".format(ret))

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

    logger.info("CA_CloseApplicationID: Attempting to open App ID {0}:{1}".format(id_high, id_low))

    ret = CA_CloseApplicationID(CK_ULONG(slot), uid_high, uid_low)

    logger.info("CA_CloseApplicationID: Ret Value: {0}".format(ret))

    return ret


ca_closeapplicationID_ex = make_error_handle_function(ca_closeapplicationID)


def ca_setapplicationID(id_high, id_low):
    """Set the App ID for the current application.

    :param id_high:
    :param id_low:

    """
    uid_high = CK_ULONG(id_high)
    uid_low = CK_ULONG(id_low)

    logger.info("CA_SetApplicationID: Attempting to set App ID {0}:{1}".format(id_high, id_low))

    ret = CA_SetApplicationID(uid_high, uid_low)

    logger.info("CA_SetApplicationID: Ret Value: {0}".format(ret))

    return ret


ca_setapplicationID_ex = make_error_handle_function(ca_setapplicationID)


def ca_restart(slot):
    """

    :param slot:

    """
    logger.info("CA_Restart: attempting to restart")

    ret = CA_Restart(CK_ULONG(slot))

    logger.info("CA_Restart: Ret Value: {0}".format(ret))

    return ret


ca_restart_ex = make_error_handle_function(ca_restart)
