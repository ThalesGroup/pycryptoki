"""
STC2 Functions
"""
from ctypes import byref, cast, POINTER, string_at, c_ulong, create_string_buffer
from six import b

from pycryptoki.common_utils import AutoCArray, refresh_c_arrays
from pycryptoki.cryptoki.c_defs import CK_BYTE, CK_CHAR, CK_ULONG
from pycryptoki.cryptoki.ck_defs import CK_SESSION_HANDLE, CK_SLOT_ID
from pycryptoki.cryptoki.func_defs import (
    CA_STCRegister,
    CA_STCRegisterV2,
    CA_STCDeregister,
    CA_STCGetPubKey,
    CA_STCGetClientsList,
    CA_STCGetClientInfo,
    CA_STCGetClientInfoV2,
    CA_STCGetPartPubKey,
    CA_STCGetAdminPubKey,
    CA_STCGetPID,
    CA_STCGetAdminPID,
    CA_STCSetCipherAlgorithm,
    CA_STCGetCipherAlgorithm,
    CA_STCClearCipherAlgorithm,
    CA_STCSetDigestAlgorithm,
    CA_STCGetDigestAlgorithm,
    CA_STCClearDigestAlgorithm,
    CA_STCSetKeyLifeTime,
    CA_STCGetKeyLifeTime,
    CA_STCSetKeyActivationTimeOut,
    CA_STCGetKeyActivationTimeOut,
    CA_STCSetMaxSessions,
    CA_STCGetMaxSessions,
    CA_STCSetSequenceWindowSize,
    CA_STCGetSequenceWindowSize,
    CA_STCIsEnabled,
    CA_STCGetState,
    CA_STCGetChannelID,
    CA_STCGetCipherID,
    CA_STCGetDigestID,
    CA_STCGetCurrentKeyLife,
    CA_STCGetCipherIDs,
    CA_STCGetCipherNameByID,
    CA_STCGetDigestIDs,
    CA_STCGetDigestNameByID,
)
from pycryptoki.defines import CKR_OK
from pycryptoki.exceptions import make_error_handle_function


SHA512_DIGEST_LENGTH = 64
STC_USERNAME_BUFFER_SIZE = 128
STC_PID_BUFFER_SIZE = 4096
STC_MODULUS_BUFFER_SIZE = 2048
STC_EXPONENT_BUFFER_SIZE = 512
STC_MIN_KEY_LIFE = 0
STC_DEFAULT_KEY_LIFE = 432  # approx. 24 hours
STC_MAX_KEY_LIFE = 4000  # approx. 9 days
CRYPTO_NAME_BUFFER_SIZE = 255


def ca_stc_register(session, slot, name, access, modulus, exponent):
    """
    Register client

    :param session: session handle
    :param slot: slot id
    :param name: name of client
    :param access:
    :param modulus: client public modulus
    :param exponent: client public exponent
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_name = AutoCArray(ctype=CK_CHAR, data=name)
    c_access = CK_ULONG(access)
    c_mod = AutoCArray(ctype=CK_CHAR, data=modulus)
    c_exp = AutoCArray(ctype=CK_CHAR, data=exponent)

    ret = CA_STCRegister(
        h_session, h_slot, c_name.array, c_access, c_mod.array, len(c_mod), c_exp.array, len(c_exp)
    )
    return ret


ca_stc_register_ex = make_error_handle_function(ca_stc_register)


def ca_stc_register_v2(session, slot, name, id_type, credential):
    """
    Register client, STC2

    :param session: session handle
    :param slot: slot id
    :param name: name of client
    :param id_type: type of client id
    :param credential: X9.62 encoded uncompressed EC point
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_name = AutoCArray(ctype=CK_CHAR, data=name)
    c_id_type = CK_ULONG(id_type)
    c_id_data = AutoCArray(ctype=CK_BYTE, data=credential)
    ret = CA_STCRegisterV2(
        h_session,
        h_slot,
        c_name.array,
        c_name.size.contents,
        c_id_type,
        c_id_data.array,
        c_id_data.size.contents,
    )
    return ret


ca_stc_register_v2_ex = make_error_handle_function(ca_stc_register_v2)


def ca_stc_deregister(session, slot, name):
    """
    Deregister client

    :param session: session handle
    :param slot: slot id
    :param name: client name to deregister
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_name = create_string_buffer(b(name))
    c_name_ptr = cast(c_name, POINTER(CK_CHAR))
    ret = CA_STCDeregister(h_session, h_slot, c_name_ptr)
    return ret


ca_stc_deregister_ex = make_error_handle_function(ca_stc_deregister)


def ca_stc_get_pub_key(session, slot, name):
    """
    Get client public key

    :param session: session handle
    :param slot: slot id
    :param name: client name
    :return: modulus and exponent
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_name = AutoCArray(ctype=CK_CHAR, data=name)
    c_mod = AutoCArray(ctype=CK_CHAR)
    c_exp = AutoCArray(ctype=CK_CHAR)
    ret = CA_STCGetPubKey(
        h_session, h_slot, c_name.array, c_mod.array, c_mod.size, c_exp.array, c_exp.size
    )

    if ret != CKR_OK:
        return ret, None, None

    mod = string_at(c_mod.array, len(c_mod))
    exp = string_at(c_exp.array, len(c_exp))
    return ret, mod, exp


ca_stc_get_pub_key_ex = make_error_handle_function(ca_stc_get_pub_key)


def ca_stc_get_clients_list(session, slot):
    """
    Get list of clients

    :param session: session handle
    :param slot: slot id
    :return: list of client handles
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    client_handles = AutoCArray()

    @refresh_c_arrays(1)
    def _get_cid_list():
        """Auto sizing double call"""
        return CA_STCGetClientsList(h_session, h_slot, client_handles.array, client_handles.size)

    ret = _get_cid_list()
    return ret, list(client_handles)


ca_stc_get_clients_list_ex = make_error_handle_function(ca_stc_get_clients_list)


def ca_stc_get_client_info(session, slot, handle, access):
    """
    Get registered client name and digest

    :param session: session handle
    :param slot: slot id
    :param handle: client handle
    :param access:
    :return: client name and digest
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    h_client = CK_ULONG(handle)

    c_name = AutoCArray(ctype=CK_CHAR, size=c_ulong(STC_USERNAME_BUFFER_SIZE))
    c_access = CK_ULONG(access)
    c_mod = AutoCArray(ctype=CK_BYTE, size=c_ulong(STC_MODULUS_BUFFER_SIZE))
    c_exp = AutoCArray(ctype=CK_BYTE, size=c_ulong(STC_EXPONENT_BUFFER_SIZE))

    ret = CA_STCGetClientInfo(
        h_session,
        h_slot,
        h_client,
        c_name.array,
        c_name.size,
        byref(c_access),
        c_mod.array,
        c_mod.size,
        c_exp.array,
        c_exp.size,
    )

    if ret != CKR_OK:
        return ret, None, None

    name = string_at(c_name.array, len(c_name))
    mod = string_at(c_mod.array, len(c_mod))
    exp = string_at(c_exp.array, len(c_exp))
    return ret, name, mod, exp


ca_stc_get_client_info_ex = make_error_handle_function(ca_stc_get_client_info)


def ca_stc_get_client_info_v2(session, slot, handle, id_type):
    """
    Get registered client name and digest, STC2

    :param session: session handle
    :param slot: slot id
    :param handle: client handle
    :param id_type: client id type
    :return: client name and digest
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    h_client = CK_ULONG(handle)

    c_name = (CK_CHAR * STC_USERNAME_BUFFER_SIZE)()
    c_name_ptr = cast(c_name, POINTER(CK_CHAR))
    c_name_len = CK_ULONG(STC_USERNAME_BUFFER_SIZE)

    c_id_type = CK_ULONG(id_type)

    c_user_id = (CK_BYTE * SHA512_DIGEST_LENGTH)()
    c_user_id_ptr = cast(c_user_id, POINTER(CK_BYTE))
    c_user_id_len = CK_ULONG(SHA512_DIGEST_LENGTH)

    ret = CA_STCGetClientInfoV2(
        h_session,
        h_slot,
        h_client,
        c_name_ptr,
        byref(c_name_len),
        c_id_type,
        c_user_id_ptr,
        byref(c_user_id_len),
    )

    if ret != CKR_OK:
        return ret, None, None

    name = string_at(c_name_ptr, c_name_len.value)
    digest = string_at(c_user_id, SHA512_DIGEST_LENGTH)
    return ret, name, digest


ca_stc_get_client_info_v2_ex = make_error_handle_function(ca_stc_get_client_info_v2)


def ca_stc_get_part_pub_key(session, slot):
    """
    Get partition public key

    :param session: session handle
    :param slot: slot id
    :return: modulus and exponent
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_mod = AutoCArray(ctype=CK_CHAR)
    c_exp = AutoCArray(ctype=CK_CHAR)
    ret = CA_STCGetPartPubKey(h_session, h_slot, c_mod.array, c_mod.size, c_exp.array, c_exp.size)

    if ret != CKR_OK:
        return ret, None, None

    mod = string_at(c_mod.array, len(c_mod))
    exp = string_at(c_exp.array, len(c_exp))
    return ret, mod, exp


ca_stc_get_part_pub_key_ex = make_error_handle_function(ca_stc_get_part_pub_key)


def ca_stc_get_admin_pub_key(slot):
    """
    Get admin partition public key

    :param slot: slot id
    :return: modulus and exponent
    """
    h_slot = CK_SLOT_ID(slot)
    c_mod = AutoCArray(ctype=CK_CHAR)
    c_exp = AutoCArray(ctype=CK_CHAR)
    ret = CA_STCGetAdminPubKey(h_slot, c_mod.array, c_mod.size, c_exp.array, c_exp.size)

    if ret != CKR_OK:
        return ret, None, None

    mod = string_at(c_mod.array, len(c_mod))
    exp = string_at(c_exp.array, len(c_exp))
    return ret, mod, exp


ca_stc_get_admin_pub_key_ex = make_error_handle_function(ca_stc_get_admin_pub_key)


def ca_stc_get_pid(session, slot):
    """
    Get partition ID

    :param session: session handle
    :param slot: slot id
    :return: id type and partition id (DER encoded X509 cert)
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_type = CK_ULONG()
    c_pid = AutoCArray(ctype=CK_BYTE)

    @refresh_c_arrays(1)
    def _get_pid():
        """Auto sizing double call"""
        return CA_STCGetPID(h_session, h_slot, byref(c_type), c_pid.array, c_pid.size)

    ret = _get_pid()
    if ret != CKR_OK:
        return ret, None, None
    pid = string_at(c_pid.array, len(c_pid))
    return ret, c_type.value, pid


ca_stc_get_pid_ex = make_error_handle_function(ca_stc_get_pid)


def ca_stc_get_admin_pid(slot):
    """
    Get admin partition ID. Admin partition must be uninitialized.

    :param slot: slot id
    :return: id type and admin partition id
    """
    h_slot = CK_SLOT_ID(slot)
    c_type = CK_ULONG()
    c_pid = AutoCArray(ctype=CK_BYTE)

    @refresh_c_arrays(1)
    def _get_pid():
        """Auto sizing double call"""
        return CA_STCGetAdminPID(h_slot, byref(c_type), c_pid.array, c_pid.size)

    ret = _get_pid()
    if ret != CKR_OK:
        return ret, None, None
    pid = string_at(c_pid.array, len(c_pid))
    return ret, c_type.value, pid


ca_stc_get_admin_pid_ex = make_error_handle_function(ca_stc_get_admin_pid)


def ca_stc_set_cipher_algorithm(session, slot, cipher_id):
    """
    Enable cipher algorithm on partition

    :param session: session handle
    :param slot: slot id
    :param cipher_id: cipher id
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_cipher_id = CK_ULONG(cipher_id)
    ret = CA_STCSetCipherAlgorithm(h_session, h_slot, c_cipher_id)
    return ret


ca_stc_set_cipher_algorithm_ex = make_error_handle_function(ca_stc_set_cipher_algorithm)


def ca_stc_get_cipher_algorithm(session, slot):
    """
    Get cipher IDs enabled on the partition

    :param session: session handle
    :param slot: slot id
    :return: list of cipher ids
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_cipher_ids_len = CK_BYTE()
    ret = CA_STCGetCipherAlgorithm(h_session, h_slot, byref(c_cipher_ids_len), None)
    if ret != CKR_OK:
        return ret, None
    c_cipher_ids = (CK_ULONG * c_cipher_ids_len.value)()
    c_cipher_ids_ptr = cast(c_cipher_ids, POINTER(CK_ULONG))
    ret = CA_STCGetCipherAlgorithm(h_session, h_slot, byref(c_cipher_ids_len), c_cipher_ids_ptr)
    if ret != CKR_OK:
        return ret, None
    return ret, list(c_cipher_ids)


ca_stc_get_cipher_algorithm_ex = make_error_handle_function(ca_stc_get_cipher_algorithm)


def ca_stc_clear_cipher_algorithm(session, slot, cipher_id):
    """
    Disable the specified cipher algorithm on the target slot

    :param session: session handle
    :param slot: slot id
    :param cipher_id: cipher id
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_cipher_id = CK_ULONG(cipher_id)
    ret = CA_STCClearCipherAlgorithm(h_session, h_slot, c_cipher_id)
    return ret


ca_stc_clear_cipher_algorithm_ex = make_error_handle_function(ca_stc_clear_cipher_algorithm)


def ca_stc_set_digest_algorithm(session, slot, digest_id):
    """
    Enable digest algorithm

    :param session: session handle
    :param slot: slot id
    :param digest_id: digest id
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_digest_id = CK_ULONG(digest_id)
    ret = CA_STCSetDigestAlgorithm(h_session, h_slot, c_digest_id)
    return ret


ca_stc_set_digest_algorithm_ex = make_error_handle_function(ca_stc_set_digest_algorithm)


def ca_stc_get_digest_algorithm(session, slot):
    """
    Get digest algorithms enabled on the partition

    :param session: session handle
    :param slot: slot id
    :return: list of digest ids
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_digest_ids_len = CK_BYTE()
    ret = CA_STCGetDigestAlgorithm(h_session, h_slot, byref(c_digest_ids_len), None)
    if ret != CKR_OK:
        return ret, None
    c_digest_ids = (CK_ULONG * c_digest_ids_len.value)()
    c_digest_ids_ptr = cast(c_digest_ids, POINTER(CK_ULONG))
    ret = CA_STCGetDigestAlgorithm(h_session, h_slot, byref(c_digest_ids_len), c_digest_ids_ptr)
    if ret != CKR_OK:
        return ret, None
    return ret, list(c_digest_ids)


ca_stc_get_digest_algorithm_ex = make_error_handle_function(ca_stc_get_digest_algorithm)


def ca_stc_clear_digest_algorithm(session, slot, digest_id):
    """
    Disable digest algorithm on partition

    :param session: session handle
    :param slot: slot id
    :param digest_id: digest id
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_digest_id = CK_ULONG(digest_id)
    ret = CA_STCClearDigestAlgorithm(h_session, h_slot, c_digest_id)
    return ret


ca_stc_clear_digest_algorithm_ex = make_error_handle_function(ca_stc_clear_digest_algorithm)


def ca_stc_set_key_life_time(session, slot, life_time):
    """
    Set key lifetime. Mininum 0, maximum 4000 million messages.

    :param session: session handle
    :param slot: slot id
    :param life_time: key lifetime in millions of messages
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_life_time = CK_ULONG(life_time)
    ret = CA_STCSetKeyLifeTime(h_session, h_slot, c_life_time)
    return ret


ca_stc_set_key_life_time_ex = make_error_handle_function(ca_stc_set_key_life_time)


def ca_stc_get_key_life_time(session, slot):
    """
    Get key lifetime

    :param session: session handle
    :param slot: slot id
    :return: key lifetime in millions of messages
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_life_time = CK_ULONG()
    ret = CA_STCGetKeyLifeTime(h_session, h_slot, byref(c_life_time))
    if ret != CKR_OK:
        return ret, None
    return ret, c_life_time.value


ca_stc_get_key_life_time_ex = make_error_handle_function(ca_stc_get_key_life_time)


def ca_stc_set_key_activation_time_out(session, slot, time_out):
    """
    Set timeout between channel open and activation

    :param session: session handle
    :param slot: slot id
    :param time_out:
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_time_out = CK_ULONG(time_out)
    ret = CA_STCSetKeyActivationTimeOut(h_session, h_slot, c_time_out)
    return ret


ca_stc_set_key_activation_time_out_ex = make_error_handle_function(
    ca_stc_set_key_activation_time_out
)


def ca_stc_get_key_activation_time_out(session, slot):
    """
    Get timeout between channel open and activation

    :param session: session handle
    :param slot: slot id
    :return: activation timeout in seconds
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_time_out = CK_ULONG()
    ret = CA_STCGetKeyActivationTimeOut(h_session, h_slot, byref(c_time_out))
    if ret != CKR_OK:
        return ret, None
    return ret, c_time_out.value


ca_stc_get_key_activation_time_out_ex = make_error_handle_function(
    ca_stc_get_key_activation_time_out
)


def ca_stc_set_max_sessions(session, slot, max_sessions):
    """
    Set maximum number of STC sessions allowed

    :param session: session handle
    :param slot: slot id
    :param max_sessions:
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_max_sessions = CK_ULONG(max_sessions)
    ret = CA_STCSetMaxSessions(h_session, h_slot, c_max_sessions)
    return ret


ca_stc_set_max_sessions_ex = make_error_handle_function(ca_stc_set_max_sessions)


def ca_stc_get_max_sessions(session, slot):
    """
    Get maximum number of STC sessions allowed

    :param session: session handle
    :param slot: slot id
    :return: max sessions number
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_max_sessions = CK_ULONG()
    ret = CA_STCGetMaxSessions(h_session, h_slot, byref(c_max_sessions))
    if ret != CKR_OK:
        return ret, None
    return ret, c_max_sessions.value


ca_stc_get_max_sessions_ex = make_error_handle_function(ca_stc_get_max_sessions)


def ca_stc_set_sequence_window_size(session, slot, window_size):
    """
    Set the size of the replay window

    :param session: session handle
    :param slot: slot id
    :param window_size:
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_window_size = CK_ULONG(window_size)
    ret = CA_STCSetSequenceWindowSize(h_session, h_slot, c_window_size)
    return ret


ca_stc_set_sequence_window_size_ex = make_error_handle_function(ca_stc_set_sequence_window_size)


def ca_stc_get_sequence_window_size(session, slot):
    """
    Get the size of the replay window

    :param session: session handle
    :param slot: slot id
    :return: sequence window size
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_window_size = CK_ULONG()
    ret = CA_STCGetSequenceWindowSize(h_session, h_slot, byref(c_window_size))
    if ret != CKR_OK:
        return ret, None
    return ret, c_window_size.value


ca_stc_get_sequence_window_size_ex = make_error_handle_function(ca_stc_get_sequence_window_size)


def ca_stc_is_enabled(slot):
    """
    Get whether STC is enabled on the partition and client

    :param slot: slot id
    :return: whether STC is enabled
    """
    h_slot = CK_SLOT_ID(slot)
    c_enabled = CK_BYTE()
    ret = CA_STCIsEnabled(h_slot, byref(c_enabled))
    if ret != CKR_OK:
        return ret, None
    return ret, bool(c_enabled.value)


ca_stc_is_enabled_ex = make_error_handle_function(ca_stc_is_enabled)


def ca_stc_get_state(slot):
    """
    Get STC connection state with specified slot

    :param slot: slot id
    :return: state string
    """
    h_slot = CK_SLOT_ID(slot)
    c_buffer_len = CK_BYTE(CRYPTO_NAME_BUFFER_SIZE)
    c_state_string = (CK_CHAR * CRYPTO_NAME_BUFFER_SIZE)()
    c_state_string_ptr = cast(c_state_string, POINTER(CK_CHAR))
    ret = CA_STCGetState(h_slot, c_state_string_ptr, c_buffer_len)
    if ret != CKR_OK:
        return ret, None
    return ret, string_at(c_state_string_ptr)


ca_stc_get_state_ex = make_error_handle_function(ca_stc_get_state)


def ca_stc_get_channel_id(slot):
    """
    Get current channel ID

    :param slot: slot id
    :return: channel id number
    """
    h_slot = CK_SLOT_ID(slot)
    c_channel_id = CK_ULONG()
    ret = CA_STCGetChannelID(h_slot, byref(c_channel_id))
    if ret != CKR_OK:
        return ret, None
    return ret, c_channel_id.value


ca_stc_get_channel_id_ex = make_error_handle_function(ca_stc_get_channel_id)


def ca_stc_get_cipher_id(slot):
    """
    Get ID of cipher currently in use with current slot

    :param slot: slot id
    :return: cipher id
    """
    h_slot = CK_SLOT_ID(slot)
    c_cipher_id = CK_ULONG()
    ret = CA_STCGetCipherID(h_slot, byref(c_cipher_id))
    if ret != CKR_OK:
        return ret, None
    return ret, c_cipher_id.value


ca_stc_get_cipher_id_ex = make_error_handle_function(ca_stc_get_cipher_id)


def ca_stc_get_digest_id(slot):
    """
    Get ID of message digest currently in use

    :param slot: slot id
    :return: digest id
    """
    h_slot = CK_SLOT_ID(slot)
    c_digest_id = CK_ULONG()
    ret = CA_STCGetDigestID(h_slot, byref(c_digest_id))
    if ret != CKR_OK:
        return ret, None
    return ret, c_digest_id.value


ca_stc_get_digest_id_ex = make_error_handle_function(ca_stc_get_digest_id)


def ca_stc_get_current_key_life(session, slot):
    """
    Get current key lifetime; count of remaining uses of the key

    :param session: session handle
    :param slot: slot id
    :return: remaining lifetime count
    """
    h_session = CK_SESSION_HANDLE(session)
    h_slot = CK_SLOT_ID(slot)
    c_key_life = CK_ULONG()
    ret = CA_STCGetCurrentKeyLife(h_session, h_slot, byref(c_key_life))
    if ret != CKR_OK:
        return ret, None
    return ret, c_key_life.value


ca_stc_get_current_key_life_ex = make_error_handle_function(ca_stc_get_current_key_life)


def ca_stc_get_cipher_ids(slot):
    """
    Get list of cipher IDs supported by the client

    :param slot: slot id
    :return: cipher ids
    """
    h_slot = CK_SLOT_ID(slot)
    c_cipher_ids_len = CK_BYTE()
    ret = CA_STCGetCipherIDs(h_slot, None, byref(c_cipher_ids_len))
    if ret != CKR_OK:
        return ret, None
    c_cipher_ids = (CK_ULONG * c_cipher_ids_len.value)()
    c_cipher_ids_ptr = cast(c_cipher_ids, POINTER(CK_ULONG))
    ret = CA_STCGetCipherIDs(h_slot, c_cipher_ids_ptr, byref(c_cipher_ids_len))
    if ret != CKR_OK:
        return ret, None
    return ret, list(c_cipher_ids)


ca_stc_get_cipher_ids_ex = make_error_handle_function(ca_stc_get_cipher_ids)


def ca_stc_get_cipher_name_by_id(slot, cipher_id):
    """
    Get name of cipher by its ID

    :param slot: slot id
    :param cipher_id: cipher id
    :return: cipher name
    """
    h_slot = CK_SLOT_ID(slot)
    c_cipher_id = CK_ULONG(cipher_id)
    c_name_len = CK_BYTE(CRYPTO_NAME_BUFFER_SIZE)
    c_name = (CK_CHAR * CRYPTO_NAME_BUFFER_SIZE)()
    c_name_ptr = cast(c_name, POINTER(CK_CHAR))
    ret = CA_STCGetCipherNameByID(h_slot, c_cipher_id, c_name_ptr, c_name_len)
    if ret != CKR_OK:
        return ret, None
    return ret, string_at(c_name_ptr)


ca_stc_get_cipher_name_by_id_ex = make_error_handle_function(ca_stc_get_cipher_name_by_id)


def ca_stc_get_digest_ids(slot):
    """
    Get list of digest IDs supported by the client

    :param slot: slot id
    :return: digest ids
    """
    h_slot = CK_SLOT_ID(slot)
    c_digest_ids_len = CK_BYTE()
    ret = CA_STCGetDigestIDs(h_slot, None, byref(c_digest_ids_len))
    if ret != CKR_OK:
        return ret, None
    c_digest_ids = (CK_ULONG * c_digest_ids_len.value)()
    c_digest_ids_ptr = cast(c_digest_ids, POINTER(CK_ULONG))
    ret = CA_STCGetDigestIDs(h_slot, c_digest_ids_ptr, byref(c_digest_ids_len))
    if ret != CKR_OK:
        return ret, None
    return ret, list(c_digest_ids)


ca_stc_get_digest_ids_ex = make_error_handle_function(ca_stc_get_digest_ids)


def ca_stc_get_digest_name_by_id(slot, digest_id):
    """
    Get name of digest by its ID

    :param slot: slot id
    :param digest_id: digest id
    :return: digest name
    """
    h_slot = CK_SLOT_ID(slot)
    c_digest_id = CK_ULONG(digest_id)
    c_name_len = CK_BYTE(CRYPTO_NAME_BUFFER_SIZE)
    c_name = (CK_CHAR * CRYPTO_NAME_BUFFER_SIZE)()
    c_name_ptr = cast(c_name, POINTER(CK_CHAR))
    ret = CA_STCGetDigestNameByID(h_slot, c_digest_id, c_name_ptr, c_name_len)
    if ret != CKR_OK:
        return ret, None
    return ret, string_at(c_name_ptr)


ca_stc_get_digest_name_by_id_ex = make_error_handle_function(ca_stc_get_digest_name_by_id)
