"""
Module to work with PKA / Per key authorization
"""
from ctypes import cast
from _ctypes import POINTER
from pycryptoki.attributes import to_byte_array
from pycryptoki.cryptoki import (
    CA_SetAuthorizationData,
    CA_ResetAuthorizationData,
    CA_AuthorizeKey,
    CA_AssignKey,
    CA_IncrementFailedAuthCount,
)
from pycryptoki.cryptoki import CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_UTF8CHAR
from pycryptoki.exceptions import make_error_handle_function


def ca_set_authorization_data(h_session, h_object, old_auth_data, new_auth_data):
    """
    User changes authorization data on key object (private, secret)

    :param h_session: session handle
    :param object: key handle to update
    :param old_auth_data: byte list, e.g. [11, 12, 13, ..]
    :param new_auth_data: byte list, e.g. [11, 12, 13, ..]
    :return: Ret code
    """
    old_auth_data_ptr, old_auth_data_length = to_byte_array(old_auth_data)
    old_auth_data_ptr = cast(old_auth_data_ptr, POINTER(CK_UTF8CHAR))

    new_auth_data_ptr, new_auth_data_length = to_byte_array(new_auth_data)
    new_auth_data_ptr = cast(new_auth_data_ptr, POINTER(CK_UTF8CHAR))

    h_object = CK_OBJECT_HANDLE(h_object)
    h_session = CK_SESSION_HANDLE(h_session)

    return CA_SetAuthorizationData(
        h_session,
        h_object,
        old_auth_data_ptr,
        old_auth_data_length,
        new_auth_data_ptr,
        new_auth_data_length,
    )


ca_set_authorization_data_ex = make_error_handle_function(ca_set_authorization_data)


def ca_reset_authorization_data(h_session, h_object, auth_data):
    """
    CO resets auth data on unassigned key

    :param h_session: session handle
    :param object: key handle to update
    :param auth_data: byte list, e.g. [11, 12, 13, ..]
    :return: Ret code
    """
    auth_data_ptr, auth_data_length = to_byte_array(auth_data)
    auth_data_ptr = cast(auth_data_ptr, POINTER(CK_UTF8CHAR))

    h_object = CK_OBJECT_HANDLE(h_object)
    h_session = CK_SESSION_HANDLE(h_session)

    return CA_ResetAuthorizationData(h_session, h_object, auth_data_ptr, auth_data_length)


ca_reset_authorization_data_ex = make_error_handle_function(ca_reset_authorization_data)


def ca_increment_failed_auth_count(h_session, h_object):
    """
    This function is called by HA group when auth failure happens on a key
    to sync up status. Here its defined mostly for testing purposes
    :param h_session: session handle
    :param object: key handle to update
    :return: Ret code
    """
    h_object = CK_OBJECT_HANDLE(h_object)
    h_session = CK_SESSION_HANDLE(h_session)

    return CA_IncrementFailedAuthCount(h_session, h_object)


ca_increment_failed_auth_count_ex = make_error_handle_function(ca_increment_failed_auth_count)


def ca_authorize_key(h_session, h_object, auth_data):
    """
    User authorizes key within session or access for use

    :param h_session: session handle
    :param object: key handle to authorize
    :param auth_data: authorization byte list, e.g. [11, 12, 13, ..]
    :return: Ret code
    """
    auth_data_ptr, auth_data_length = to_byte_array(auth_data)
    auth_data_ptr = cast(auth_data_ptr, POINTER(CK_UTF8CHAR))

    h_object = CK_OBJECT_HANDLE(h_object)
    h_session = CK_SESSION_HANDLE(h_session)

    return CA_AuthorizeKey(h_session, h_object, auth_data_ptr, auth_data_length)


ca_authorize_key_ex = make_error_handle_function(ca_authorize_key)


def ca_assign_key(h_session, h_object):
    """
    Crypto Officer assigns a key

    :param h_session: session handle
    :param object: key handle to assign
    :return: Ret code
    """

    h_object = CK_OBJECT_HANDLE(h_object)
    h_session = CK_SESSION_HANDLE(h_session)

    return CA_AssignKey(h_session, h_object)


ca_assign_key_ex = make_error_handle_function(ca_assign_key)
