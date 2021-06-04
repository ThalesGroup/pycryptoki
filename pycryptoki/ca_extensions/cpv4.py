"""
cpv4 ca extensions
"""
import logging
from collections import namedtuple
from copy import deepcopy
from ctypes import c_uint32, byref, create_string_buffer, c_ubyte, pointer, c_uint, cast, string_at
from _ctypes import POINTER

from pycryptoki.conversions import from_bytestring
from pycryptoki.defines import CKR_OK
from pycryptoki.cryptoki import (
    CA_MigrateKeys,
    CA_MigrationStartSessionNegotiation,
    CA_MigrationContinueSessionNegotiation,
    CA_MigrationCloseSession,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_SESSION_HANDLE,
    CK_OBJECT_MIGRATION_DATA,
)

from pycryptoki.attributes import to_byte_array

from pycryptoki.exceptions import make_error_handle_function


LOG = logging.getLogger(__name__)
MIGRATION_KEYS = ["object_type", "source_handle"]
MIGRATION_DATA = namedtuple("MIGRATION_DATA", deepcopy(MIGRATION_KEYS))
PCPROT_MAX_BUFFER_SIZE = 64000


def get_mig_data_c_struct(mig_data_list):
    """
    Build an array of :class:`~pycryptoki.cryptoki.CK_OBJECT_MIGRATION_DATA` Structs & return it.

    :return: :class:`~pycryptoki.cryptoki.CK_OBJECT_MIGRATION_DATA` array
    """
    ret_struct = (CK_OBJECT_MIGRATION_DATA * len(mig_data_list))()
    for index, mig_data in enumerate(mig_data_list):
        object_type, source_handle = mig_data
        ret_struct[index] = CK_OBJECT_MIGRATION_DATA(
            objectType=object_type, sourceHandle=source_handle
        )
    return ret_struct


def ca_migrate_keys(
    source_session, target_session, migration_flags, num_objects, objects_to_migrate
):
    """
    Runs CA_MigrateKeys command

    :param objects_to_migrate: a list of tuples (objectType, sourceHandle) or list of MIGRATION_DATA
    """
    objects_to_migrate = (
        objects_to_migrate if isinstance(objects_to_migrate, list) else [objects_to_migrate]
    )
    c_mig_data = get_mig_data_c_struct(objects_to_migrate)

    ret = CA_MigrateKeys(source_session, target_session, migration_flags, num_objects, c_mig_data)

    return ret, [(data.rv, data.targetHandle) for data in c_mig_data]


ca_migrate_keys_ex = make_error_handle_function(ca_migrate_keys)


def ca_migration_start_session_negotiation(target_session, input_data=None):
    """
    Runs CA_MigrationStartSessionNegotiation command

    :param target_session: target slot session
    :param step: Output step of the protocol, this can be used as input as well,
                 but hey early stages of development and design!
    """
    output_data = (c_ubyte * PCPROT_MAX_BUFFER_SIZE)()
    output_data_len = CK_ULONG(PCPROT_MAX_BUFFER_SIZE)
    out_step = CK_ULONG()

    if input_data is None:
        input_data_len = 0
    else:
        input_data, input_data_len = to_byte_array(from_bytestring(input_data))
        input_data = cast(input_data, POINTER(c_ubyte))

    ret = CA_MigrationStartSessionNegotiation(
        target_session,
        input_data_len,
        input_data,
        byref(out_step),
        byref(output_data_len),
        output_data,
    )

    if ret != CKR_OK:
        return ret, {}

    return ret, {"output": string_at(output_data, output_data_len.value), "step": out_step.value}


ca_migration_start_session_negotiation_ex = make_error_handle_function(
    ca_migration_start_session_negotiation
)


def ca_migration_continue_session_negotiation(
    target_session, input_step, input_data, session_ouid=None
):
    """
    Runs CA_MigrationContinueSessionNegotiation
    """
    output_step = CK_ULONG()
    output_data = (c_ubyte * PCPROT_MAX_BUFFER_SIZE)()
    output_data_len = CK_ULONG(PCPROT_MAX_BUFFER_SIZE)
    status = CK_ULONG()

    if session_ouid is None:
        session_ouid = (c_ubyte * PCPROT_MAX_BUFFER_SIZE)()
        session_ouid_len = CK_ULONG(PCPROT_MAX_BUFFER_SIZE)
    else:
        session_ouid, session_ouid_len = to_byte_array(from_bytestring(session_ouid))
        session_ouid = cast(session_ouid, POINTER(c_ubyte))

    input_data, input_len = to_byte_array(from_bytestring(input_data))
    input_data = cast(input_data, POINTER(c_ubyte))

    ret = CA_MigrationContinueSessionNegotiation(
        target_session,
        input_step,
        input_len,
        input_data,
        byref(output_step),
        byref(output_data_len),
        output_data,
        byref(status),
        byref(session_ouid_len),
        session_ouid,
    )
    if ret != CKR_OK:
        return ret, {}

    return (
        ret,
        {
            "output": string_at(output_data, output_data_len.value),
            "step": output_step.value,
            "status": status.value,
            "session_ouid": string_at(session_ouid, session_ouid_len.value),
        },
    )


ca_migration_continue_session_negotiation_ex = make_error_handle_function(
    ca_migration_continue_session_negotiation
)


def ca_migration_close_session(target_session, session_ouid):
    """
    Runs CA_MigrationCloseSession
    """
    session_ouid, session_ouid_len = to_byte_array(from_bytestring(session_ouid))
    session_ouid = cast(session_ouid, POINTER(c_ubyte))

    return CA_MigrationCloseSession(target_session, session_ouid_len, session_ouid)


ca_migration_close_session_ex = make_error_handle_function(ca_migration_close_session)
