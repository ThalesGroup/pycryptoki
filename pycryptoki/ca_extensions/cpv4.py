"""
cpv4 ca extensions
"""
import logging
from collections import namedtuple
from copy import deepcopy

from pycryptoki.defines import CKR_OK
from pycryptoki.cryptoki import (
    CA_MigrateKeys,
    CK_ULONG,
    CK_SESSION_HANDLE,
    CK_OBJECT_MIGRATION_DATA,
)
from pycryptoki.exceptions import make_error_handle_function


LOG = logging.getLogger(__name__)
MIGRATION_KEYS = ["object_type", "source_handle"]
MIGRATION_DATA = namedtuple("MIGRATION_DATA", deepcopy(MIGRATION_KEYS))


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

    if ret != CKR_OK:
        return ret, None

    return ret, [(data.rv, data.targetHandle) for data in c_mig_data]


ca_migrate_keys_ex = make_error_handle_function(ca_migrate_keys)
