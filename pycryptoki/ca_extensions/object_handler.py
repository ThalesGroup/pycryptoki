"""
Module to work with objects, specifically dealing with ca_extension functions
"""

import logging
from ctypes import byref, cast, c_ubyte
from _ctypes import POINTER

from pycryptoki.attributes import to_byte_array
from pycryptoki.ca_extensions.session import ca_get_session_info_ex
from pycryptoki.cryptoki import CK_ULONG, CK_SLOT_ID, CA_GetObjectHandle, CA_DestroyMultipleObjects
from pycryptoki.defines import CKR_OK
from pycryptoki.exceptions import make_error_handle_function
from pycryptoki.common_utils import AutoCArray


LOG = logging.getLogger(__name__)


def ca_get_object_handle(slot, session, objectouid):
    """
    Calls CA_GetObjectHandle to get the object handle from OUID

    :param slot: partition slot number
    :param session: session id that was opened to run the function
    :param objectouid: OUID, a string of the hex value that maps to object handle
    :return: a tuple containing the return code and the object handle mapping the given OUID
    """
    objecttype = CK_ULONG()
    objecthandle = CK_ULONG()
    # ulContainerNumber is required which is of type CK_ULONG
    container_number = ca_get_session_info_ex(session)['containerNumber']
    ouid, size_ouid = to_byte_array(int(objectouid, 16))
    c_ouid = cast(ouid, POINTER(c_ubyte))

    ret = CA_GetObjectHandle(CK_SLOT_ID(slot),
                             container_number,
                             c_ouid,
                             byref(objecttype),
                             byref(objecthandle))
    if ret != CKR_OK:
        return ret, None

    return ret, objecthandle.value


ca_get_object_handle_ex = make_error_handle_function(ca_get_object_handle)


def ca_destroy_multiple_objects(h_session, objects):
    """Delete multiple objects corresponding to given object handles

    :param int h_session: Session handle
    :param list objects: The handles of the objects to delete
    :returns: Return code
    """
    handles_count = len(objects)
    handles = AutoCArray(data=objects, ctype=CK_ULONG)
    ret = CA_DestroyMultipleObjects(h_session, handles_count, handles.array, byref(CK_ULONG()))
    return ret


ca_destroy_multiple_objects_ex = make_error_handle_function(ca_destroy_multiple_objects)
