"""
Functions for dealing with object attributes
"""
import logging
from ctypes import byref, cast, c_void_p

from .attributes import Attributes, c_struct_to_python, KEY_TRANSFORMS
from .cryptoki import CK_OBJECT_HANDLE, C_FindObjectsInit, CK_ULONG, \
    C_FindObjects, C_FindObjectsFinal, C_GetAttributeValue, C_SetAttributeValue
from .defines import CKR_OK
from .exceptions import make_error_handle_function

LOG = logging.getLogger(__name__)


def c_find_objects(h_session, template, num_entries):
    """Calls c_find_objects and c_find_objects_init to get a python dictionary
    of the objects found.

    :param int h_session: Session handle
    :param template: A python dictionary of the object template to look for
    :param num_entries: The max number of entries to return
    :returns: Returns a list of handles of objects found

    """
    struct = Attributes(template).get_c_struct()
    ret = C_FindObjectsInit(h_session, struct, CK_ULONG(len(template)))
    if ret != CKR_OK:
        return ret, None

    h_ary = (CK_OBJECT_HANDLE * num_entries)()
    us_total = CK_ULONG(num_entries)
    ret = C_FindObjects(h_session, h_ary, CK_ULONG(num_entries), byref(us_total))
    if ret != CKR_OK:
        return ret, None

    ret = C_FindObjectsFinal(h_session)

    return ret, [h_ary[i] for i in range(us_total.value)]


c_find_objects_ex = make_error_handle_function(c_find_objects)


def c_get_attribute_value(h_session, h_object, template):
    """Calls C_GetAttrributeValue to get an attribute value based on a python template

    :param int h_session: Session handle
    :param h_object: The handle of the object to get attributes for
    :param template: A python dictionary representing the template of the attributes to be retrieved
    :returns: A python dictionary representing the attributes returned from the HSM/library

    """
    c_struct = Attributes(template).get_c_struct()
    unknown_key_vals = [key for key, value in template.items() if value is None]
    if unknown_key_vals:
        LOG.debug("Retrieving Attribute Length for keys %s", unknown_key_vals)
        # We need to get the size of the target memory area first, then
        # we can allocate the mem size.
        ret = C_GetAttributeValue(h_session, h_object, c_struct, CK_ULONG(len(template)))
        if ret != CKR_OK:
            return ret, None

        for index in range(0, len(c_struct)):
            key_type = c_struct[index].type
            if any(key_type == unknown_key_type for unknown_key_type in unknown_key_vals):
                # Allocate memory for the type.
                c_obj_type = KEY_TRANSFORMS[key_type].ctype
                mem = (c_obj_type * c_struct[index].usValueLen)()
                c_struct[index].pValue = cast(mem, c_void_p)

    ret = C_GetAttributeValue(h_session, h_object, c_struct, CK_ULONG(len(template)))
    if ret != CKR_OK:
        return ret, None

    return ret, c_struct_to_python(c_struct)


c_get_attribute_value_ex = make_error_handle_function(c_get_attribute_value)


def c_set_attribute_value(h_session, h_object, template):
    """Calls C_SetAttributeValue to set an attribute value based on a python template

    :param int h_session: Session handle
    :param h_object: The handle of the object to get attributes for
    :param template: A python dictionary representing the template of the attributes to be written
    :returns: A python dictionary representing the attributes returned from the HSM/library

    """
    c_struct = Attributes(template).get_c_struct()
    ret = C_SetAttributeValue(h_session, h_object, c_struct, CK_ULONG(len(template)))
    return ret


c_set_attribute_value_ex = make_error_handle_function(c_set_attribute_value)

