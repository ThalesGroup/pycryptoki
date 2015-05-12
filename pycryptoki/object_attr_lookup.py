from ctypes import byref, sizeof
from pycryptoki.attributes import Attributes, c_struct_to_python
from pycryptoki.cryptoki import CK_OBJECT_HANDLE, C_FindObjectsInit, CK_ULONG, \
    C_FindObjects, C_FindObjectsFinal, C_GetAttributeValue, C_SetAttributeValue
from pycryptoki.defines import CKR_OK, CKA_CLASS, CKA_LABEL, CKA_VALUE
from pycryptoki.test_functions import LunaException, make_error_handle_function

def c_find_objects(h_session, objects_find, template_attributes, num_entries):
    '''
    Calls c_find_objects and c_find_objects_init to get a python dictionary 
    of the objects found.
    
    @param h_session: The current session
    @param objects_find: A python dictionary of the object template to look for
    @param template_attributes: A python dictionary of the attributes to look for
    @param num_entries: The number of entries to return
    
    @return: Returns a python dictionary of the templates of the objects found
    '''
    attributes = []
    struct = Attributes(objects_find).get_c_struct()
    ret = C_FindObjectsInit(h_session, struct, CK_ULONG(len(objects_find)))
    if ret != CKR_OK: return ret, -1, None;
    
    h_ary = (CK_OBJECT_HANDLE * num_entries)()
    us_total = CK_ULONG(num_entries)
    ret = C_FindObjects(h_session, h_ary, CK_ULONG(num_entries), byref(us_total))
    if ret != CKR_OK: return ret, -1, None;

    #todo get attribute value for all of them
    for i in range(0, us_total.value):
        attribute = c_get_attribute_value_ex(h_session, h_ary[i], template_attributes)
        attributes.append(attribute)
    

    ret = C_FindObjectsFinal(h_session)

    return ret, h_ary[0], attributes
c_find_objects_ex = make_error_handle_function(c_find_objects)  

def c_get_attribute_value(h_session, h_object, template):
    '''
    Calls C_GetAttrributeValue to get an attribute value based on a python template
    @param h_session: The current session
    @param h_object: The handle of the object to get attributes for
    @param template: A python dictionary representing the template of the attributes to be retrieved
    
    @return: A python dictionary representing the attributes returned from the HSM/library
    '''
    c_struct = Attributes(template).get_c_struct()
    ret = C_GetAttributeValue(h_session, h_object, c_struct, CK_ULONG(len(template)))
    if ret != CKR_OK: return ret;
    
    return ret, c_struct_to_python(c_struct)
c_get_attribute_value_ex = make_error_handle_function(c_get_attribute_value)  

def c_set_attribute_value(h_session, h_object, template):
    '''
    Calls C_SetAttributeValue to set an attribute value based on a python template
    @param h_session: The current session
    @param h_object: The handle of the object to get attributes for
    @param template: A python dictionary representing the template of the attributes to be written
    
    @return: A python dictionary representing the attributes returned from the HSM/library
    '''
    c_struct = Attributes(template).get_c_struct()
    ret = C_SetAttributeValue(h_session, h_object, c_struct, CK_ULONG(len(template)))
    if ret != CKR_OK: return ret;
    
    return ret, c_struct_to_python(c_struct)
c_set_attribute_value_ex = make_error_handle_function(c_set_attribute_value)
