"""
This module contains a wrapper around the key attributes and the template struct
generation to make it possible to create templates in python and easily
convert them into templates in C.
"""
from ctypes import cast, c_void_p, create_string_buffer, c_bool, c_char_p, \
    c_ulong, pointer, POINTER, byref, sizeof, c_int, c_ubyte

from cryptoki import CK_ATTRIBUTE, CK_BBOOL, CK_ATTRIBUTE_TYPE, CK_ULONG, \
    CK_BYTE, C_GetAttributeValue, CK_OBJECT_HANDLE, CK_DATE, CK_CHAR, CK_CHAR_PTR
from defines import CKA_USAGE_LIMIT, CKA_USAGE_COUNT, CKA_CLASS, CKA_TOKEN, \
    CKA_PRIVATE, CKA_LABEL, CKA_APPLICATION, CKA_VALUE, CKA_CERTIFICATE_TYPE, \
    CKA_ISSUER, CKA_SERIAL_NUMBER, CKA_KEY_TYPE, CKA_SUBJECT, CKA_ID, CKA_SENSITIVE, \
    CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP, CKA_SIGN, CKA_SIGN_RECOVER, \
    CKA_VERIFY, CKA_VERIFY_RECOVER, CKA_DERIVE, CKA_START_DATE, CKA_END_DATE, \
    CKA_MODULUS, CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT, CKA_PRIVATE_EXPONENT, \
    CKA_PRIME_1, CKA_PRIME_2, CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_COEFFICIENT, \
    CKA_PRIME, CKA_SUBPRIME, CKA_BASE, CKA_PRIME_BITS, CKA_SUBPRIME_BITS, \
    CKA_VALUE_BITS, CKA_VALUE_LEN, CKA_ECDSA_PARAMS, CKA_EC_POINT, CKA_LOCAL, \
    CKA_MODIFIABLE, CKA_EXTRACTABLE, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, \
    CKA_CCM_PRIVATE, CKA_FINGERPRINT_SHA1, CKA_FINGERPRINT_SHA256, CKA_PKC_TCTRUST, CKA_PKC_CITS, \
    CKA_OUID, CKA_UNWRAP_TEMPLATE, CKA_DERIVE_TEMPLATE, \
    CKA_X9_31_GENERATED, CKA_PKC_ECC, CKR_OK
from pycryptoki.cryptoki import CK_ULONG_PTR
from pycryptoki.defines import CKA_EKM_UID, CKA_GENERIC_1, CKA_GENERIC_2, \
    CKA_GENERIC_3
from pycryptoki.dictionary_handling import CDict

'''
List class for handling attributes with lists of a certain type
'''


class CList:
    """ """
    list_type = None

    def __init__(self, list_type):
        self.list_type = list_type


class NonAsciiString:
    """ """
    data = None

    def __init__(self, data):
        self.data = data


def get_byte_list_from_python_list(python_byte_list):
    """Helper method to create a C style byte list from a python
    style list of integers.

    :param python_byte_list: A list of integers to convert to a C style list of integers
    :returns: The pointer to the C representation of the python byte list

    """
    list_val = create_string_buffer("", len(python_byte_list))
    ptr = cast(pointer(list_val), c_void_p)
    for j in range(0, len(python_byte_list)):
        list_val[j] = chr(python_byte_list[j])
        return ptr


date_attrb = {'year': str,
              'month': str,
              'day': str}

'''
A mapping of attributes to what type they have. This is used when converting
a python dictionary to a C struct or vice versa
'''
key_attributes = {CKA_USAGE_LIMIT: long,
                  CKA_USAGE_COUNT: long,
                  CKA_CLASS: long,
                  CKA_TOKEN: bool,
                  CKA_PRIVATE: bool,
                  CKA_LABEL: str,
                  CKA_APPLICATION: None,
                  CKA_VALUE: CList(str),
                  CKA_CERTIFICATE_TYPE: long,  # TODO guessing
                  CKA_ISSUER: None,
                  CKA_SERIAL_NUMBER: None,
                  CKA_KEY_TYPE: long,
                  CKA_SUBJECT: str,
                  CKA_ID: None,
                  CKA_SENSITIVE: bool,
                  CKA_ENCRYPT: bool,
                  CKA_DECRYPT: bool,
                  CKA_WRAP: bool,
                  CKA_UNWRAP: bool,
                  CKA_SIGN: bool,
                  CKA_SIGN_RECOVER: None,
                  CKA_VERIFY: bool,
                  CKA_VERIFY_RECOVER: None,
                  CKA_DERIVE: bool,
                  CKA_START_DATE: CDict(date_attrb),
                  CKA_END_DATE: CDict(date_attrb),
                  CKA_MODULUS: None,
                  CKA_MODULUS_BITS: long,
                  CKA_PUBLIC_EXPONENT: int,  # Python has no concept of byte
                  CKA_PRIVATE_EXPONENT: None,
                  CKA_PRIME_1: None,
                  CKA_PRIME_2: None,
                  CKA_EXPONENT_1: None,
                  CKA_EXPONENT_2: None,
                  CKA_COEFFICIENT: None,
                  CKA_PRIME: CList(str),
                  CKA_SUBPRIME: CList(str),
                  CKA_BASE: CList(str),
                  CKA_PRIME_BITS: long,
                  CKA_SUBPRIME_BITS: long,
                  CKA_VALUE_BITS: long,
                  CKA_VALUE_LEN: long,
                  CKA_ECDSA_PARAMS: CList(str),
                  CKA_EC_POINT: None,
                  CKA_LOCAL: None,
                  CKA_MODIFIABLE: bool,
                  CKA_EXTRACTABLE: bool,
                  CKA_ALWAYS_SENSITIVE: bool,
                  CKA_NEVER_EXTRACTABLE: bool,
                  CKA_CCM_PRIVATE: None,
                  CKA_FINGERPRINT_SHA1: NonAsciiString,
                  CKA_FINGERPRINT_SHA256: NonAsciiString,
                  CKA_PKC_TCTRUST: None,
                  CKA_PKC_CITS: None,
                  CKA_OUID: NonAsciiString,
                  CKA_X9_31_GENERATED: None,
                  CKA_PKC_ECC: None,
                  CKA_EKM_UID: None,
                  CKA_GENERIC_1: None,
                  CKA_GENERIC_2: None,
                  CKA_GENERIC_3: None,
                  CKA_UNWRAP_TEMPLATE: {},
                  CKA_DERIVE_TEMPLATE: {}}

role_attributes = {}


def to_byte_array(val):
    """Converts an arbitrarily sized integer into a byte array.

    It'll zero-pad the bit length so it's a multiple of 8, then convert
    the int to binary, split the binary string into sections of 8, then
    place each section into a slot in a c_ubyte array (converting to small
    int).

    :param val: Big Integer to convert.
    :return: c_ubyte array

    """
    # Explicitly convert to a long. Python doesn't like X.bit_length() where X is an int
    # and not a variable assigned an int.
    width = long(val).bit_length()
    width += 8 - ((width % 8) or 8)

    fmt = "{:0%sb}" % width
    str_val = fmt.format(val)
    n = 8
    str_array = [str_val[i:i + n] for i in range(0, len(str_val), n)]

    return (CK_BYTE * len(str_array))(*[int(x, 2) for x in str_array])


class Attributes:
    """A wrapper around all of the attributes necessary to create a key.
    Has a python dictionary object containing python types, the corresponding
    C struct can then be generated with a simple method call.


    """
    attributes = {}

    def __init__(self, attributes_list=None):
        """
        Initializes a Attributes object, the attributes_list argument is optional
        since the attributes object can be populated from the board later

        @param attributes_list: The list of python style attributes to create the class with.
        """

        if attributes_list is not None:
            # take either strings or ints as the key to the dictionary (used mainly to accomodate
            #  xmlrpc easily)
            attributes_list_new = {}
            for key, value in attributes_list.iteritems():
                if isinstance(key, str):
                    attributes_list_new[int(key)] = value
                else:
                    break
            if len(attributes_list_new) > 0:
                attributes_list = attributes_list_new

            for key in attributes_list:
                self._input_check(key, attributes_list[key])
            self.attributes = attributes_list

    def add_attribute(self, key, value):
        """Add an attribute to the dictionary in place

        :param key: The type of the attribute
        :param value: The value of the attribute

        """
        if isinstance(key, str):
            # take either strings or ints for the key (used mainly to accomodate xmlrpc easily)
            key = int(key)

        self._input_check(key, value)
        self.attributes[key] = value

    def _input_check(self, key, value):
        """Checks to see if the type is supported (yet)

        :param key: They key of the attribute to check
        :param value: The actual value of the input to check
        :returns: Returns true if the variable is a of a type that has been accounted for in the
        key_attributes dictionary

        """
        if isinstance(value, bool) or isinstance(value, int) or isinstance(value,
                                                                           CDict) or isinstance(
            value, long) or isinstance(value, str) or isinstance(value, list) or isinstance(
            value, CList) or isinstance(value, NonAsciiString) or isinstance(value, dict):
            return True
        else:
            raise Exception(
                "Argument type not supported. <key: " + str(key) + ", value: " + str(value) + ">")

    def get_c_struct(self):
        """Assembles and returns a proper C struct from the dictionary of python attributes


        :returns: Returns a Ctypes struct representing the python attributes stored in this class

        """
        c_struct = (CK_ATTRIBUTE * len(self.attributes))()

        i = 0
        for key in self.attributes:
            value = self.attributes[key]
            self._input_check(key, value)

            # Get the proper type for what your data is, originally I had
            # this automatically detected from the python type but passing in
            # int's vs longs was problematic
            item_type = lookup_attributes(key)

            if item_type == bool:
                byte_val = CK_BBOOL(value)
                c_struct[i] = CK_ATTRIBUTE(CK_ATTRIBUTE_TYPE(key),
                                           cast(pointer(byte_val), c_void_p),
                                           CK_ULONG(sizeof(byte_val)))
            elif item_type == long:
                long_val = CK_ULONG(value)
                c_struct[i] = CK_ATTRIBUTE(CK_ATTRIBUTE_TYPE(key),
                                           cast(pointer(long_val), c_void_p),
                                           CK_ULONG(sizeof(long_val)))
            elif item_type == int:
                ck_byte_array = to_byte_array(value)
                c_struct[i] = CK_ATTRIBUTE(CK_ATTRIBUTE_TYPE(key),
                                           cast(pointer(ck_byte_array), c_void_p),
                                           CK_ULONG(sizeof(ck_byte_array)))
            elif item_type == str:
                string_val = create_string_buffer(value)
                c_struct[i] = CK_ATTRIBUTE(CK_ATTRIBUTE_TYPE(key), cast(string_val, c_void_p),
                                           CK_ULONG(len(string_val)))
            elif isinstance(item_type, CDict):
                date = CK_DATE()

                date.year = convert_string_to_CK_CHAR(value.dict_val['year'])
                date.month = convert_string_to_CK_CHAR(value.dict_val['month'])
                date.day = convert_string_to_CK_CHAR(value.dict_val['day'])

                c_struct[i] = CK_ATTRIBUTE(CK_ATTRIBUTE_TYPE(key), cast(pointer(date), c_void_p),
                                           CK_ULONG(sizeof(date)))
            elif isinstance(item_type, CList):
                if item_type.list_type == str:
                    list_val = create_string_buffer("", len(value))

                    ptr = cast(pointer(list_val), c_void_p)
                    for j in range(0, len(value)):
                        list_val[j] = chr(value[j])

                    c_struct[i] = CK_ATTRIBUTE(CK_ATTRIBUTE_TYPE(key), ptr, CK_ULONG(len(value)))
                elif item_type.list_type == long:
                    list_val = (CK_ULONG * len(value))()
                    ptr = cast(pointer(list_val), c_void_p)
                    for j in range(0, len(value)):
                        list_val[j] = CK_ULONG(value[j])

                    c_struct[i] = CK_ATTRIBUTE(CK_ATTRIBUTE_TYPE(key), ptr,
                                               CK_ULONG(sizeof(CK_ULONG(0)) * len(value)))
            elif item_type == NonAsciiString:
                list_val = (CK_CHAR * len(value))()
                ptr = cast(pointer(list_val), c_void_p)
                for j in range(0, len(value)):
                    list_val[j] = CK_CHAR(ord(value[j]) - 0x30)
                c_struct[i] = CK_ATTRIBUTE(CK_ATTRIBUTE_TYPE(key), ptr,
                                           CK_ULONG(sizeof(CK_CHAR(0)) * len(value)))
            elif isinstance(item_type, dict):
                template = Attributes(attributes_list=value).get_c_struct()
                c_struct[i] = CK_ATTRIBUTE(CK_ATTRIBUTE_TYPE(key),
                                           cast(template, c_void_p),
                                           CK_ULONG(len(template)))
            else:
                raise Exception("Argument type " + str(item_type) + " not supported. <key: " + str(
                    key) + ", value: " + str(value) + ">")
            i += 1

        return c_struct

    def retrieve_key_attributes(self, h_session, h_object):
        """Gets all of the key's attributes from the board given the key's handle,
        and populates the KeyAttribute object with all of those attributes.

        :param h_session: Current session
        :param h_object: The handle of the object to fetch the attributes for

        """
        # Clean before starting
        self.attributes = {}

        for key in key_attributes:
            attribute = CK_ATTRIBUTE()
            attribute.type = CK_ULONG(key)
            attribute.pValue = c_void_p(0)
            retCode = C_GetAttributeValue(h_session, CK_OBJECT_HANDLE(h_object), byref(attribute),
                                          CK_ULONG(1))
            if retCode == CKR_OK:
                attr_type = lookup_attributes(key)

                if isinstance(attr_type, CList):
                    if attr_type.list_type == str:
                        pb_value = (CK_BYTE * attribute.usValueLen)()
                    elif attr_type.list_type == long:
                        pb_value = (CK_ULONG * attribute.usValueLen)()
                else:
                    pb_value = create_string_buffer(attribute.usValueLen)

                attribute.pValue = cast(pb_value, c_void_p)
                retCode = C_GetAttributeValue(h_session, CK_OBJECT_HANDLE(h_object),
                                              byref(attribute), CK_ULONG(1))
                if retCode == CKR_OK:
                    if attr_type == bool:
                        self.add_attribute(attribute.type, attr_type(
                            cast(attribute.pValue, POINTER(c_bool)).contents.value))
                    elif attr_type == str:
                        string = cast(attribute.pValue, c_char_p).value[0:attribute.usValueLen]
                        self.add_attribute(attribute.type, attr_type(string))
                    elif attr_type == long:
                        self.add_attribute(attribute.type, (
                            attr_type(cast(attribute.pValue, POINTER(c_ulong)).contents.value)))
                    elif attr_type == int:
                        self.add_attribute(attribute.type, attr_type(
                            cast(attribute.pValue, POINTER(c_int)).contents.value))
                    elif isinstance(attr_type, CList):
                        value = []
                        i = 0
                        while i < attribute.usValueLen:
                            value.append(pb_value[i])
                            i += 1

                        self.add_attribute(attribute.type, value)
                    elif attr_type == NonAsciiString:
                        value = ''
                        i = 0
                        while i < attribute.usValueLen:
                            value += '%02x' % cast(pb_value, CK_CHAR_PTR)[i]
                            i += 1

                        self.add_attribute(attribute.type, value)
                    elif attr_type is None:
                        # raise Exception("Attribute of type " + str(attribute.type) + "'s value
                        # type not yet determined") # Add type to all_attributes
                        pass

    def get_attributes(self):
        """Returns the python dictionary of attributes


        :returns: The python dictionary of attributes

        """
        return self.attributes

    def __eq__(self, other):
        """
        Overriding the == sign to properly compare equality in KeyAttribute objects

        :param other: Another KeyAttribute to compare against
        :return: True if the attributes are equal
        """
        other_attribs = other.get_attributes()
        self_attribs = self.get_attributes()
        for key in self.attributes:
            if key in self_attribs and key in other_attribs:  # TODO we are only checking if the
                # key exists in both, maybe this is a bad idea
                if self_attribs[key] != other_attribs[key]:
                    return False
        return True

    def debug_print(self):
        """Simple method to print out all the keys and values in a KeyAttribute object"""
        for key in self.attributes:
            print "key: " + str(key) + ", value: " + str(self.attributes[key])


def get_attribute_py_value(attribute):
    """Gets the python version of the value of a attribute from the
    C format

    :param attribute: The ctypes style variable representing the value of an attribute
    :returns: Returns the python version of the ctypes style variable

    """
    key = attribute.type
    attr_type = lookup_attributes(key)
    if attr_type == bool:
        return attr_type(cast(attribute.pValue, POINTER(c_bool)).contents.value)
    elif attr_type == str:
        string = cast(attribute.pValue, c_char_p).value[0:attribute.usValueLen]
        return attr_type(string)
    elif attr_type == long:
        return attr_type(cast(attribute.pValue, POINTER(c_ulong)).contents.value)
    elif attr_type == int:
        return attr_type(cast(attribute.pValue, POINTER(c_int)).contents.value)
    elif isinstance(attr_type, CDict):
        py_date = {}

        c_date = cast(attribute.pValue, POINTER(CK_DATE))

        py_date['year'] = convert_CK_CHAR_to_string(cast(c_date.year, CK_CHAR_PTR))
        py_date['month'] = convert_CK_CHAR_to_string(cast(c_date.month, CK_CHAR_PTR))
        py_date['day'] = convert_CK_CHAR_to_string(cast(c_date.day, CK_CHAR_PTR))
        return py_date

    elif isinstance(attr_type, CList):
        if attr_type.list_type == str:
            value = []
            try:
                for i in range(0, attribute.usValueLen):
                    value.append(attribute.pValue[i])
                return value
            except OverflowError:
                return value

        elif attr_type.list_type == long:
            value = []
            for i in range(0, attribute.usValueLen / sizeof(CK_ULONG(0))):
                value.append(cast(attribute.pValue, CK_ULONG_PTR)[i])
            return value
    elif attr_type == NonAsciiString:
        value = ''
        for i in range(0, attribute.usValueLen / sizeof(CK_CHAR(0))):
            value += '%02x' % cast(attribute.pValue, CK_CHAR_PTR)[i]
        return value
    elif attr_type is None:
        # raise Exception("Attribute of type " + str(attribute.type) + "'s value type not yet
        # determined") # Add type to all_attributes
        pass


def c_struct_to_python(c_struct):
    """Converts a struct in C to a dictionary in python.

    :param c_struct: The c struct to convert into a dictionary in python
    :returns: Returns a python dictionary which represents the C struct passed in

    """
    py_struct = {}
    for i in range(0, len(c_struct)):
        obj_type = c_struct[i].type

        value = get_attribute_py_value(c_struct[i])

        py_struct[obj_type] = value

    return py_struct


def lookup_attributes(key):
    """Utility function to look through the lists of attributes and figure out
    the type of variable for a given attribute represented by a key

    :param key: The key representing the attribute
    :returns: The python type that can represent the attribute

    """

    ret_val = None
    if key in key_attributes:
        ret_val = key_attributes[key]
    elif key in role_attributes:
        ret_val = role_attributes[key]

    return ret_val


def convert_string_to_CK_CHAR(string):
    """

    :param string:

    """
    byte_array = (c_ubyte * len(string))()
    i = 0
    for char in string:
        byte_array[i] = ord(char)
        i += 1

    return byte_array


def convert_CK_CHAR_to_string(byte_array):
    """

    :param byte_array:

    """
    string = ""

    for b in byte_array:
        string += chr(b)
    return string


def convert_ck_char_array_to_string(ck_char_array):
    """

    :param ck_char_array:

    """
    string = ""

    for b in ck_char_array:
        string = string + b
    return string


def convert_CK_BYTE_array_to_string(byte_array):
    """

    :param byte_array:

    """
    string = ""

    for b in byte_array:
        string += "%02x" % b
    return string
