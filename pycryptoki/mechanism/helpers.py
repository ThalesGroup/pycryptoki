"""
Mechanism base class, as well as helper functions for parsing Mechanism arguments
to pycryptoki functions.
"""

import logging
from ctypes import c_void_p, cast, pointer, POINTER, sizeof, create_string_buffer, c_char
import warnings

from six import integer_types, binary_type

from pycryptoki import cryptoki
from pycryptoki.attributes import CONVERSIONS
from pycryptoki.cryptoki import CK_ULONG
from pycryptoki.exceptions import LunaException

from pycryptoki.string_helpers import _decode
from pycryptoki.lookup_dicts import MECH_NAME_LOOKUP
from pycryptoki.pycryptoki_warnings import CryptoWarning
from ..cryptoki import (
    CK_AES_CBC_PAD_EXTRACT_PARAMS,
    CK_MECHANISM,
    CK_ULONG,
    CK_ULONG_PTR,
    CK_AES_CBC_PAD_INSERT_PARAMS,
    CK_BYTE,
    CK_BYTE_PTR,
    CK_MECHANISM_TYPE,
)
from ..defines import *

LOG = logging.getLogger(__name__)

CK_AES_CBC_PAD_EXTRACT_PARAMS_TEMP = {
    "mechanism": CKM_AES_CBC_PAD_EXTRACT_DOMAIN_CTRL,
    "ulType": CK_CRYPTOKI_ELEMENT,
    "ulHandle": 5,
    "ulDeleteAfterExtract": 0,
    "pBuffer": 0,
    "pulBufferLen": 0,
    "ulStorage": CK_STORAGE_HOST,
    "pedId": 0,
    "pbFileName": 0,
    "ctxID": 3,
}

CK_AES_CBC_PAD_INSERT_PARAMS_TEMP = {
    "mechanism": CKM_AES_CBC_PAD_INSERT_DOMAIN_CTRL,
    "ulType": CK_CRYPTOKI_ELEMENT,
    "ulContainerState": 0,
    "pBuffer": 0,
    "pulBufferLen": 0,
    "ulStorageType": CK_STORAGE_HOST,
    "pulType": 0,
    "pulHandle": 0,
    "ctxID": 3,
    "pedID": 3,
    "pbFileName": 0,
    "ulStorage": CK_STORAGE_HOST,
}

supported_parameters = {
    "CK_AES_CBC_PAD_EXTRACT_PARAMS": CK_AES_CBC_PAD_EXTRACT_PARAMS,
    "CK_AES_CBC_PAD_INSERT_PARAMS": CK_AES_CBC_PAD_INSERT_PARAMS,
}


class MechanismException(Exception):
    """
    Exception raised for mechanism errors. Ex: required parameters are missing
    """

    pass


class Mechanism(object):
    """
    Base class for pycryptoki mechanisms.
    Performs checks for missing parameters w/ created mechs, and
    creates the base Mechanism Struct for conversion to ctypes.
    """

    REQUIRED_PARAMS = []
    OPTIONAL_PARAMS = []

    def __new__(cls, mech_type="UNKNOWN", params=None):
        """
        Factory for mechs.
        """

        from . import MECH_LOOKUP, NullMech

        if cls == Mechanism:
            mech_cls = MECH_LOOKUP.get(mech_type, NullMech)
            return super(Mechanism, cls).__new__(mech_cls)
        else:
            return super(Mechanism, cls).__new__(cls)

    def __init__(self, mech_type="UNKNOWN", params=None):
        self.mech_type = mech_type
        if params is None:
            params = {}
        self.params = params

        missing_params = []
        for req in self.REQUIRED_PARAMS:
            if req not in params:
                missing_params.append(req)
        if missing_params:
            raise MechanismException(
                "Cannot create {}, "
                "Missing required parameters:\n\t"
                "{}".format(self.__class__, "\n\t".join(missing_params))
            )

        warnings.filterwarnings("always", r"^Found extra parameter.*", CryptoWarning)
        for param in params:
            if (
                param not in self.REQUIRED_PARAMS
                and param not in self.OPTIONAL_PARAMS
                and not isinstance(self, AutoMech)
            ):
                warnings.warn(
                    "Found extra parameter while creating {}: {}. It will not be used.".format(
                        self.__class__, param
                    ),
                    CryptoWarning,
                )

    def __repr__(self):
        """
        Return a human-readable string of the mechanism data.
        """
        # todo: lookup dict for the mechanism name.
        return "{}(mech_type: {}," " {})".format(
            self.__class__.__name__,
            MECH_NAME_LOOKUP.get(self.mech_type, "UNKNOWN"),
            ", ".join("{}: {}".format(k, v) for k, v in self.params.items()),
        )

    def __str__(self):
        """
        Formatted string representation of a mechanism.
        """
        nice_params = []
        msg = "{}(mech_type: {}".format(
            self.__class__.__name__, MECH_NAME_LOOKUP.get(self.mech_type, "UNKNOWN")
        )
        # +1 for the opening (
        msg_buff = len(self.__class__.__name__) + 1
        for key, value in self.params.items():
            if isinstance(value, binary_type):
                value = _decode(value)
            nice_params.append("{}{}: {}".format(" " * msg_buff, key, value))
        if self.params:
            msg += ",\n" + "\n".join(nice_params)
        msg += ")"
        return msg

    def to_c_mech(self):
        """
        Create the Mechanism structure & set the mech type to the passed-in flavor.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        self.mech = CK_MECHANISM()
        self.mech.mechanism = CK_MECHANISM_TYPE(self.mech_type)
        return self.mech


def get_c_struct_from_mechanism(python_dictionary, params_type_string):
    """Gets a c struct from a python dictionary representing that struct

    :param python_dictionary: The python dictionary representing the C struct,
        see :class:`CK_AES_CBC_PAD_EXTRACT_PARAMS` for an example
    :param params_type_string: A string representing the parameter struct.
        ex. for  :class:`~pycryptoki.cryptoki.CK_AES_CBC_PAD_EXTRACT_PARAMS` use the
        string ``CK_AES_CBC_PAD_EXTRACT_PARAMS``
    :returns: A C struct

    """
    params_type = supported_parameters[params_type_string]
    params = params_type()
    mech = CK_MECHANISM()
    mech.mechanism = python_dictionary["mechanism"]
    mech.pParameter = cast(pointer(params), c_void_p)
    mech.usParameterLen = CK_ULONG(sizeof(params_type))

    # Automatically handle the simpler fields
    for entry in params_type._fields_:
        key_name = entry[0]
        key_type = entry[1]

        if key_type == CK_ULONG:
            setattr(params, key_name, CK_ULONG(python_dictionary[key_name]))
        elif key_type == CK_ULONG_PTR:
            setattr(params, key_name, pointer(CK_ULONG(python_dictionary[key_name])))
        else:
            continue

    # Explicitly handle the more complex fields
    if params_type == CK_AES_CBC_PAD_EXTRACT_PARAMS:
        if len(python_dictionary["pBuffer"]) == 0:
            params.pBuffer = None
        else:
            params.pBuffer = (CK_BYTE * len(python_dictionary["pBuffer"]))()
        # params.pbFileName = 0 #TODO convert byte pointer to serializable type
        pass
    elif params_type == CK_AES_CBC_PAD_INSERT_PARAMS:
        # params.pbFileName =  TODO
        params.pBuffer = cast(create_string_buffer(python_dictionary["pBuffer"]), CK_BYTE_PTR)
        params.ulBufferLen = len(python_dictionary["pBuffer"])
        pass
    else:
        raise Exception("Unsupported parameter type, pycryptoki can be extended to make it work")

    return mech


def get_python_dict_from_c_mechanism(c_mechanism, params_type_string):
    """Gets a python dictionary from a c mechanism's struct for serialization
    and easier test case writing

    :param c_mechanism: The c mechanism to convert to a python dictionary
    :param params_type_string: A string representing the parameter struct.
        ex. for  :class:`~pycryptoki.cryptoki.CK_AES_CBC_PAD_EXTRACT_PARAMS` use the
        string ``CK_AES_CBC_PAD_EXTRACT_PARAMS``
    :returns: A python dictionary representing the c struct
    """
    python_dictionary = {}
    python_dictionary["mechanism"] = c_mechanism.mechanism

    params_type = supported_parameters[params_type_string]
    params_struct = cast(c_mechanism.pParameter, POINTER(params_type)).contents

    # Automatically handle the simpler fields
    for entry in params_type._fields_:
        key_name = entry[0]
        key_type = entry[1]

        if key_type == CK_ULONG:
            python_dictionary[key_name] = getattr(params_struct, key_name)
        elif key_type == CK_ULONG_PTR:
            python_dictionary[key_name] = getattr(params_struct, key_name).contents.value
        else:
            continue

    # Explicitly handle the more complex fields
    if params_type == CK_AES_CBC_PAD_EXTRACT_PARAMS:
        bufferLength = params_struct.pulBufferLen.contents.value
        if params_struct.pBuffer is None:
            bufferString = None
        else:
            char_p_string = cast(params_struct.pBuffer, POINTER(c_char))
            if char_p_string is not None:
                bufferString = char_p_string[0:bufferLength]
            else:
                bufferString = None
        python_dictionary["pBuffer"] = bufferString
        python_dictionary["pbFileName"] = 0  # TODO
    elif params_type == CK_AES_CBC_PAD_INSERT_PARAMS:
        python_dictionary["pbFileName"] = 0  # TODO
        python_dictionary["pBuffer"] = 0  # TODO
    else:
        raise Exception("Unsupported parameter type, pycryptoki can be extended to make it work")

    return python_dictionary


def parse_mechanism(mechanism_param):
    """
    Designed for use with any function call that takes in a mechanism,
    this will handle a mechanism parameter that is one of the following:

        1. ``CKM_`` integer constant -- will create a :class:`~pycryptoki.cryptoki.CK_MECHANISM`
           with only mech_type set.

           .. code-block :: python

                parse_mechanism(CKM_RSA_PKCS)
                # Results in:
                mech = CK_MECHANISM()
                mech.mechanism = CK_MECHANISM_TYPE(CKM_RSA_PKCS)
                mech.pParameter = None
                mech.usParameterLen = 0

        2. Dictionary with ``mech_type`` as a mandatory key, and ``params`` as an optional key. This
           will be passed into the :class:`Mechanism` class for conversion to
           a :class:`~pycryptoki.cryptoki.CK_MECHANISM`.

           .. code-block :: python

                parse_mechanism({'mech_type': CKM_AES_CBC,
                                 'params': {'iv': list(range(8))}})
                # Results in:
                mech = CK_MECHANISM()
                mech.mechanism = CK_MECHANISM_TYPE(CKM_AES_CBC)
                iv_ba, iv_len = to_byte_array(list(range(8)))
                mech.pParameter = iv_ba
                mech.usParameterLen = iv_len

        3. :class:`~pycryptoki.cryptoki.CK_MECHANISM` struct -- passed directly into the raw C Call.
        4. Mechanism class -- will call to_c_mech() on the class, and use the results.

    .. warning:: If you're using this with rpyc, you need to make sure the call `to_c_mech` occurs
        on the *server* (the machine with the HSM)! If you pass in a :py:class:`Mechanism` class
        that was created on the client, the resulting call into `to_c_mech()` will *also* be on
        the client side!

    .. note:: You can look at ``REQUIRED_PARAMS`` on each mechanism class to see what parameters are
        required.

    :param mechanism_param: Parameter to convert to a C Mechanism.
    :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM` struct.
    """

    if isinstance(mechanism_param, dict):
        mech = Mechanism(**mechanism_param).to_c_mech()
    elif isinstance(mechanism_param, CK_MECHANISM):
        mech = mechanism_param
    elif isinstance(mechanism_param, integer_types):
        mech = Mechanism(mech_type=mechanism_param).to_c_mech()
    elif isinstance(mechanism_param, Mechanism):
        mech = mechanism_param.to_c_mech()
    else:
        raise TypeError(
            "Invalid mechanism type {}, should be CK_MECHANISM, dictionary with "
            "kwargs to be passed to `Mechanism`, integer constant, or a "
            "Mechanism() class.".format(type(mechanism_param))
        )

    return mech


class AutoMech(Mechanism):
    """
    An attempt to examine underlying C Struct and fill in the appropriate fields,
    making some assumptions about the data. This works best with parameter structs that only
    have CK_ULONGs within them (though there is a best-effort attempt to handle arrays).

    .. warning:: Do not use this if the mechanism is already defined!
    """

    def to_c_mech(self):
        """
        Attempt to handle generic mechanisms by introspection of the
        structure.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(AutoMech, self).to_c_mech()
        c_params_type = getattr(cryptoki, self.params.get("params_name", "UNKNOWN"), None)
        if not c_params_type:
            raise MechanismException(
                "Failed to find a suitable "
                "Ctypes Parameter Struct for type {}. "
                "Make sure to set 'params_name' in the arguments!".format(repr(self.mech_type))
            )

        fields = c_params_type._fields_
        c_params = c_params_type()
        for name, c_type in fields:
            # Check if it's an array.
            if hasattr(c_type, "_length_"):
                c_type = c_type._type_
                if c_type not in CONVERSIONS:
                    raise LunaException("Cannot convert to c_type: {}".format(c_type))
                ptr, length = CONVERSIONS[c_type](self.params[name])
                setattr(c_params, name, cast(ptr, POINTER(c_type)))
            # Otherwise, do a direct conversion.
            else:
                # c_type = c_type._type_
                setattr(c_params, name, c_type(self.params[name]))
        self.mech.pParameter = cast(pointer(c_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(c_params))
        return self.mech
