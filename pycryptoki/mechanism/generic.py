"""
Generic Mechanisms conversions. 
"""
from ctypes import c_void_p, cast, pointer, POINTER, sizeof
from . import Mechanism, MechanismException
from .. import cryptoki
from ..attributes import to_byte_array, CONVERSIONS
from ..cryptoki import CK_ULONG, CK_KEY_DERIVATION_STRING_DATA, c_ubyte
from ..exceptions import LunaException


class ConcatenationDeriveMechanism(Mechanism):
    """
    Mechanism class for key derivations. This will take in a second key handle in the parameters,
    and use it in the resulting Structure.

     .. warning :: This mechanism is disabled in later versions of PCKS11.

    """
    REQUIRED_PARAMS = ['h_second_key']

    def to_c_mech(self):
        """
        Add in a pointer to the second key in the resulting mech structure.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(ConcatenationDeriveMechanism, self).to_c_mech()
        c_second_key = CK_ULONG(self.params['h_second_key'])
        self.mech.pParameter = cast(pointer(c_second_key), c_void_p)
        self.mech.usParameterLen = sizeof(c_second_key)
        return self.mech


class StringDataDerivationMechanism(Mechanism):
    """
    Mechanism class for key derivation using passed in string data.
    """
    REQUIRED_PARAMS = ['data']

    def to_c_mech(self):
        """
        Convert data to bytearray, then use in the resulting mech structure.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(StringDataDerivationMechanism, self).to_c_mech()
        parameters = CK_KEY_DERIVATION_STRING_DATA()
        data, length = to_byte_array(self.params['data'])
        parameters.pData = cast(data, POINTER(c_ubyte))
        parameters.ulLen = length
        self.mech.pParameter = cast(pointer(parameters), c_void_p)
        self.mech.usParameterLen = sizeof(parameters)
        return self.mech


class NullMech(Mechanism):
    """
    Class that creates a mechanism from a flavor with null parameters.
    Used mostly for signing mechanisms that really don't need anything else.
    """

    def to_c_mech(self):
        """
        Simply set the pParameter to null pointer.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(NullMech, self).to_c_mech()
        self.mech.pParameter = c_void_p(0)
        self.mech.usParameterLen = CK_ULONG(0)
        return self.mech


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
        c_params_type = getattr(cryptoki,
                                self.params.get('params_name', "UNKNOWN"),
                                None)
        if not c_params_type:
            raise MechanismException("Failed to find a suitable "
                                     "Ctypes Parameter Struct for type {}. "
                                     "Make sure to set 'params_name' in the arguments!".format(
                repr(self.mech_type)))

        fields = c_params_type._fields_
        c_params = c_params_type()
        for name, c_type in fields:
            # Check if it's an array.
            if hasattr(c_type, '_length_'):
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
