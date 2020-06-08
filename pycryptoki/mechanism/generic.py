"""
Generic Mechanisms conversions.
"""
from ctypes import c_void_p, cast, pointer, POINTER, sizeof
from . import Mechanism
from ..attributes import to_byte_array
from ..cryptoki import CK_ULONG, CK_KEY_DERIVATION_STRING_DATA, c_ubyte


class ConcatenationDeriveMechanism(Mechanism):
    """
    Mechanism class for key derivations. This will take in a second key handle in the parameters,
    and use it in the resulting Structure.

     .. warning :: This mechanism is disabled in later versions of PCKS11.

    """

    REQUIRED_PARAMS = ["h_second_key"]

    def to_c_mech(self):
        """
        Add in a pointer to the second key in the resulting mech structure.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(ConcatenationDeriveMechanism, self).to_c_mech()
        c_second_key = CK_ULONG(self.params["h_second_key"])
        self.mech.pParameter = cast(pointer(c_second_key), c_void_p)
        self.mech.usParameterLen = sizeof(c_second_key)
        return self.mech


class StringDataDerivationMechanism(Mechanism):
    """
    Mechanism class for key derivation using passed in string data.
    """

    REQUIRED_PARAMS = ["data"]

    def to_c_mech(self):
        """
        Convert data to bytearray, then use in the resulting mech structure.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(StringDataDerivationMechanism, self).to_c_mech()
        parameters = CK_KEY_DERIVATION_STRING_DATA()
        data, length = to_byte_array(self.params["data"])
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
