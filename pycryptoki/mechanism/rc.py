"""
RC-related Mechanism implementations
"""
import logging
import types
from ctypes import c_void_p, cast, pointer, POINTER, sizeof, create_string_buffer, c_char

from six import integer_types

from .. import cryptoki
from . import Mechanism
from ..attributes import to_byte_array, to_char_array, CONVERSIONS
from ..cryptoki import CK_AES_CBC_PAD_EXTRACT_PARAMS, CK_MECHANISM, \
    CK_ULONG, CK_ULONG_PTR, CK_AES_CBC_PAD_INSERT_PARAMS, CK_BYTE, CK_BYTE_PTR, CK_RC2_CBC_PARAMS, \
    CK_RC5_PARAMS, CK_RC5_CBC_PARAMS, CK_MECHANISM_TYPE, CK_AES_XTS_PARAMS, \
    CK_RSA_PKCS_OAEP_PARAMS, \
    CK_AES_GCM_PARAMS, CK_RSA_PKCS_PSS_PARAMS, CK_KEY_DERIVATION_STRING_DATA, c_ubyte, \
    CK_AES_CBC_ENCRYPT_DATA_PARAMS
from ..defines import *
from ..exceptions import LunaException


class RC2Mechanism(Mechanism):
    """
    Sets the mechanism parameter to the usEffectiveBits
    """
    REQUIRED_PARAMS = ['usEffectiveBits']

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(RC2Mechanism, self).to_c_mech()
        effective_bits = CK_ULONG(self.params['usEffectiveBits'])
        self.mech.pParameter = cast(pointer(effective_bits), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(effective_bits))
        return self.mech


class RC2CBCMechanism(Mechanism):
    """
    Creates required RC2CBC Param structure & converts python data to C data.
    """
    REQUIRED_PARAMS = ['usEffectiveBits', 'iv']

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(RC2CBCMechanism, self).to_c_mech()
        effective_bits = self.params['usEffectiveBits']
        cbc_params = CK_RC2_CBC_PARAMS()
        cbc_params.usEffectiveBits = CK_ULONG(effective_bits)
        cbc_params.iv = (CK_BYTE * 8)(*self.params['iv'])
        self.mech.pParameter = cast(pointer(cbc_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(cbc_params))
        return self.mech


class RC5Mechanism(Mechanism):
    """
    Creates required RC5 Param structure & converts python data to C data.
    """
    REQUIRED_PARAMS = ['ulWordsize', 'ulRounds']

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(RC5Mechanism, self).to_c_mech()
        rc5_params = CK_RC5_PARAMS()
        rc5_params.ulWordsize = CK_ULONG(self.params['ulWordsize'])
        rc5_params.ulRounds = CK_ULONG(self.params['ulRounds'])
        self.mech.pParameter = cast(pointer(rc5_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(rc5_params))
        return self.mech


class RC5CBCMechanism(Mechanism):
    """
    Creates required RC5CBC Param structure & converts python data to C data.
    """
    REQUIRED_PARAMS = ['ulWordsize', 'ulRounds', 'iv']

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(RC5CBCMechanism, self).to_c_mech()
        rc5_params = CK_RC5_CBC_PARAMS()
        rc5_params.ulWordsize = CK_ULONG(self.params['ulWordsize'])
        rc5_params.ulRounds = CK_ULONG(self.params['ulRounds'])
        iv, ivlen = to_byte_array(self.params['iv'])
        rc5_params.pIv = cast(iv, CK_BYTE_PTR)
        rc5_params.ulIvLen = ivlen
        self.mech.pParameter = cast(pointer(rc5_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(rc5_params))
        return self.mech

