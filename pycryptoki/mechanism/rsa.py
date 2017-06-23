"""
RSA-related Mechanism implementations.
"""
from ctypes import c_void_p, cast, pointer, sizeof

from .helpers import Mechanism
from ..attributes import to_byte_array
from ..cryptoki import CK_ULONG, CK_RSA_PKCS_OAEP_PARAMS, \
    CK_RSA_PKCS_PSS_PARAMS
from ..defines import *


class RSAPKCSOAEPMechanism(Mechanism):
    """
    Create the required RSA_PKCS_OAEP param structure & convert python data to
    C data.
    """
    REQUIRED_PARAMS = ['hashAlg', 'mgf']

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(RSAPKCSOAEPMechanism, self).to_c_mech()
        oaep_params = CK_RSA_PKCS_OAEP_PARAMS()
        oaep_params.hashAlg = CK_ULONG(self.params['hashAlg'])
        oaep_params.mgf = CK_ULONG(self.params['mgf'])
        # Note: According to
        # https://www.cryptsoft.com/pkcs11doc/v220
        # /group__SEC__12__1__7__PKCS____1__RSA__OAEP__MECHANISM__PARAMETERS.html
        # there is only one encoding parameter source.
        oaep_params.source = CK_ULONG(CKZ_DATA_SPECIFIED)
        data, data_len = to_byte_array(self.params.get('sourceData', ''))
        oaep_params.pSourceData = data
        oaep_params.ulSourceDataLen = data_len

        self.mech.pParameter = cast(pointer(oaep_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(oaep_params))
        return self.mech


class RSAPKCSPSSMechanism(Mechanism):
    """
    Create the required RSA_PKCS_PSS param structure & convert python data to
    C data.
    """
    REQUIRED_PARAMS = ['hashAlg', 'mgf']

    def to_c_mech(self):
        """
        Uses default salt length of 8.
        Can be overridden w/ a parameter though.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(RSAPKCSPSSMechanism, self).to_c_mech()
        c_params = CK_RSA_PKCS_PSS_PARAMS()
        c_params.hashAlg = CK_ULONG(self.params['hashAlg'])
        c_params.mgf = CK_ULONG(self.params['mgf'])
        c_params.usSaltLen = CK_ULONG(self.params.get('usSaltLen', 8))
        self.mech.pParameter = cast(pointer(c_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(c_params))
        return self.mech
