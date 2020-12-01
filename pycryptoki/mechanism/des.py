"""
DES3-specific mechanism implementations.
"""
import logging
from ctypes import c_void_p, cast, pointer, sizeof, POINTER

from . import Mechanism

from ..attributes import to_byte_array
from ..conversions import from_bytestring
from ..cryptoki import (
    CK_ULONG,
    CK_BYTE,
    CK_BYTE_PTR,
    CK_DES_CTR_PARAMS,
    CK_KEY_DERIVATION_STRING_DATA,
    CK_DES_CBC_ENCRYPT_DATA_PARAMS,
)

from ..attributes import to_byte_array
from ..conversions import from_bytestring
from ..cryptoki import (
    CK_ULONG,
    CK_BYTE,
    CK_BYTE_PTR,
    CK_DES_CTR_PARAMS,
    CK_KEY_DERIVATION_STRING_DATA,
    CK_DES_CBC_ENCRYPT_DATA_PARAMS,
)

from ..attributes import to_byte_array
from ..conversions import from_bytestring
from ..cryptoki import CK_ULONG, CK_BYTE, CK_BYTE_PTR, CK_DES_CTR_PARAMS, \
    CK_KEY_DERIVATION_STRING_DATA, CK_DES_CBC_ENCRYPT_DATA_PARAMS
LOG = logging.getLogger(__name__)


class DES3CTRMechanism(Mechanism):
    """
    DES3 CTR Mechanism param conversion.
    """

    REQUIRED_PARAMS = ["cb", "ulCounterBits"]

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(DES3CTRMechanism, self).to_c_mech()
        ctr_params = CK_DES_CTR_PARAMS()
        ctr_params.cb = (CK_BYTE * 8)(*self.params["cb"])
        ctr_params.ulCounterBits = CK_ULONG(self.params["ulCounterBits"])
        self.mech.pParameter = cast(pointer(ctr_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(ctr_params))
        return self.mech


class DES3ECBEncryptDataMechanism(Mechanism):
    """
    DES3 mechanism for deriving keys from encrypted data.
    """

    REQUIRED_PARAMS = ["data"]

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(DES3ECBEncryptDataMechanism, self).to_c_mech()
        # from https://www.cryptsoft.com/pkcs11doc/v220
        # /group__SEC__12__14__2__MECHANISM__PARAMETERS.html
        # CKM_DES3_ECB_ENCRYPT_DATA
        # Note: data should same or > size of key in multiples of 8.
        params = CK_KEY_DERIVATION_STRING_DATA()
        pdata, data_len = to_byte_array(from_bytestring(self.params["data"]))
        pdata = cast(pdata, CK_BYTE_PTR)
        params.pData = pdata
        params.ulLen = CK_ULONG(data_len.value)
        self.mech.pParameter = cast(pointer(params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(params))
        return self.mech


class DES3CBCEncryptDataMechanism(Mechanism):
    """
    DES3 CBC mechanism for deriving keys from encrypted data.
    """

    REQUIRED_PARAMS = ["iv", "data"]

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(DES3CBCEncryptDataMechanism, self).to_c_mech()
        # from https://www.cryptsoft.com/pkcs11doc/v220
        # /group__SEC__12__14__2__MECHANISM__PARAMETERS.html
        # CKM_DES3_CBC_ENCRYPT_DATA
        # Note: data should same or > size of key in multiples of 8.
        params = CK_DES_CBC_ENCRYPT_DATA_PARAMS()
        pdata, data_len = to_byte_array(from_bytestring(self.params["data"]))
        pdata = cast(pdata, CK_BYTE_PTR)
        # Note: IV should always be a length of 8.
        params.iv = (CK_BYTE * 8)(*self.params["iv"])
        params.pData = pdata
        params.length = CK_ULONG(data_len.value)
        self.mech.pParameter = cast(pointer(params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(params))
        return self.mech
