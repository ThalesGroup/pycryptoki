"""
AES-specific mechanism implementations.
"""
import logging
from ctypes import c_void_p, cast, pointer, sizeof

from . import Mechanism
from ..attributes import to_byte_array
from ..cryptoki import (
    CK_ULONG,
    CK_BYTE,
    CK_BYTE_PTR,
    CK_AES_XTS_PARAMS,
    CK_AES_GCM_PARAMS,
    CK_KEY_DERIVATION_STRING_DATA,
    CK_AES_CBC_ENCRYPT_DATA_PARAMS,
    CK_AES_CTR_PARAMS,
    c_ubyte)

LOG = logging.getLogger(__name__)


class IvMechanism(Mechanism):
    """
    Mech class for flavors that require an IV set in the mechanism.
    Will default to `[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]` if no IV is passed in
    """

    OPTIONAL_PARAMS = ["iv"]

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(IvMechanism, self).to_c_mech()
        if self.params is None or "iv" not in self.params:
            self.params["iv"] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
            LOG.warning("Using static IVs can be insecure! ")
        if len(self.params["iv"]) == 0:
            LOG.debug("Setting IV to NULL (using internal)")
            iv_ba = None
            iv_len = 0
        else:
            iv_ba, iv_len = to_byte_array(self.params["iv"])
        self.mech.pParameter = iv_ba
        self.mech.usParameterLen = iv_len
        return self.mech


class Iv16Mechanism(Mechanism):
    """
    Mech class for flavors that require an IV set in the mechanism.
    Will default to `[1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]` if no IV is passed in
    """

    OPTIONAL_PARAMS = ["iv"]

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(Iv16Mechanism, self).to_c_mech()
        if self.params is None or "iv" not in self.params:
            self.params["iv"] = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]
            LOG.warning("Using static IVs can be insecure! ")
        if len(self.params["iv"]) == 0:
            LOG.debug("Setting IV to NULL (using internal)")
            iv_ba = None
            iv_len = 0
        else:
            iv_ba, iv_len = to_byte_array(self.params["iv"])
        self.mech.pParameter = iv_ba
        self.mech.usParameterLen = iv_len
        return self.mech


class AESXTSMechanism(Mechanism):
    """
    Creates the AES-XTS specific param structure & converts python types to C types.
    """

    REQUIRED_PARAMS = ["cb", "hTweakKey"]

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(AESXTSMechanism, self).to_c_mech()
        xts_params = CK_AES_XTS_PARAMS()
        xts_params.cb = (CK_BYTE * 16)(*self.params["cb"])
        xts_params.hTweakKey = CK_ULONG(self.params["hTweakKey"])
        self.mech.pParameter = cast(pointer(xts_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(xts_params))
        return self.mech


class AESGCMMechanism(Mechanism):
    """
    Creates the AES-GCM specific param structure & converts python types to C types.
    """

    REQUIRED_PARAMS = ["iv", "AAD", "ulTagBits"]

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(AESGCMMechanism, self).to_c_mech()
        gcm_params = CK_AES_GCM_PARAMS()
        if len(self.params["iv"]) == 0:
            LOG.debug("Setting IV to NULL (using internal)")
            iv_ba = None
            iv_len = 0
        else:
            iv_ba, iv_len = to_byte_array(self.params["iv"])
        gcm_params.pIv = cast(iv_ba, CK_BYTE_PTR)
        gcm_params.ulIvLen = iv_len
        # Assuming 8 bits per entry in IV.
        gcm_params.ulIvBits = CK_ULONG(len(self.params["iv"]) * 8)
        aad, aadlen = to_byte_array(self.params["AAD"])
        gcm_params.pAAD = cast(aad, CK_BYTE_PTR)
        gcm_params.ulAADLen = aadlen
        gcm_params.ulTagBits = CK_ULONG(self.params["ulTagBits"])
        self.mech.pParameter = cast(pointer(gcm_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(gcm_params))
        return self.mech


class AESECBEncryptDataMechanism(Mechanism):
    """
    AES mechanism for deriving keys from encrypted data.
    """

    REQUIRED_PARAMS = ["data"]

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(AESECBEncryptDataMechanism, self).to_c_mech()
        # from https://www.cryptsoft.com/pkcs11doc/v220
        # /group__SEC__12__14__2__MECHANISM__PARAMETERS.html
        # Note: data should be a multiple of 16 long.
        params = CK_KEY_DERIVATION_STRING_DATA()
        pdata, data_len = to_byte_array(self.params["data"])
        params.pData = cast(pdata, CK_BYTE_PTR)
        params.ulLen = data_len
        self.mech.pParameter = cast(pointer(params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(params))
        return self.mech


class AESCBCEncryptDataMechanism(Mechanism):
    """
    AES CBC mechanism for deriving keys from encrypted data.
    """

    REQUIRED_PARAMS = ["iv", "data"]

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(AESCBCEncryptDataMechanism, self).to_c_mech()
        # https://www.cryptsoft.com/pkcs11doc/v220
        # /group__SEC__12__14__KEY__DERIVATION__BY__DATA__ENCRYPTION______DES______AES.html
        # #CKM_AES_CBC_ENCRYPT_DATA
        # Note: data should be a multiple of 16 long.
        params = CK_AES_CBC_ENCRYPT_DATA_PARAMS()
        pdata, data_len = to_byte_array(self.params["data"])
        # Note: IV should always be a length of 8.
        params.pData = cast(pdata, CK_BYTE_PTR)
        params.length = data_len
        params.iv = (c_ubyte * 16)(*self.params["iv"])
        self.mech.pParameter = cast(pointer(params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(params))
        return self.mech


class AESCTRMechanism(Mechanism):
    """
    AES CTR Mechanism param conversion.
    """

    REQUIRED_PARAMS = ["cb", "ulCounterBits"]

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(AESCTRMechanism, self).to_c_mech()
        ctr_params = CK_AES_CTR_PARAMS()
        ctr_params.cb = (CK_BYTE * 16)(*self.params["cb"])
        ctr_params.ulCounterBits = CK_ULONG(self.params["ulCounterBits"])
        self.mech.pParameter = cast(pointer(ctr_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(ctr_params))
        return self.mech
