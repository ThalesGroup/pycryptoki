"""
Conversions for pure-python dictionaries to C struct mechanisms.

To implement a new Mechanism:

    1. Create a new mechanism class, deriving from
       :py:class:`~pycryptoki.mechanism.helpers.Mechanism`
    2. Set ``REQUIRED_PARAMS`` as a class variable. ``REQUIRED_PARAMS`` should be a list of strings,
       defining required parameter keys.

       .. code-block:: python

            class IvMechanism(Mechanism):
                REQUIRED_PARAMS = ['iv']

    3. Override ``to_c_mech()`` on the new mechanism class. This function can access ``self.params``
       to get passed-in parameters, and should create the C parameter struct required by the
       mechanism. This should also return ``self.mech`` (which is a ``CK_MECHANISM`` struct).

        .. code-block:: python
            :caption: Simple Example

            class IvMechanism(Mechanism):
                REQUIRED_PARAMS = ['iv']

                def to_c_mech(self):
                    super(IvMechanism, self).to_c_mech()
                    if len(self.params['iv']) == 0:
                        LOG.debug("Setting IV to NULL (using internal)")
                        iv_ba = None
                        iv_len = 0
                    else:
                        iv_ba, iv_len = to_byte_array(self.params['iv'])
                    self.mech.pParameter = iv_ba
                    self.mech.usParameterLen = iv_len
                    return self.mech


        .. code-block:: python
            :caption: Example with a PARAMS struct

            class AESXTSMechanism(Mechanism):
                REQUIRED_PARAMS = ['cb', 'hTweakKey']

                def to_c_mech(self):
                    super(AESXTSMechanism, self).to_c_mech()
                    xts_params = CK_AES_XTS_PARAMS()
                    xts_params.cb = (CK_BYTE * 16)(*self.params['cb'])
                    xts_params.hTweakKey = CK_ULONG(self.params['hTweakKey'])
                    self.mech.pParameter = cast(pointer(xts_params), c_void_p)
                    self.mech.usParameterLen = CK_ULONG(sizeof(xts_params))
                    return self.mech

"""
from .helpers import (get_c_struct_from_mechanism,
                      get_python_dict_from_c_mechanism,
                      parse_mechanism,
                      Mechanism,
                      MechanismException)
from .aes import (AESECBEncryptDataMechanism,
                  AESCBCEncryptDataMechanism,
                  AESGCMMechanism,
                  AESXTSMechanism,
                  Iv16Mechanism,
                  IvMechanism, AESCTRMechanism)
from .des import DES3CTRMechanism
from .dh import ECDH1DeriveMechanism
from .generic import (ConcatenationDeriveMechanism,
                      StringDataDerivationMechanism,
                      NullMech,
                      AutoMech)
from .rc import (RC2CBCMechanism,
                 RC2Mechanism,
                 RC5CBCMechanism,
                 RC5Mechanism)
from .rsa import (RSAPKCSOAEPMechanism,
                  RSAPKCSPSSMechanism)
from .kdf import PRFKDFDeriveMechanism
from ..defines import (CKM_DES_CBC,
                       CKM_DES3_CBC,
                       CKM_CAST3_CBC,
                       CKM_CAST5_CBC,
                       CKM_DES_CBC_PAD,
                       CKM_DES3_CBC_PAD,
                       CKM_DES3_CBC_PAD_IPSEC,
                       CKM_CAST3_CBC_PAD,
                       CKM_CAST5_CBC_PAD,
                       CKM_DES_CFB8,
                       CKM_DES_CFB64,
                       CKM_DES_OFB64,
                       CKM_AES_KW,
                       CKM_AES_KWP,
                       CKM_AES_CFB8,
                       CKM_AES_CFB128,
                       CKM_AES_OFB,
                       CKM_ARIA_CFB8,
                       CKM_ARIA_CFB128,
                       CKM_ARIA_OFB,
                       CKM_SEED_CBC,
                       CKM_SEED_CBC_PAD,
                       CKM_AES_CBC,
                       CKM_AES_CBC_PAD,
                       CKM_AES_CBC_PAD_IPSEC,
                       CKM_ARIA_ECB,
                       CKM_ARIA_CBC,
                       CKM_ARIA_CBC_PAD,
                       CKM_RC2_ECB,
                       CKM_RC2_MAC,
                       CKM_RC2_CBC,
                       CKM_RC2_CBC_PAD,
                       CKM_RC5_CBC,
                       CKM_RC5_ECB,

                       CKM_AES_XTS,
                       CKM_VENDOR_DEFINED,
                       CKM_AES_GCM,

                       CKM_RSA_PKCS_OAEP,

                       CKM_RSA_PKCS_PSS,
                       CKM_SHA1_RSA_PKCS_PSS,
                       CKM_SHA224_RSA_PKCS_PSS,
                       CKM_SHA256_RSA_PKCS_PSS,
                       CKM_SHA384_RSA_PKCS_PSS,
                       CKM_SHA512_RSA_PKCS_PSS,

                       CKM_DES_ECB,

                       CKM_AES_CBC_ENCRYPT_DATA,
                       CKM_AES_ECB_ENCRYPT_DATA,

                       CKM_CONCATENATE_BASE_AND_KEY,
                       CKM_CONCATENATE_BASE_AND_DATA,
                       CKM_XOR_BASE_AND_DATA,
                       CKM_CONCATENATE_DATA_AND_BASE,

                       CKM_ECDH1_DERIVE,
                       CKM_AES_CTR,
                       CKM_DES3_CTR,
                       CKM_AES_GMAC,

                       CKM_PRF_KDF)

MECH_LOOKUP = {
    # Iv
    CKM_DES_CBC: IvMechanism,
    CKM_DES3_CBC: IvMechanism,
    CKM_CAST3_CBC: IvMechanism,
    CKM_CAST5_CBC: IvMechanism,
    CKM_DES_CBC_PAD: IvMechanism,
    CKM_DES3_CBC_PAD: IvMechanism,
    CKM_DES3_CBC_PAD_IPSEC: IvMechanism,
    CKM_CAST3_CBC_PAD: IvMechanism,
    CKM_CAST5_CBC_PAD: IvMechanism,
    CKM_DES_CFB8: IvMechanism,
    CKM_DES_CFB64: IvMechanism,
    CKM_DES_OFB64: IvMechanism,
    CKM_AES_KW: IvMechanism,
    CKM_AES_KWP: IvMechanism,
    CKM_AES_CFB8: IvMechanism,
    CKM_AES_CFB128: IvMechanism,
    CKM_AES_OFB: IvMechanism,
    CKM_AES_CTR: AESCTRMechanism,
    CKM_DES3_CTR: DES3CTRMechanism,
    CKM_ARIA_CFB8: IvMechanism,
    CKM_ARIA_CFB128: IvMechanism,
    CKM_ARIA_OFB: IvMechanism,
    # Iv16
    CKM_SEED_CBC: Iv16Mechanism,
    CKM_SEED_CBC_PAD: Iv16Mechanism,
    CKM_AES_CBC: Iv16Mechanism,
    CKM_AES_CBC_PAD: Iv16Mechanism,
    CKM_AES_CBC_PAD_IPSEC: Iv16Mechanism,
    CKM_ARIA_ECB: Iv16Mechanism,
    CKM_ARIA_CBC: Iv16Mechanism,
    CKM_ARIA_CBC_PAD: Iv16Mechanism,
    # Others
    CKM_RC2_ECB: RC2Mechanism,
    CKM_RC2_MAC: RC2Mechanism,
    CKM_RC2_CBC: RC2CBCMechanism,
    CKM_RC2_CBC_PAD: RC2CBCMechanism,
    CKM_RC5_CBC: RC5CBCMechanism,
    CKM_RC5_ECB: RC5Mechanism,

    CKM_AES_XTS: AESXTSMechanism,
    (CKM_VENDOR_DEFINED + 0x11c): AESGCMMechanism,  # Backwards compatibility w/ older Lunas.
    CKM_AES_GCM: AESGCMMechanism,
    CKM_AES_GMAC: AESGCMMechanism,

    CKM_RSA_PKCS_OAEP: RSAPKCSOAEPMechanism,

    CKM_RSA_PKCS_PSS: RSAPKCSPSSMechanism,
    CKM_SHA1_RSA_PKCS_PSS: RSAPKCSPSSMechanism,
    CKM_SHA224_RSA_PKCS_PSS: RSAPKCSPSSMechanism,
    CKM_SHA256_RSA_PKCS_PSS: RSAPKCSPSSMechanism,
    CKM_SHA384_RSA_PKCS_PSS: RSAPKCSPSSMechanism,
    CKM_SHA512_RSA_PKCS_PSS: RSAPKCSPSSMechanism,

    CKM_DES_ECB: NullMech,

    CKM_AES_CBC_ENCRYPT_DATA: AESCBCEncryptDataMechanism,
    CKM_AES_ECB_ENCRYPT_DATA: AESECBEncryptDataMechanism,

    CKM_CONCATENATE_BASE_AND_KEY: ConcatenationDeriveMechanism,
    CKM_CONCATENATE_BASE_AND_DATA: StringDataDerivationMechanism,
    CKM_XOR_BASE_AND_DATA: StringDataDerivationMechanism,
    CKM_CONCATENATE_DATA_AND_BASE: StringDataDerivationMechanism,

    CKM_ECDH1_DERIVE: ECDH1DeriveMechanism,

    CKM_PRF_KDF: PRFKDFDeriveMechanism,
}
