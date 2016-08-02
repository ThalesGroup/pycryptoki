"""
Mechanism-related utilities
"""

import logging
from ctypes import c_void_p, cast, pointer, POINTER, sizeof, create_string_buffer, c_char

from . import cryptoki
from .attributes import to_byte_array, to_char_array, CONVERSIONS
from .cryptoki import CK_AES_CBC_PAD_EXTRACT_PARAMS, CK_MECHANISM, \
    CK_ULONG, CK_ULONG_PTR, CK_AES_CBC_PAD_INSERT_PARAMS, CK_BYTE, CK_BYTE_PTR, CK_RC2_CBC_PARAMS, \
    CK_RC5_PARAMS, CK_RC5_CBC_PARAMS, CK_MECHANISM_TYPE, CK_AES_XTS_PARAMS, \
    CK_RSA_PKCS_OAEP_PARAMS, \
    CK_AES_GCM_PARAMS, CK_RSA_PKCS_PSS_PARAMS
from .defines import *
from .test_functions import LunaException

LOG = logging.getLogger(__name__)

CK_AES_CBC_PAD_EXTRACT_PARAMS_TEMP = {'mechanism': CKM_AES_CBC_PAD_EXTRACT_DOMAIN_CTRL,
                                      'ulType': CK_CRYPTOKI_ELEMENT,
                                      'ulHandle': 5,
                                      'ulDeleteAfterExtract': 0,
                                      'pBuffer': 0,
                                      'pulBufferLen': 0,
                                      'ulStorage': CK_STORAGE_HOST,
                                      'pedId': 0,
                                      'pbFileName': 0,
                                      'ctxID': 3
                                      }

CK_AES_CBC_PAD_INSERT_PARAMS_TEMP = {'mechanism': CKM_AES_CBC_PAD_INSERT_DOMAIN_CTRL,
                                     'ulType': CK_CRYPTOKI_ELEMENT,
                                     'ulContainerState': 0,
                                     'pBuffer': 0,
                                     'pulBufferLen': 0,
                                     'ulStorageType': CK_STORAGE_HOST,
                                     'pulType': 0,
                                     'pulHandle': 0,
                                     'ctxID': 3,
                                     'pedID': 3,
                                     'pbFileName': 0,
                                     'ulStorage': CK_STORAGE_HOST,
                                     }

supported_parameters = {'CK_AES_CBC_PAD_EXTRACT_PARAMS': CK_AES_CBC_PAD_EXTRACT_PARAMS,
                        'CK_AES_CBC_PAD_INSERT_PARAMS': CK_AES_CBC_PAD_INSERT_PARAMS}


class MechanismException(Exception):
    """
    Mechanism-related exceptions
    """

    pass


class Mechanism(object):
    """
    Base class for pycryptoki mechanisms.
    Performs checks for missing parameters w/ created mechs, and
    creates the base Mechanism Struct for conversion to ctypes.
    """
    REQUIRED_PARAMS = []

    def __new__(cls, mech_type="UNKNOWN", params=None):
        """
        Factory for mechs.
        """

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
            raise MechanismException("Cannot create {}, "
                                     "Missing required parameters:\n\t"
                                     "{}".format(self.__class__,
                                                 "\n\t".join(missing_params)))

    def to_c_mech(self):
        """
        Create the Mechanism structure & set the mech type to the passed-in flavor.

        :return: `CK_MECHANISM`
        """
        self.mech = CK_MECHANISM()
        self.mech.mechanism = CK_MECHANISM_TYPE(self.mech_type)
        return self.mech


class IvMechanism(Mechanism):
    """
    Mech class for flavors that require an IV set in the mechanism.
    Will default to `[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]` if no IV is passed in
    """

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: CK_MECHANISM
        """
        super(IvMechanism, self).to_c_mech()
        if self.params is None or 'iv' not in self.params:
            self.params['iv'] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
            LOG.warning("Using static IVs can be insecure! ")
        if len(self.params['iv']) == 0:
            LOG.debug("Setting IV to NULL (using internal)")
            iv_ba = None
            iv_len = 0
        else:
            iv_ba, iv_len = to_byte_array(self.params['iv'])
        self.mech.pParameter = iv_ba
        self.mech.usParameterLen = iv_len
        return self.mech


class Iv16Mechanism(Mechanism):
    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: CK_MECHANISM
        """
        super(Iv16Mechanism, self).to_c_mech()
        if self.params is None or 'iv' not in self.params:
            self.params['iv'] = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]
            LOG.warning("Using static IVs can be insecure! ")
        if len(self.params['iv']) == 0:
            LOG.debug("Setting IV to NULL (using internal)")
            iv_ba = None
            iv_len = 0
        else:
            iv_ba, iv_len = to_byte_array(self.params['iv'])
        self.mech.pParameter = iv_ba
        self.mech.usParameterLen = iv_len
        return self.mech


class RC2Mechanism(Mechanism):
    REQUIRED_PARAMS = ['usEffectiveBits']

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: CK_MECHANISM
        """
        super(RC2Mechanism, self).to_c_mech()
        effective_bits = CK_ULONG(self.params['usEffectiveBits'])
        self.mech.pParameter = cast(pointer(effective_bits), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(effective_bits))
        return self.mech


class RC2CBCMechanism(Mechanism):
    REQUIRED_PARAMS = ['usEffectiveBits', 'iv']

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: CK_MECHANISM
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
    REQUIRED_PARAMS = ['ulWordsize', 'ulRounds']

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: CK_MECHANISM
        """
        super(RC5Mechanism, self).to_c_mech()
        rc5_params = CK_RC5_PARAMS()
        rc5_params.ulWordsize = CK_ULONG(self.params['ulWordsize'])
        rc5_params.ulRounds = CK_ULONG(self.params['ulRounds'])
        self.mech.pParameter = cast(pointer(rc5_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(rc5_params))
        return self.mech


class RC5CBCMechanism(Mechanism):
    REQUIRED_PARAMS = ['ulWordsize', 'ulRounds', 'iv']

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: CK_MECHANISM
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


class AESXTSMechanism(Mechanism):
    REQUIRED_PARAMS = ['cb', 'hTweakKey']

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: CK_MECHANISM
        """
        super(AESXTSMechanism, self).to_c_mech()
        xts_params = CK_AES_XTS_PARAMS()
        xts_params.cb = (CK_BYTE * 16)(*self.params['cb'])
        xts_params.hTweakKey = CK_ULONG(self.params['hTweakKey'])
        self.mech.pParameter = cast(pointer(xts_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(xts_params))
        return self.mech


class RSAPKCSOAEPMechanism(Mechanism):
    REQUIRED_PARAMS = ['hashAlg', 'mgf']

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: CK_MECHANISM
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
    REQUIRED_PARAMS = ['hashAlg', 'mgf']

    def to_c_mech(self):
        """
        Uses default salt length of 8.
        Can be overridden w/ a parameter though.

        :return: CK_MECHANISM
        """
        super(RSAPKCSPSSMechanism, self).to_c_mech()
        c_params = CK_RSA_PKCS_PSS_PARAMS()
        c_params.hashAlg = CK_ULONG(self.params['hashAlg'])
        c_params.mgf = CK_ULONG(self.params['mgf'])
        c_params.usSaltLen = CK_ULONG(self.params.get('usSaltLen', 8))
        self.mech.pParameter = cast(pointer(c_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(c_params))
        return self.mech


class AESGCMMechanism(Mechanism):
    REQUIRED_PARAMS = ['iv', 'AAD', 'ulTagBits']

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: CK_MECHANISM
        """
        super(AESGCMMechanism, self).to_c_mech()
        gcm_params = CK_AES_GCM_PARAMS()
        if len(self.params['iv']) == 0:
            LOG.debug("Setting IV to NULL (using internal)")
            iv_ba = None
            iv_len = 0
        else:
            iv_ba, iv_len = to_byte_array(self.params['iv'])
        gcm_params.pIv = cast(iv_ba, CK_BYTE_PTR)
        gcm_params.ulIvLen = iv_len
        # Assuming 8 bits per entry in IV.
        gcm_params.ulIvBits = CK_ULONG(len(self.params['iv']) * 8)
        aad, aadlen = to_char_array(self.params['AAD'])
        gcm_params.pAAD = cast(aad, CK_BYTE_PTR)
        gcm_params.ulAADLen = aadlen
        gcm_params.ulTagBits = CK_ULONG(self.params['ulTagBits'])
        self.mech.pParameter = cast(pointer(gcm_params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(gcm_params))
        return self.mech


# TODO: xordf mech

class NullMech(Mechanism):
    """
    Class that creates a mechanism from a flavor with null parameters.
    Used mostly for signing mechanisms that really don't need anything else.
    """

    def to_c_mech(self):
        """
        Simply set the pParameter to null pointer.
        :return:
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

    .. warning : Do not use this if the mechanism is defined!
    """

    def to_c_mech(self):
        """
        Attempt to handle generic mechanisms by introspection of the
        structure.
        :return:
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

    CKM_RSA_PKCS_OAEP: RSAPKCSOAEPMechanism,

    CKM_RSA_PKCS_PSS: RSAPKCSPSSMechanism,
    CKM_SHA1_RSA_PKCS_PSS: RSAPKCSPSSMechanism,
    CKM_SHA224_RSA_PKCS_PSS: RSAPKCSPSSMechanism,
    CKM_SHA256_RSA_PKCS_PSS: RSAPKCSPSSMechanism,
    CKM_SHA384_RSA_PKCS_PSS: RSAPKCSPSSMechanism,
    CKM_SHA512_RSA_PKCS_PSS: RSAPKCSPSSMechanism,

    CKM_DES_ECB: NullMech,
}


def get_c_struct_from_mechanism(python_dictionary, params_type_string):
    """Gets a c struct from a python dictionary representing that struct

    :param python_dictionary: The python dictionary representing the C struct,
    see CK_AES_CBC_PAD_EXTRACT_PARAMS_TEMP for an example
    :param params_type_string: A string representing the parameter struct.
    ex. for  CK_AES_CBC_PAD_EXTRACT_PARAMS use the string 'CK_AES_CBC_PAD_EXTRACT_PARAMS'
    :returns: A C struct

    """
    params_type = supported_parameters[params_type_string]
    params = params_type()
    mech = CK_MECHANISM()
    mech.mechanism = python_dictionary['mechanism']
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
        if len(python_dictionary['pBuffer']) == 0:
            params.pBuffer = None
        else:
            params.pBuffer = (CK_BYTE * len(python_dictionary['pBuffer']))()
        # params.pbFileName = 0 #TODO convert byte pointer to serializable type
        pass
    elif params_type == CK_AES_CBC_PAD_INSERT_PARAMS:
        # params.pbFileName =  TODO
        params.pBuffer = cast(create_string_buffer(python_dictionary['pBuffer']), CK_BYTE_PTR)
        params.ulBufferLen = len(python_dictionary['pBuffer'])
        pass
    else:
        raise Exception("Unsupported parameter type, pycryptoki can be extended to make it work")

    return mech


def get_python_dict_from_c_mechanism(c_mechanism, params_type_string):
    """Gets a python dictionary from a c mechanism's struct for serialization
    and easier test case writing

    :param c_mechanism: The c mechanism to convert to a python dictionary
    :param params_type_string: A string representing the parameter struct.
    ex. for  CK_AES_CBC_PAD_EXTRACT_PARAMS use the string 'CK_AES_CBC_PAD_EXTRACT_PARAMS'
    :returns: A python dictionary representing the c struct

    """
    python_dictionary = {}
    python_dictionary['mechanism'] = c_mechanism.mechanism

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
        python_dictionary['pBuffer'] = bufferString
        python_dictionary['pbFileName'] = 0  # TODO
    elif params_type == CK_AES_CBC_PAD_INSERT_PARAMS:
        python_dictionary['pbFileName'] = 0  # TODO
        python_dictionary['pBuffer'] = 0  # TODO
    else:
        raise Exception("Unsupported parameter type, pycryptoki can be extended to make it work")

    return python_dictionary
