"""
Structure & PKCS11-specific definitions.
"""
from ctypes import CFUNCTYPE, Structure

from pycryptoki.cryptoki.c_defs import *
from pycryptoki.cryptoki.helpers import struct_def

# values for unnamed enumeration


CK_MECHANISM_TYPE = CK_ULONG
CK_MECHANISM_TYPE_PTR = POINTER(CK_MECHANISM_TYPE)
CK_USER_TYPE = CK_ULONG
CK_SESSION_HANDLE = CK_ULONG
CK_SESSION_HANDLE_PTR = POINTER(CK_SESSION_HANDLE)

CK_OBJECT_HANDLE = CK_ULONG
CK_OBJECT_HANDLE_PTR = POINTER(CK_OBJECT_HANDLE)
CK_STATE = CK_ULONG


CK_OBJECT_CLASS = CK_ULONG
CK_OBJECT_CLASS_PTR = POINTER(CK_OBJECT_CLASS)
CK_HW_FEATURE_TYPE = CK_ULONG
CK_KEY_TYPE = CK_ULONG
CK_CERTIFICATE_TYPE = CK_ULONG
CK_ATTRIBUTE_TYPE = CK_ULONG


class CK_MECHANISM(Structure):
    pass


class CK_ATTRIBUTE(Structure):
    pass


CK_MECHANISM_PTR = POINTER(CK_MECHANISM)
CK_ATTRIBUTE_PTR = POINTER(CK_ATTRIBUTE)


class CK_AES_GCM_PARAMS(Structure):
    pass


struct_def(
    CK_AES_GCM_PARAMS,
    [
        ("pIv", CK_BYTE_PTR),
        ("ulIvLen", CK_ULONG),
        ("ulIvBits", CK_ULONG),
        ("pAAD", CK_BYTE_PTR),
        ("ulAADLen", CK_ULONG),
        ("ulTagBits", CK_ULONG),
    ],
)

CK_AES_GCM_PARAMS_PTR = CK_AES_GCM_PARAMS


class CK_XOR_BASE_DATA_KDF_PARAMS(Structure):
    pass


CK_EC_KDF_TYPE = CK_ULONG
struct_def(
    CK_XOR_BASE_DATA_KDF_PARAMS,
    [("kdf", CK_EC_KDF_TYPE), ("ulSharedDataLen", CK_ULONG), ("pSharedData", CK_BYTE_PTR)],
)
CK_XOR_BASE_DATA_KDF_PARAMS_PTR = POINTER(CK_XOR_BASE_DATA_KDF_PARAMS)


class CK_AES_XTS_PARAMS(Structure):
    pass


struct_def(CK_AES_XTS_PARAMS, [("hTweakKey", CK_OBJECT_HANDLE), ("cb", CK_BYTE * 16)])
CK_AES_XTS_PARAMS_PTR = POINTER(CK_AES_XTS_PARAMS)
CK_EC_DH_PRIMITIVE = CK_ULONG
CK_EC_ENC_SCHEME = CK_ULONG
CK_EC_MAC_SCHEME = CK_ULONG


class CK_ECIES_PARAMS(Structure):
    pass


struct_def(
    CK_ECIES_PARAMS,
    [
        ("dhPrimitive", CK_EC_DH_PRIMITIVE),
        ("kdf", CK_EC_KDF_TYPE),
        ("ulSharedDataLen1", CK_ULONG),
        ("pSharedData1", CK_BYTE_PTR),
        ("encScheme", CK_EC_ENC_SCHEME),
        ("ulEncKeyLenInBits", CK_ULONG),
        ("macScheme", CK_EC_MAC_SCHEME),
        ("ulMacKeyLenInBits", CK_ULONG),
        ("ulMacLenInBits", CK_ULONG),
        ("ulSharedDataLen2", CK_ULONG),
        ("pSharedData2", CK_BYTE_PTR),
    ],
)
CK_ECIES_PARAMS_PTR = POINTER(CK_ECIES_PARAMS)
CK_KDF_PRF_TYPE = CK_ULONG
CK_KDF_PRF_ENCODING_SCHEME = CK_ULONG


class CK_KDF_PRF_PARAMS(Structure):
    pass


struct_def(
    CK_KDF_PRF_PARAMS,
    [
        ("prfType", CK_KDF_PRF_TYPE),
        ("pLabel", CK_BYTE_PTR),
        ("ulLabelLen", CK_ULONG),
        ("pContext", CK_BYTE_PTR),
        ("ulContextLen", CK_ULONG),
        ("ulCounter", CK_ULONG),
        ("ulEncodingScheme", CK_KDF_PRF_ENCODING_SCHEME),
    ],
)
CK_PRF_KDF_PARAMS = CK_KDF_PRF_PARAMS
CK_KDF_PRF_PARAMS_PTR = POINTER(CK_PRF_KDF_PARAMS)


class CK_AES_CTR_PARAMS(Structure):
    pass


CK_SEED_CTR_PARAMS = CK_AES_CTR_PARAMS
CK_SEED_CTR_PARAMS_PTR = POINTER(CK_SEED_CTR_PARAMS)
CK_ARIA_CTR_PARAMS = CK_AES_CTR_PARAMS
CK_ARIA_CTR_PARAMS_PTR = POINTER(CK_ARIA_CTR_PARAMS)


class CK_DES_CTR_PARAMS(Structure):
    pass


struct_def(CK_DES_CTR_PARAMS, [("ulCounterBits", CK_ULONG), ("cb", CK_BYTE * 8)])
CK_DES_CTR_PARAMS_PTR = POINTER(CK_DES_CTR_PARAMS)
CK_AES_GMAC_PARAMS = CK_AES_GCM_PARAMS
CK_AES_GMAC_PARAMS_PTR = POINTER(CK_AES_GMAC_PARAMS)


class HSM_STATS_PARAMS(Structure):
    pass


struct_def(
    HSM_STATS_PARAMS, [("ulId", CK_ULONG), ("ulHighValue", CK_ULONG), ("ulLowValue", CK_ULONG)]
)


class CA_ROLE_STATE(Structure):
    pass


struct_def(
    CA_ROLE_STATE,
    [
        ("flags", CK_BYTE),
        ("loginAttemptsLeft", CK_BYTE),
        ("primaryAuthMech", CK_BYTE),
        ("secondaryAuthMech", CK_BYTE),
    ],
)


class CK_POLICY_INFO(Structure):
    pass


struct_def(
    CK_POLICY_INFO,
    [
        ("ulId", CK_ULONG),
        ("ulValue", CK_ULONG),
        ("ulOffToOnDestructive", CK_ULONG),
        ("ulOnToOffDestructive", CK_ULONG),
    ],
)
CK_POLICY_INFO_PTR = POINTER(CK_POLICY_INFO)


class CA_MOFN_GENERATION(Structure):
    pass


struct_def(
    CA_MOFN_GENERATION,
    [("ulWeight", CK_ULONG), ("pVector", CK_BYTE_PTR), ("ulVectorLen", CK_ULONG)],
)
CA_MOFN_GENERATION_PTR = POINTER(CA_MOFN_GENERATION)


class CA_MOFN_ACTIVATION(Structure):
    pass


struct_def(CA_MOFN_ACTIVATION, [("pVector", CK_BYTE_PTR), ("ulVectorLen", CK_ULONG)])
CA_MOFN_ACTIVATION_PTR = POINTER(CA_MOFN_ACTIVATION)


class CA_M_OF_N_STATUS(Structure):
    pass


struct_def(
    CA_M_OF_N_STATUS,
    [
        ("ulID", CK_ULONG),
        ("ulM", CK_ULONG),
        ("ulN", CK_ULONG),
        ("ulSecretSize", CK_ULONG),
        ("ulFlag", CK_ULONG),
    ],
)
CA_MOFN_STATUS = CA_M_OF_N_STATUS
CA_MOFN_STATUS_PTR = POINTER(CA_MOFN_STATUS)

CKCA_MODULE_ID = CK_ULONG
CKCA_MODULE_ID_PTR = POINTER(CKCA_MODULE_ID)


class CKCA_MODULE_INFO(Structure):
    pass


class CK_VERSION(Structure):
    pass


struct_def(CK_VERSION, [("major", CK_BYTE), ("minor", CK_BYTE)])
struct_def(
    CKCA_MODULE_INFO,
    [
        ("ulModuleSize", CK_ULONG),
        ("developerName", CK_CHAR * 32),
        ("moduleDescription", CK_CHAR * 32),
        ("moduleVersion", CK_VERSION),
    ],
)
CKCA_MODULE_INFO_PTR = POINTER(CKCA_MODULE_INFO)


class CK_HA_MEMBER(Structure):
    pass


struct_def(CK_HA_MEMBER, [("memberSerial", CK_CHAR * 20), ("memberStatus", CK_RV)])


class CK_HA_STATUS(Structure):
    pass


struct_def(
    CK_HA_STATUS,
    [("groupSerial", CK_CHAR * 20), ("memberList", CK_HA_MEMBER * 32), ("listSize", CK_ULONG)],
)
CK_HA_MEMBER_PTR = POINTER(CK_HA_MEMBER)
CK_HA_STATE_PTR = POINTER(CK_HA_STATUS)
CKA_SIM_AUTH_FORM = CK_ULONG


class CT_Token(Structure):
    pass


struct_def(CT_Token, [])

CT_TokenHndle = POINTER(CT_Token)


class CK_AES_CBC_PAD_EXTRACT_PARAMS(Structure):
    pass


struct_def(
    CK_AES_CBC_PAD_EXTRACT_PARAMS,
    [
        ("ulType", CK_ULONG),
        ("ulHandle", CK_ULONG),
        ("ulDeleteAfterExtract", CK_ULONG),
        ("pBuffer", CK_BYTE_PTR),
        ("pulBufferLen", CK_ULONG_PTR),
        ("ulStorage", CK_ULONG),
        ("pedId", CK_ULONG),
        ("pbFileName", CK_BYTE_PTR),
        ("ctxID", CK_ULONG),
    ],
)
CK_AES_CBC_PAD_EXTRACT_PARAMS_PTR = POINTER(CK_AES_CBC_PAD_EXTRACT_PARAMS)


class CK_AES_CBC_PAD_INSERT_PARAMS(Structure):
    pass


struct_def(
    CK_AES_CBC_PAD_INSERT_PARAMS,
    [
        ("ulStorageType", CK_ULONG),
        ("ulContainerState", CK_ULONG),
        ("pBuffer", CK_BYTE_PTR),
        ("ulBufferLen", CK_ULONG),
        ("pulType", CK_ULONG_PTR),
        ("pulHandle", CK_ULONG_PTR),
        ("ulStorage", CK_ULONG),
        ("pedId", CK_ULONG),
        ("pbFileName", CK_BYTE_PTR),
        ("ctxID", CK_ULONG),
    ],
)
CK_AES_CBC_PAD_INSERT_PARAMS_PTR = POINTER(CK_AES_CBC_PAD_INSERT_PARAMS)


class CK_CLUSTER_STATE(Structure):
    pass


struct_def(CK_CLUSTER_STATE, [("bMembers", CK_BYTE * 32 * 8), ("ulMemberStatus", CK_ULONG * 8)])
CK_CLUSTER_STATE_PTR = POINTER(CK_CLUSTER_STATE)


class CK_LKM_TOKEN_ID_S(Structure):
    pass


struct_def(CK_LKM_TOKEN_ID_S, [("id", CK_BYTE * 20)])
CK_LKM_TOKEN_ID = CK_LKM_TOKEN_ID_S
CK_LKM_TOKEN_ID_PTR = POINTER(CK_LKM_TOKEN_ID)


class CK_UTILIZATION_COUNTER(Structure):
    pass


struct_def(
    CK_UTILIZATION_COUNTER,
    [
        ("ullSerialNumber", CK_ULONGLONG),
        ("label", CK_CHAR * 66),
        ("ulBindId", CK_ULONG),
        ("ulCounterId", CK_ULONG),
        ("ullCount", CK_ULONGLONG),
    ],
)
CK_UTILIZATION_COUNTER_PTR = POINTER(CK_UTILIZATION_COUNTER)

# pka
class CK_KEY_STATUS(Structure):
    pass


struct_def(
    CK_KEY_STATUS,
    [
        ("flags", CK_BYTE),
        ("failedAuthCountLimit", CK_BYTE),
        ("reserved1", CK_BYTE),
        ("reserved2", CK_BYTE),
    ],
)


class CK_FUNCTION_LIST(Structure):
    pass


class CK_INFO(Structure):
    pass


CK_INFO_PTR = POINTER(CK_INFO)


class CK_SLOT_INFO(Structure):
    pass


CK_SLOT_INFO_PTR = POINTER(CK_SLOT_INFO)


class CK_TOKEN_INFO(Structure):
    pass


CK_TOKEN_INFO_PTR = POINTER(CK_TOKEN_INFO)


class CK_MECHANISM_INFO(Structure):
    pass


CK_MECHANISM_INFO_PTR = POINTER(CK_MECHANISM_INFO)


class CK_SESSION_INFO(Structure):
    pass


CK_SESSION_INFO_PTR = POINTER(CK_SESSION_INFO)
CK_VERSION_PTR = POINTER(CK_VERSION)

struct_def(
    CK_INFO,
    [
        ("cryptokiVersion", CK_VERSION),
        ("manufacturerID", CK_UTF8CHAR * 32),
        ("flags", CK_FLAGS),
        ("libraryDescription", CK_UTF8CHAR * 32),
        ("libraryVersion", CK_VERSION),
    ],
)

struct_def(
    CK_SLOT_INFO,
    [
        ("slotDescription", CK_UTF8CHAR * 64),
        ("manufacturerID", CK_UTF8CHAR * 32),
        ("flags", CK_FLAGS),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
    ],
)

struct_def(
    CK_TOKEN_INFO,
    [
        ("label", CK_UTF8CHAR * 32),
        ("manufacturerID", CK_UTF8CHAR * 32),
        ("model", CK_UTF8CHAR * 16),
        ("serialNumber", CK_CHAR * 16),
        ("flags", CK_FLAGS),
        ("usMaxSessionCount", CK_ULONG),
        ("usSessionCount", CK_ULONG),
        ("usMaxRwSessionCount", CK_ULONG),
        ("usRwSessionCount", CK_ULONG),
        ("usMaxPinLen", CK_ULONG),
        ("usMinPinLen", CK_ULONG),
        ("ulTotalPublicMemory", CK_ULONG),
        ("ulFreePublicMemory", CK_ULONG),
        ("ulTotalPrivateMemory", CK_ULONG),
        ("ulFreePrivateMemory", CK_ULONG),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
        ("utcTime", CK_CHAR * 16),
    ],
)


struct_def(
    CK_SESSION_INFO,
    [("slotID", CK_SLOT_ID), ("state", CK_STATE), ("flags", CK_FLAGS), ("usDeviceError", CK_ULONG)],
)
struct_def(
    CK_ATTRIBUTE, [("type", CK_ATTRIBUTE_TYPE), ("pValue", CK_VOID_PTR), ("usValueLen", CK_ULONG)]
)


class CK_DATE(Structure):
    pass


struct_def(CK_DATE, [("year", CK_CHAR * 4), ("month", CK_CHAR * 2), ("day", CK_CHAR * 2)])
struct_def(
    CK_MECHANISM,
    [("mechanism", CK_MECHANISM_TYPE), ("pParameter", CK_VOID_PTR), ("usParameterLen", CK_ULONG)],
)

struct_def(
    CK_MECHANISM_INFO, [("ulMinKeySize", CK_ULONG), ("ulMaxKeySize", CK_ULONG), ("flags", CK_FLAGS)]
)
CK_CREATEMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR_PTR)
CK_DESTROYMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR)
CK_LOCKMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR)
CK_UNLOCKMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR)


class CK_C_INITIALIZE_ARGS(Structure):
    pass


struct_def(
    CK_C_INITIALIZE_ARGS,
    [
        ("CreateMutex", CK_CREATEMUTEX),
        ("DestroyMutex", CK_DESTROYMUTEX),
        ("LockMutex", CK_LOCKMUTEX),
        ("UnlockMutex", CK_UNLOCKMUTEX),
        ("flags", CK_FLAGS),
        ("pReserved", CK_VOID_PTR),
    ],
)
CK_C_INITIALIZE_ARGS_PTR = POINTER(CK_C_INITIALIZE_ARGS)
CK_RSA_PKCS_MGF_TYPE = CK_ULONG
CK_RSA_PKCS_MGF_TYPE_PTR = POINTER(CK_RSA_PKCS_MGF_TYPE)
CK_RSA_PKCS_OAEP_SOURCE_TYPE = CK_ULONG
CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR = POINTER(CK_RSA_PKCS_OAEP_SOURCE_TYPE)


class CK_RSA_PKCS_OAEP_PARAMS(Structure):
    pass


struct_def(
    CK_RSA_PKCS_OAEP_PARAMS,
    [
        ("hashAlg", CK_MECHANISM_TYPE),
        ("mgf", CK_RSA_PKCS_MGF_TYPE),
        ("source", CK_RSA_PKCS_OAEP_SOURCE_TYPE),
        ("pSourceData", CK_VOID_PTR),
        ("ulSourceDataLen", CK_ULONG),
    ],
)
CK_RSA_PKCS_OAEP_PARAMS_PTR = POINTER(CK_RSA_PKCS_OAEP_PARAMS)


class CK_RSA_PKCS_PSS_PARAMS(Structure):
    pass


struct_def(
    CK_RSA_PKCS_PSS_PARAMS,
    [("hashAlg", CK_MECHANISM_TYPE), ("mgf", CK_RSA_PKCS_MGF_TYPE), ("usSaltLen", CK_ULONG)],
)
CK_RSA_PKCS_PSS_PARAMS_PTR = POINTER(CK_RSA_PKCS_PSS_PARAMS)


class CK_ECDH1_DERIVE_PARAMS(Structure):
    pass


struct_def(
    CK_ECDH1_DERIVE_PARAMS,
    [
        ("kdf", CK_EC_KDF_TYPE),
        ("ulSharedDataLen", CK_ULONG),
        ("pSharedData", CK_BYTE_PTR),
        ("ulPublicDataLen", CK_ULONG),
        ("pPublicData", CK_BYTE_PTR),
    ],
)
CK_ECDH1_DERIVE_PARAMS_PTR = POINTER(CK_ECDH1_DERIVE_PARAMS)


class CK_ECDH2_DERIVE_PARAMS(Structure):
    pass


struct_def(
    CK_ECDH2_DERIVE_PARAMS,
    [
        ("kdf", CK_EC_KDF_TYPE),
        ("ulSharedDataLen", CK_ULONG),
        ("pSharedData", CK_BYTE_PTR),
        ("ulPublicDataLen", CK_ULONG),
        ("pPublicData", CK_BYTE_PTR),
        ("ulPrivateDataLen", CK_ULONG),
        ("hPrivateData", CK_OBJECT_HANDLE),
        ("ulPublicDataLen2", CK_ULONG),
        ("pPublicData2", CK_BYTE_PTR),
    ],
)
CK_ECDH2_DERIVE_PARAMS_PTR = POINTER(CK_ECDH2_DERIVE_PARAMS)


class CK_ECMQV_DERIVE_PARAMS(Structure):
    pass


struct_def(
    CK_ECMQV_DERIVE_PARAMS,
    [
        ("kdf", CK_EC_KDF_TYPE),
        ("ulSharedDataLen", CK_ULONG),
        ("pSharedData", CK_BYTE_PTR),
        ("ulPublicDataLen", CK_ULONG),
        ("pPublicData", CK_BYTE_PTR),
        ("ulPrivateDataLen", CK_ULONG),
        ("hPrivateData", CK_OBJECT_HANDLE),
        ("ulPublicDataLen2", CK_ULONG),
        ("pPublicData2", CK_BYTE_PTR),
        ("publicKey", CK_OBJECT_HANDLE),
    ],
)
CK_ECMQV_DERIVE_PARAMS_PTR = POINTER(CK_ECMQV_DERIVE_PARAMS)
CK_X9_42_DH_KDF_TYPE = CK_ULONG
CK_X9_42_DH_KDF_TYPE_PTR = POINTER(CK_X9_42_DH_KDF_TYPE)


class CK_X9_42_DH1_DERIVE_PARAMS(Structure):
    pass


struct_def(
    CK_X9_42_DH1_DERIVE_PARAMS,
    [
        ("kdf", CK_X9_42_DH_KDF_TYPE),
        ("ulOtherInfoLen", CK_ULONG),
        ("pOtherInfo", CK_BYTE_PTR),
        ("ulPublicDataLen", CK_ULONG),
        ("pPublicData", CK_BYTE_PTR),
    ],
)
CK_X9_42_DH1_DERIVE_PARAMS_PTR = POINTER(CK_X9_42_DH1_DERIVE_PARAMS)


class CK_X9_42_DH2_DERIVE_PARAMS(Structure):
    pass


struct_def(
    CK_X9_42_DH2_DERIVE_PARAMS,
    [
        ("kdf", CK_X9_42_DH_KDF_TYPE),
        ("ulOtherInfoLen", CK_ULONG),
        ("pOtherInfo", CK_BYTE_PTR),
        ("ulPublicDataLen", CK_ULONG),
        ("pPublicData", CK_BYTE_PTR),
        ("ulPrivateDataLen", CK_ULONG),
        ("hPrivateData", CK_OBJECT_HANDLE),
        ("ulPublicDataLen2", CK_ULONG),
        ("pPublicData2", CK_BYTE_PTR),
    ],
)
CK_X9_42_DH2_DERIVE_PARAMS_PTR = POINTER(CK_X9_42_DH2_DERIVE_PARAMS)


class CK_X9_42_MQV_DERIVE_PARAMS(Structure):
    pass


struct_def(
    CK_X9_42_MQV_DERIVE_PARAMS,
    [
        ("kdf", CK_X9_42_DH_KDF_TYPE),
        ("ulOtherInfoLen", CK_ULONG),
        ("pOtherInfo", CK_BYTE_PTR),
        ("ulPublicDataLen", CK_ULONG),
        ("pPublicData", CK_BYTE_PTR),
        ("ulPrivateDataLen", CK_ULONG),
        ("hPrivateData", CK_OBJECT_HANDLE),
        ("ulPublicDataLen2", CK_ULONG),
        ("pPublicData2", CK_BYTE_PTR),
        ("publicKey", CK_OBJECT_HANDLE),
    ],
)
CK_X9_42_MQV_DERIVE_PARAMS_PTR = POINTER(CK_X9_42_MQV_DERIVE_PARAMS)


class CK_KEA_DERIVE_PARAMS(Structure):
    pass


struct_def(
    CK_KEA_DERIVE_PARAMS,
    [
        ("isSender", CK_BBOOL),
        ("ulRandomLen", CK_ULONG),
        ("pRandomA", CK_BYTE_PTR),
        ("pRandomB", CK_BYTE_PTR),
        ("ulPublicDataLen", CK_ULONG),
        ("pPublicData", CK_BYTE_PTR),
    ],
)
CK_KEA_DERIVE_PARAMS_PTR = POINTER(CK_KEA_DERIVE_PARAMS)
CK_RC2_PARAMS = CK_ULONG
CK_RC2_PARAMS_PTR = POINTER(CK_RC2_PARAMS)


class CK_RC2_CBC_PARAMS(Structure):
    pass


struct_def(CK_RC2_CBC_PARAMS, [("usEffectiveBits", CK_ULONG), ("iv", CK_BYTE * 8)])
CK_RC2_CBC_PARAMS_PTR = POINTER(CK_RC2_CBC_PARAMS)


class CK_RC2_MAC_GENERAL_PARAMS(Structure):
    pass


struct_def(CK_RC2_MAC_GENERAL_PARAMS, [("usEffectiveBits", CK_ULONG), ("ulMacLength", CK_ULONG)])
CK_RC2_MAC_GENERAL_PARAMS_PTR = POINTER(CK_RC2_MAC_GENERAL_PARAMS)


class CK_RC5_PARAMS(Structure):
    pass


struct_def(CK_RC5_PARAMS, [("ulWordsize", CK_ULONG), ("ulRounds", CK_ULONG)])
CK_RC5_PARAMS_PTR = POINTER(CK_RC5_PARAMS)


class CK_RC5_CBC_PARAMS(Structure):
    pass


struct_def(
    CK_RC5_CBC_PARAMS,
    [("ulWordsize", CK_ULONG), ("ulRounds", CK_ULONG), ("pIv", CK_BYTE_PTR), ("ulIvLen", CK_ULONG)],
)
CK_RC5_CBC_PARAMS_PTR = POINTER(CK_RC5_CBC_PARAMS)


class CK_RC5_MAC_GENERAL_PARAMS(Structure):
    pass


struct_def(
    CK_RC5_MAC_GENERAL_PARAMS,
    [("ulWordsize", CK_ULONG), ("ulRounds", CK_ULONG), ("ulMacLength", CK_ULONG)],
)
CK_RC5_MAC_GENERAL_PARAMS_PTR = POINTER(CK_RC5_MAC_GENERAL_PARAMS)
CK_MAC_GENERAL_PARAMS = CK_ULONG
CK_MAC_GENERAL_PARAMS_PTR = POINTER(CK_MAC_GENERAL_PARAMS)


class CK_DES_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass


struct_def(
    CK_DES_CBC_ENCRYPT_DATA_PARAMS,
    [("iv", CK_BYTE * 8), ("pData", CK_BYTE_PTR), ("length", CK_ULONG)],
)
CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_DES_CBC_ENCRYPT_DATA_PARAMS)


class CK_AES_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass


struct_def(
    CK_AES_CBC_ENCRYPT_DATA_PARAMS,
    [("iv", CK_BYTE * 16), ("pData", CK_BYTE_PTR), ("length", CK_ULONG)],
)
CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_AES_CBC_ENCRYPT_DATA_PARAMS)


class CK_SKIPJACK_PRIVATE_WRAP_PARAMS(Structure):
    pass


struct_def(
    CK_SKIPJACK_PRIVATE_WRAP_PARAMS,
    [
        ("usPasswordLen", CK_ULONG),
        ("pPassword", CK_BYTE_PTR),
        ("ulPublicDataLen", CK_ULONG),
        ("pPublicData", CK_BYTE_PTR),
        ("ulPAndGLen", CK_ULONG),
        ("ulQLen", CK_ULONG),
        ("ulRandomLen", CK_ULONG),
        ("pRandomA", CK_BYTE_PTR),
        ("pPrimeP", CK_BYTE_PTR),
        ("pBaseG", CK_BYTE_PTR),
        ("pSubprimeQ", CK_BYTE_PTR),
    ],
)
CK_SKIPJACK_PRIVATE_WRAP_PTR = POINTER(CK_SKIPJACK_PRIVATE_WRAP_PARAMS)


class CK_SKIPJACK_RELAYX_PARAMS(Structure):
    pass


struct_def(
    CK_SKIPJACK_RELAYX_PARAMS,
    [
        ("ulOldWrappedXLen", CK_ULONG),
        ("pOldWrappedX", CK_BYTE_PTR),
        ("ulOldPasswordLen", CK_ULONG),
        ("pOldPassword", CK_BYTE_PTR),
        ("ulOldPublicDataLen", CK_ULONG),
        ("pOldPublicData", CK_BYTE_PTR),
        ("ulOldRandomLen", CK_ULONG),
        ("pOldRandomA", CK_BYTE_PTR),
        ("ulNewPasswordLen", CK_ULONG),
        ("pNewPassword", CK_BYTE_PTR),
        ("ulNewPublicDataLen", CK_ULONG),
        ("pNewPublicData", CK_BYTE_PTR),
        ("ulNewRandomLen", CK_ULONG),
        ("pNewRandomA", CK_BYTE_PTR),
    ],
)
CK_SKIPJACK_RELAYX_PARAMS_PTR = POINTER(CK_SKIPJACK_RELAYX_PARAMS)


class CK_PBE_PARAMS(Structure):
    pass


struct_def(
    CK_PBE_PARAMS,
    [
        ("pInitVector", CK_BYTE_PTR),
        ("pPassword", CK_UTF8CHAR_PTR),
        ("usPasswordLen", CK_ULONG),
        ("pSalt", CK_BYTE_PTR),
        ("usSaltLen", CK_ULONG),
        ("usIteration", CK_ULONG),
    ],
)
CK_PBE_PARAMS_PTR = POINTER(CK_PBE_PARAMS)


class CK_KEY_WRAP_SET_OAEP_PARAMS(Structure):
    pass


struct_def(
    CK_KEY_WRAP_SET_OAEP_PARAMS, [("bBC", CK_BYTE), ("pX", CK_BYTE_PTR), ("ulXLen", CK_ULONG)]
)
CK_KEY_WRAP_SET_OAEP_PARAMS_PTR = POINTER(CK_KEY_WRAP_SET_OAEP_PARAMS)


class CK_SSL3_RANDOM_DATA(Structure):
    pass


struct_def(
    CK_SSL3_RANDOM_DATA,
    [
        ("pClientRandom", CK_BYTE_PTR),
        ("ulClientRandomLen", CK_ULONG),
        ("pServerRandom", CK_BYTE_PTR),
        ("ulServerRandomLen", CK_ULONG),
    ],
)


class CK_SSL3_MASTER_KEY_DERIVE_PARAMS(Structure):
    pass


struct_def(
    CK_SSL3_MASTER_KEY_DERIVE_PARAMS,
    [("RandomInfo", CK_SSL3_RANDOM_DATA), ("pVersion", CK_VERSION_PTR)],
)
CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR = POINTER(CK_SSL3_MASTER_KEY_DERIVE_PARAMS)


class CK_SSL3_KEY_MAT_OUT(Structure):
    pass


struct_def(
    CK_SSL3_KEY_MAT_OUT,
    [
        ("hClientMacSecret", CK_OBJECT_HANDLE),
        ("hServerMacSecret", CK_OBJECT_HANDLE),
        ("hClientKey", CK_OBJECT_HANDLE),
        ("hServerKey", CK_OBJECT_HANDLE),
        ("pIVClient", CK_BYTE_PTR),
        ("pIVServer", CK_BYTE_PTR),
    ],
)
CK_SSL3_KEY_MAT_OUT_PTR = POINTER(CK_SSL3_KEY_MAT_OUT)


class CK_SSL3_KEY_MAT_PARAMS(Structure):
    pass


struct_def(
    CK_SSL3_KEY_MAT_PARAMS,
    [
        ("ulMacSizeInBits", CK_ULONG),
        ("ulKeySizeInBits", CK_ULONG),
        ("ulIVSizeInBits", CK_ULONG),
        ("bIsExport", CK_BBOOL),
        ("RandomInfo", CK_SSL3_RANDOM_DATA),
        ("pReturnedKeyMaterial", CK_SSL3_KEY_MAT_OUT_PTR),
    ],
)
CK_SSL3_KEY_MAT_PARAMS_PTR = POINTER(CK_SSL3_KEY_MAT_PARAMS)


class CK_TLS_PRF_PARAMS(Structure):
    pass


struct_def(
    CK_TLS_PRF_PARAMS,
    [
        ("pSeed", CK_BYTE_PTR),
        ("ulSeedLen", CK_ULONG),
        ("pLabel", CK_BYTE_PTR),
        ("ulLabelLen", CK_ULONG),
        ("pOutput", CK_BYTE_PTR),
        ("pulOutputLen", CK_ULONG_PTR),
    ],
)
CK_TLS_PRF_PARAMS_PTR = POINTER(CK_TLS_PRF_PARAMS)


class CK_WTLS_RANDOM_DATA(Structure):
    pass


struct_def(
    CK_WTLS_RANDOM_DATA,
    [
        ("pClientRandom", CK_BYTE_PTR),
        ("ulClientRandomLen", CK_ULONG),
        ("pServerRandom", CK_BYTE_PTR),
        ("ulServerRandomLen", CK_ULONG),
    ],
)
CK_WTLS_RANDOM_DATA_PTR = POINTER(CK_WTLS_RANDOM_DATA)


class CK_WTLS_MASTER_KEY_DERIVE_PARAMS(Structure):
    pass


struct_def(
    CK_WTLS_MASTER_KEY_DERIVE_PARAMS,
    [
        ("DigestMechanism", CK_MECHANISM_TYPE),
        ("RandomInfo", CK_WTLS_RANDOM_DATA),
        ("pVersion", CK_BYTE_PTR),
    ],
)
CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR = POINTER(CK_WTLS_MASTER_KEY_DERIVE_PARAMS)


class CK_WTLS_PRF_PARAMS(Structure):
    pass


struct_def(
    CK_WTLS_PRF_PARAMS,
    [
        ("DigestMechanism", CK_MECHANISM_TYPE),
        ("pSeed", CK_BYTE_PTR),
        ("ulSeedLen", CK_ULONG),
        ("pLabel", CK_BYTE_PTR),
        ("ulLabelLen", CK_ULONG),
        ("pOutput", CK_BYTE_PTR),
        ("pulOutputLen", CK_ULONG_PTR),
    ],
)
CK_WTLS_PRF_PARAMS_PTR = POINTER(CK_WTLS_PRF_PARAMS)


class CK_WTLS_KEY_MAT_OUT(Structure):
    pass


struct_def(
    CK_WTLS_KEY_MAT_OUT,
    [("hMacSecret", CK_OBJECT_HANDLE), ("hKey", CK_OBJECT_HANDLE), ("pIV", CK_BYTE_PTR)],
)
CK_WTLS_KEY_MAT_OUT_PTR = POINTER(CK_WTLS_KEY_MAT_OUT)


class CK_WTLS_KEY_MAT_PARAMS(Structure):
    pass


struct_def(
    CK_WTLS_KEY_MAT_PARAMS,
    [
        ("DigestMechanism", CK_MECHANISM_TYPE),
        ("ulMacSizeInBits", CK_ULONG),
        ("ulKeySizeInBits", CK_ULONG),
        ("ulIVSizeInBits", CK_ULONG),
        ("ulSequenceNumber", CK_ULONG),
        ("bIsExport", CK_BBOOL),
        ("RandomInfo", CK_WTLS_RANDOM_DATA),
        ("pReturnedKeyMaterial", CK_WTLS_KEY_MAT_OUT_PTR),
    ],
)
CK_WTLS_KEY_MAT_PARAMS_PTR = POINTER(CK_WTLS_KEY_MAT_PARAMS)


class CK_CMS_SIG_PARAMS(Structure):
    pass


struct_def(
    CK_CMS_SIG_PARAMS,
    [
        ("certificateHandle", CK_OBJECT_HANDLE),
        ("pSigningMechanism", CK_MECHANISM_PTR),
        ("pDigestMechanism", CK_MECHANISM_PTR),
        ("pContentType", CK_UTF8CHAR_PTR),
        ("pRequestedAttributes", CK_BYTE_PTR),
        ("ulRequestedAttributesLen", CK_ULONG),
        ("pRequiredAttributes", CK_BYTE_PTR),
        ("ulRequiredAttributesLen", CK_ULONG),
    ],
)
CK_CMS_SIG_PARAMS_PTR = POINTER(CK_CMS_SIG_PARAMS)


class CK_KEY_DERIVATION_STRING_DATA(Structure):
    pass


struct_def(CK_KEY_DERIVATION_STRING_DATA, [("pData", CK_BYTE_PTR), ("ulLen", CK_ULONG)])
CK_KEY_DERIVATION_STRING_DATA_PTR = POINTER(CK_KEY_DERIVATION_STRING_DATA)
CK_EXTRACT_PARAMS = CK_ULONG
CK_EXTRACT_PARAMS_PTR = POINTER(CK_EXTRACT_PARAMS)
CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = CK_ULONG
CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR = POINTER(CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE)
CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE = CK_ULONG
CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR = POINTER(CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE)


class CK_PKCS5_PBKD2_PARAMS(Structure):
    pass


struct_def(
    CK_PKCS5_PBKD2_PARAMS,
    [
        ("saltSource", CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE),
        ("pSaltSourceData", CK_VOID_PTR),
        ("ulSaltSourceDataLen", CK_ULONG),
        ("iterations", CK_ULONG),
        ("prf", CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE),
        ("pPrfData", CK_VOID_PTR),
        ("ulPrfDataLen", CK_ULONG),
        ("pPassword", CK_UTF8CHAR_PTR),
        ("usPasswordLen", CK_ULONG),
    ],
)
CK_PKCS5_PBKD2_PARAMS_PTR = POINTER(CK_PKCS5_PBKD2_PARAMS)
CK_OTP_PARAM_TYPE = CK_ULONG
CK_PARAM_TYPE = CK_OTP_PARAM_TYPE


class CK_OTP_PARAM(Structure):
    pass


struct_def(
    CK_OTP_PARAM, [("type", CK_OTP_PARAM_TYPE), ("pValue", CK_VOID_PTR), ("usValueLen", CK_ULONG)]
)
CK_OTP_PARAM_PTR = POINTER(CK_OTP_PARAM)


class CK_OTP_PARAMS(Structure):
    pass


struct_def(CK_OTP_PARAMS, [("pParams", CK_OTP_PARAM_PTR), ("ulCount", CK_ULONG)])
CK_OTP_PARAMS_PTR = POINTER(CK_OTP_PARAMS)


class CK_OTP_SIGNATURE_INFO(Structure):
    pass


struct_def(CK_OTP_SIGNATURE_INFO, [("pParams", CK_OTP_PARAM_PTR), ("ulCount", CK_ULONG)])
CK_OTP_SIGNATURE_INFO_PTR = POINTER(CK_OTP_SIGNATURE_INFO)


class CK_KIP_PARAMS(Structure):
    pass


struct_def(
    CK_KIP_PARAMS,
    [
        ("pMechanism", CK_MECHANISM_PTR),
        ("hKey", CK_OBJECT_HANDLE),
        ("pSeed", CK_BYTE_PTR),
        ("ulSeedLen", CK_ULONG),
    ],
)
CK_KIP_PARAMS_PTR = POINTER(CK_KIP_PARAMS)


struct_def(CK_AES_CTR_PARAMS, [("ulCounterBits", CK_ULONG), ("cb", CK_BYTE * 16)])
CK_AES_CTR_PARAMS_PTR = POINTER(CK_AES_CTR_PARAMS)


class CK_CAMELLIA_CTR_PARAMS(Structure):
    pass


struct_def(CK_CAMELLIA_CTR_PARAMS, [("ulCounterBits", CK_ULONG), ("cb", CK_BYTE * 16)])
CK_CAMELLIA_CTR_PARAMS_PTR = POINTER(CK_CAMELLIA_CTR_PARAMS)


class CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass


struct_def(
    CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS,
    [("iv", CK_BYTE * 16), ("pData", CK_BYTE_PTR), ("length", CK_ULONG)],
)
CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS)


class CK_ARIA_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass


struct_def(
    CK_ARIA_CBC_ENCRYPT_DATA_PARAMS,
    [("iv", CK_BYTE * 16), ("pData", CK_BYTE_PTR), ("length", CK_ULONG)],
)
CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS)


class CK_APPLICATION_ID(Structure):
    def __init__(self, aid=None):
        if aid is None:
            aid = []
        self.id = (CK_BYTE * 16)(*aid)


struct_def(CK_APPLICATION_ID, [("id", CK_BYTE * 16)])


class CK_CPV4_EXTRACT_PARAMS(Structure):
    pass


struct_def(
    CK_CPV4_EXTRACT_PARAMS,
    [
        ("inputLength", CK_ULONG),
        ("input", CK_BYTE_PTR),
        ("sessionOuidLen", CK_ULONG),
        ("sessionOuid", CK_BYTE_PTR),
        ("extractionFlags", CK_ULONG),
        ("numberOfObjects", CK_ULONG),
        ("objectType", CK_ULONG_PTR),
        ("objectHandle", CK_ULONG_PTR),
        ("result", CK_ULONG_PTR),
        ("keyBlobLen", CK_ULONG_PTR),
        ("keyBlob", POINTER(CK_BYTE_PTR)),
    ],
)
CK_CPV4_EXTRACT_PARAMS_PTR = POINTER(CK_CPV4_EXTRACT_PARAMS)


class CK_CPV4_INSERT_PARAMS(Structure):
    pass


struct_def(
    CK_CPV4_INSERT_PARAMS,
    [
        ("inputLength", CK_ULONG),
        ("input", CK_BYTE_PTR),
        ("sessionOuidLen", CK_ULONG),
        ("sessionOuid", CK_BYTE_PTR),
        ("insertionFlags", CK_ULONG),
        ("numberOfObjects", CK_ULONG),
        ("objectType", CK_ULONG_PTR),
        ("storageType", CK_ULONG_PTR),
        ("keyBlobLen", CK_ULONG_PTR),
        ("keyBlob", POINTER(CK_BYTE_PTR)),
        ("result", CK_ULONG_PTR),
        ("objectHandle", CK_ULONG_PTR),
    ],
)
CK_CPV4_INSERT_PTR = POINTER(CK_CPV4_INSERT_PARAMS)


class CK_EDDSA_PARAMS(Structure):
    pass


struct_def(
    CK_EDDSA_PARAMS,
    [("phFlag", CK_BBOOL), ("ulContextDataLen", CK_ULONG), ("pContextData", CK_BYTE_PTR)],
)
CK_EDDSA_PARAMS_PTR = POINTER(CK_EDDSA_PARAMS)


class CK_BIP32_MASTER_DERIVE_PARAMS(Structure):
    pass


struct_def(
    CK_BIP32_MASTER_DERIVE_PARAMS,
    [
        ("pPublicKeyTemplate", CK_ATTRIBUTE_PTR),
        ("ulPublicKeyAttributeCount", CK_ULONG),
        ("pPrivateKeyTemplate", CK_ATTRIBUTE_PTR),
        ("ulPrivateKeyAttributeCount", CK_ULONG),
        ("hPublicKey", CK_OBJECT_HANDLE),
        ("hPrivateKey", CK_OBJECT_HANDLE),
    ],
)

CK_BIP32_MASTER_DERIVE_PARAMS_PTR = POINTER(CK_BIP32_MASTER_DERIVE_PARAMS)


class CK_BIP32_CHILD_DERIVE_PARAMS(Structure):
    pass


struct_def(
    CK_BIP32_CHILD_DERIVE_PARAMS,
    [
        ("pPublicKeyTemplate", CK_ATTRIBUTE_PTR),
        ("ulPublicKeyAttributeCount", CK_ULONG),
        ("pPrivateKeyTemplate", CK_ATTRIBUTE_PTR),
        ("ulPrivateKeyAttributeCount", CK_ULONG),
        ("pulPath", CK_ULONG_PTR),
        ("ulPathLen", CK_ULONG),
        ("hPublicKey", CK_OBJECT_HANDLE),
        ("hPrivateKey", CK_OBJECT_HANDLE),
        ("ulPathErrorIndex", CK_ULONG),
    ],
)
CK_BIP32_CHILD_DERIVE_PARAMS_PTR = POINTER(CK_BIP32_CHILD_DERIVE_PARAMS)


class CK_SHAKE_PARAMS(Structure):
    pass


struct_def(CK_SHAKE_PARAMS, [("ulOutputLen", CK_ULONG)])
CK_SHAKE_PARAMS_PTR = POINTER(CK_SHAKE_PARAMS)


class CK_SHA_HMAC_GENERAL_PARAMS(Structure):
    pass


struct_def(CK_SHA_HMAC_GENERAL_PARAMS, [("ulOutputLen", CK_ULONG)])
CK_SHA_HMAC_GENERAL_PARAMS_PTR = POINTER(CK_SHA_HMAC_GENERAL_PARAMS)
