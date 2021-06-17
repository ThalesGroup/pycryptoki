"""
PKCS11 & CA Extension ctypes function bindings.

Note to maintainers: This is where new functions added to the libCryptoki C API should
be defined.
"""
from pycryptoki.cryptoki._ck_func_list import (
    CK_SFNT_CA_FUNCTION_LIST_PTR_PTR,
    CK_NOTIFY,
    CK_FUNCTION_LIST_PTR_PTR,
)
from pycryptoki.cryptoki.ck_defs import *
from pycryptoki.cryptoki.helpers import make_late_binding_function


CA_GetFunctionList = make_late_binding_function(
    "CA_GetFunctionList", [CK_SFNT_CA_FUNCTION_LIST_PTR_PTR]
)
CA_WaitForSlotEvent = make_late_binding_function(
    "CA_WaitForSlotEvent", [CK_FLAGS, POINTER(CK_ULONG), CK_SLOT_ID_PTR, CK_VOID_PTR]
)
CA_InitIndirectToken = make_late_binding_function(
    "CA_InitIndirectToken", [CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR, CK_SESSION_HANDLE]
)
CA_InitIndirectPIN = make_late_binding_function(
    "CA_InitIndirectPIN", [CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG, CK_SESSION_HANDLE]
)
CA_ResetPIN = make_late_binding_function("CA_ResetPIN", [CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG])
CA_InitRolePIN = make_late_binding_function(
    "CA_InitRolePIN", [CK_SESSION_HANDLE, CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG]
)
CA_InitSlotRolePIN = make_late_binding_function(
    "CA_InitSlotRolePIN", [CK_SESSION_HANDLE, CK_SLOT_ID, CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG]
)
CA_RoleStateGet = make_late_binding_function(
    "CA_RoleStateGet", [CK_SLOT_ID, CK_USER_TYPE, POINTER(CA_ROLE_STATE)]
)
CA_CreateLoginChallenge = make_late_binding_function(
    "CA_CreateLoginChallenge",
    [CK_SESSION_HANDLE, CK_USER_TYPE, CK_ULONG, CK_CHAR_PTR, CK_ULONG_PTR, CK_CHAR_PTR],
)
CA_CreateContainerLoginChallenge = make_late_binding_function(
    "CA_CreateContainerLoginChallenge",
    [CK_SESSION_HANDLE, CK_SLOT_ID, CK_USER_TYPE, CK_ULONG, CK_CHAR_PTR, CK_ULONG_PTR, CK_CHAR_PTR],
)
CA_Deactivate = make_late_binding_function("CA_Deactivate", [CK_SLOT_ID, CK_USER_TYPE])
CA_FindAdminSlotForSlot = make_late_binding_function(
    "CA_FindAdminSlotForSlot", [CK_SLOT_ID, POINTER(CK_SLOT_ID), POINTER(CK_SLOT_ID)]
)
CA_TokenInsert = make_late_binding_function(
    "CA_TokenInsert", [CK_SESSION_HANDLE, CT_TokenHndle, CK_SLOT_ID]
)
CA_TokenInsertNoAuth = make_late_binding_function(
    "CA_TokenInsertNoAuth", [CT_TokenHndle, CK_SLOT_ID]
)
CA_TokenZeroize = make_late_binding_function(
    "CA_TokenZeroize", [CK_SESSION_HANDLE, CK_SLOT_ID, CK_FLAGS]
)
CA_TokenDelete = make_late_binding_function("CA_TokenDelete", [CK_SESSION_HANDLE, CK_SLOT_ID])
CA_OpenSession = make_late_binding_function(
    "CA_OpenSession",
    [CK_SLOT_ID, CK_ULONG, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR],
)
CA_OpenSessionWithAppID = make_late_binding_function(
    "CA_OpenSessionWithAppID",
    [CK_SLOT_ID, CK_FLAGS, CK_ULONG, CK_ULONG, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR],
)
CA_IndirectLogin = make_late_binding_function(
    "CA_IndirectLogin", [CK_SESSION_HANDLE, CK_USER_TYPE, CK_SESSION_HANDLE]
)
CA_InitializeRemotePEDVector = make_late_binding_function(
    "CA_InitializeRemotePEDVector", [CK_SESSION_HANDLE]
)
CA_DeleteRemotePEDVector = make_late_binding_function(
    "CA_DeleteRemotePEDVector", [CK_SESSION_HANDLE]
)
CA_GetRemotePEDVectorStatus = make_late_binding_function(
    "CA_GetRemotePEDVectorStatus", [CK_SLOT_ID, CK_ULONG_PTR]
)
CA_ConfigureRemotePED = make_late_binding_function(
    "CA_ConfigureRemotePED", [CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_ULONG_PTR]
)
CA_DismantleRemotePED = make_late_binding_function("CA_DismantleRemotePED", [CK_SLOT_ID, CK_ULONG])
CA_Restart = make_late_binding_function("CA_Restart", [CK_SLOT_ID])
CA_RestartForContainer = make_late_binding_function(
    "CA_RestartForContainer", [CK_SLOT_ID, CK_ULONG]
)
CA_CloseApplicationID = make_late_binding_function(
    "CA_CloseApplicationID", [CK_SLOT_ID, CK_ULONG, CK_ULONG]
)
CA_CloseApplicationIDForContainer = make_late_binding_function(
    "CA_CloseApplicationIDForContainer", [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG]
)
CA_OpenApplicationID = make_late_binding_function(
    "CA_OpenApplicationID", [CK_SLOT_ID, CK_ULONG, CK_ULONG]
)
CA_OpenApplicationIDForContainer = make_late_binding_function(
    "CA_OpenApplicationIDForContainer", [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG]
)
CA_SetApplicationID = make_late_binding_function("CA_SetApplicationID", [CK_ULONG, CK_ULONG])
CA_DescribeUtilizationBinId = make_late_binding_function(
    "CA_DescribeUtilizationBinId", [CK_ULONG, CK_CHAR_PTR]
)
CA_ReadUtilizationMetrics = make_late_binding_function(
    "CA_ReadUtilizationMetrics", [CK_SESSION_HANDLE]
)
CA_ReadAndResetUtilizationMetrics = make_late_binding_function(
    "CA_ReadAndResetUtilizationMetrics", [CK_SESSION_HANDLE]
)
CA_ReadAllUtilizationCounters = make_late_binding_function(
    "CA_ReadAllUtilizationCounters", [CK_SESSION_HANDLE, CK_UTILIZATION_COUNTER_PTR, CK_ULONG_PTR]
)
# pka
CA_SetAuthorizationData = make_late_binding_function(
    "CA_SetAuthorizationData",
    [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG],
)
CA_ResetAuthorizationData = make_late_binding_function(
    "CA_ResetAuthorizationData", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG]
)
CA_AuthorizeKey = make_late_binding_function(
    "CA_AuthorizeKey", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG]
)
CA_AssignKey = make_late_binding_function("CA_AssignKey", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE])
CA_IncrementFailedAuthCount = make_late_binding_function(
    "CA_IncrementFailedAuthCount", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
)
CA_SessionCancel = make_late_binding_function("CA_SessionCancel", [CK_SESSION_HANDLE, CK_FLAGS])
CA_ManualKCV = make_late_binding_function("CA_ManualKCV", [CK_SESSION_HANDLE])
CA_SetLKCV = make_late_binding_function("CA_SetLKCV", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG])
CA_SetKCV = make_late_binding_function("CA_SetKCV", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG])
CA_SetRDK = make_late_binding_function("CA_SetRDK", [CK_SESSION_HANDLE, POINTER(CK_BYTE), CK_ULONG])
CA_SetCloningDomain = make_late_binding_function("CA_SetCloningDomain", [CK_BYTE_PTR, CK_ULONG])
CA_ClonePrivateKey = make_late_binding_function(
    "CA_ClonePrivateKey",
    [CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR],
)
CA_CloneObject = make_late_binding_function(
    "CA_CloneObject",
    [CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR],
)
CA_GenerateCloningKEV = make_late_binding_function(
    "CA_GenerateCloningKEV", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_CloneAsTargetInit = make_late_binding_function(
    "CA_CloneAsTargetInit",
    [
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BBOOL,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ],
)
CA_CloneAsSource = make_late_binding_function(
    "CA_CloneAsSource",
    [
        CK_SESSION_HANDLE,
        CK_ULONG,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BBOOL,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ],
)
CA_CloneAsTarget = make_late_binding_function(
    "CA_CloneAsTarget",
    [
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_BBOOL,
        CK_OBJECT_HANDLE_PTR,
    ],
)
CA_SetMofN = make_late_binding_function("CA_SetMofN", [CK_BBOOL])
CA_GenerateMofN = make_late_binding_function(
    "CA_GenerateMofN",
    [CK_SESSION_HANDLE, CK_ULONG, CA_MOFN_GENERATION_PTR, CK_ULONG, CK_ULONG, CK_VOID_PTR],
)
CA_GenerateCloneableMofN = make_late_binding_function(
    "CA_GenerateCloneableMofN",
    [CK_SESSION_HANDLE, CK_ULONG, CA_MOFN_GENERATION_PTR, CK_ULONG, CK_ULONG, CK_VOID_PTR],
)
CA_ModifyMofN = make_late_binding_function(
    "CA_ModifyMofN",
    [CK_SESSION_HANDLE, CK_ULONG, CA_MOFN_GENERATION_PTR, CK_ULONG, CK_ULONG, CK_VOID_PTR],
)
CA_CloneMofN = make_late_binding_function(
    "CA_CloneMofN", [CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_VOID_PTR]
)
CA_CloneModifyMofN = make_late_binding_function(
    "CA_CloneModifyMofN", [CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_VOID_PTR]
)
CA_ActivateMofN = make_late_binding_function(
    "CA_ActivateMofN", [CK_SESSION_HANDLE, CA_MOFN_ACTIVATION_PTR, CK_ULONG]
)
CA_DeactivateMofN = make_late_binding_function("CA_DeactivateMofN", [CK_SESSION_HANDLE])
CA_GetMofNStatus = make_late_binding_function("CA_GetMofNStatus", [CK_SLOT_ID, CA_MOFN_STATUS_PTR])
CA_DuplicateMofN = make_late_binding_function("CA_DuplicateMofN", [CK_SESSION_HANDLE])
CA_IsMofNEnabled = make_late_binding_function("CA_IsMofNEnabled", [CK_SLOT_ID, CK_ULONG_PTR])
CA_IsMofNRequired = make_late_binding_function("CA_IsMofNRequired", [CK_SLOT_ID, CK_ULONG_PTR])
CA_GenerateTokenKeys = make_late_binding_function(
    "CA_GenerateTokenKeys", [CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
)
CA_GetTokenCertificateInfo = make_late_binding_function(
    "CA_GetTokenCertificateInfo", [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_SetTokenCertificateSignature = make_late_binding_function(
    "CA_SetTokenCertificateSignature",
    [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG],
)
CA_GetModuleList = make_late_binding_function(
    "CA_GetModuleList", [CK_SLOT_ID, CKCA_MODULE_ID_PTR, CK_ULONG, CK_ULONG_PTR]
)
CA_GetModuleInfo = make_late_binding_function(
    "CA_GetModuleInfo", [CK_SLOT_ID, CKCA_MODULE_ID, CKCA_MODULE_INFO_PTR]
)
CA_LoadModule = make_late_binding_function(
    "CA_LoadModule",
    [
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CKCA_MODULE_ID_PTR,
    ],
)
CA_LoadEncryptedModule = make_late_binding_function(
    "CA_LoadEncryptedModule",
    [
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CKCA_MODULE_ID_PTR,
    ],
)
CA_UnloadModule = make_late_binding_function("CA_UnloadModule", [CK_SESSION_HANDLE, CKCA_MODULE_ID])
CA_PerformModuleCall = make_late_binding_function(
    "CA_PerformModuleCall",
    [CK_SESSION_HANDLE, CKCA_MODULE_ID, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_ULONG_PTR],
)
CA_FirmwareUpdate = make_late_binding_function(
    "CA_FirmwareUpdate",
    [
        CK_SESSION_HANDLE,
        CK_ULONG,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
    ],
)
CA_FirmwareRollback = make_late_binding_function("CA_FirmwareRollback", [CK_SESSION_HANDLE])
CA_CapabilityUpdate = make_late_binding_function(
    "CA_CapabilityUpdate", [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR]
)
CA_GetUserContainerNumber = make_late_binding_function(
    "CA_GetUserContainerNumber", [CK_SLOT_ID, CK_ULONG_PTR]
)
CA_GetUserContainerName = make_late_binding_function(
    "CA_GetUserContainerName", [CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_SetUserContainerName = make_late_binding_function(
    "CA_SetUserContainerName", [CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG]
)
CA_GetTokenInsertionCount = make_late_binding_function(
    "CA_GetTokenInsertionCount", [CK_SLOT_ID, CK_ULONG_PTR]
)
CA_GetRollbackFirmwareVersion = make_late_binding_function(
    "CA_GetRollbackFirmwareVersion", [CK_SLOT_ID, CK_ULONG_PTR]
)
CA_GetFPV = make_late_binding_function("CA_GetFPV", [CK_SLOT_ID, CK_ULONG_PTR])
CA_GetTPV = make_late_binding_function("CA_GetTPV", [CK_SLOT_ID, CK_ULONG_PTR])
CA_GetExtendedTPV = make_late_binding_function(
    "CA_GetExtendedTPV", [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_GetConfigurationElementDescription = make_late_binding_function(
    "CA_GetConfigurationElementDescription",
    [
        CK_SLOT_ID,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG_PTR,
        CK_ULONG_PTR,
        CK_ULONG_PTR,
        CK_CHAR_PTR,
    ],
)
CA_GetHSMCapabilitySet = make_late_binding_function(
    "CA_GetHSMCapabilitySet", [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_GetHSMCapabilitySetting = make_late_binding_function(
    "CA_GetHSMCapabilitySetting", [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR]
)
CA_GetHSMPolicySet = make_late_binding_function(
    "CA_GetHSMPolicySet", [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_GetHSMPolicySetting = make_late_binding_function(
    "CA_GetHSMPolicySetting", [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR]
)
CA_GetContainerCapabilitySet = make_late_binding_function(
    "CA_GetContainerCapabilitySet",
    [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR],
)
CA_GetContainerCapabilitySetting = make_late_binding_function(
    "CA_GetContainerCapabilitySetting", [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR]
)
CA_GetContainerPolicySet = make_late_binding_function(
    "CA_GetContainerPolicySet",
    [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR],
)
CA_GetContainerPolicySetting = make_late_binding_function(
    "CA_GetContainerPolicySetting", [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR]
)
CA_GetPartitionPolicyTemplate = make_late_binding_function(
    "CA_GetPartitionPolicyTemplate", [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_BYTE_PTR]
)
CA_SetTPV = make_late_binding_function("CA_SetTPV", [CK_SESSION_HANDLE, CK_ULONG])
CA_SetExtendedTPV = make_late_binding_function(
    "CA_SetExtendedTPV", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)
CA_SetHSMPolicy = make_late_binding_function(
    "CA_SetHSMPolicy", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)
CA_SetHSMPolicies = make_late_binding_function(
    "CA_SetHSMPolicies", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_SetDestructiveHSMPolicy = make_late_binding_function(
    "CA_SetDestructiveHSMPolicy", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)
CA_SetDestructiveHSMPolicies = make_late_binding_function(
    "CA_SetDestructiveHSMPolicies", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_SetContainerPolicy = make_late_binding_function(
    "CA_SetContainerPolicy", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG]
)
CA_SetContainerPolicies = make_late_binding_function(
    "CA_SetContainerPolicies", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_GetTokenCapabilities = make_late_binding_function(
    "CA_GetTokenCapabilities", [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_SetTokenPolicies = make_late_binding_function(
    "CA_SetTokenPolicies", [CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_GetTokenPolicies = make_late_binding_function(
    "CA_GetTokenPolicies", [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_RetrieveLicenseList = make_late_binding_function(
    "CA_RetrieveLicenseList", [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_QueryLicense = make_late_binding_function(
    "CA_QueryLicense",
    [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_BYTE_PTR],
)
CA_GetContainerStatus = make_late_binding_function(
    "CA_GetContainerStatus",
    [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR],
)
CA_GetTokenStatus = make_late_binding_function(
    "CA_GetTokenStatus", [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_GetSessionInfo = make_late_binding_function(
    "CA_GetSessionInfo", [CK_SESSION_HANDLE, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_GetCVFirmwareVersion = make_late_binding_function(
    "CA_GetCVFirmwareVersion", [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_ReadCommonStore = make_late_binding_function(
    "CA_ReadCommonStore", [CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_WriteCommonStore = make_late_binding_function(
    "CA_WriteCommonStore", [CK_ULONG, CK_BYTE_PTR, CK_ULONG]
)
CA_GetPrimarySlot = make_late_binding_function(
    "CA_GetPrimarySlot", [CK_SESSION_HANDLE, CK_SLOT_ID_PTR]
)
CA_GetSecondarySlot = make_late_binding_function(
    "CA_GetSecondarySlot", [CK_SESSION_HANDLE, CK_SLOT_ID_PTR]
)
CA_SwitchSecondarySlot = make_late_binding_function(
    "CA_SwitchSecondarySlot", [CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG]
)
CA_CloseSecondarySession = make_late_binding_function(
    "CA_CloseSecondarySession", [CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG]
)
CA_CloseAllSecondarySessions = make_late_binding_function(
    "CA_CloseAllSecondarySessions", [CK_SESSION_HANDLE]
)
CA_ChoosePrimarySlot = make_late_binding_function("CA_ChoosePrimarySlot", [CK_SESSION_HANDLE])
CA_ChooseSecondarySlot = make_late_binding_function("CA_ChooseSecondarySlot", [CK_SESSION_HANDLE])
CA_CloneObjectToAllSessions = make_late_binding_function(
    "CA_CloneObjectToAllSessions", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
)
CA_CloneAllObjectsToSession = make_late_binding_function(
    "CA_CloneAllObjectsToSession", [CK_SESSION_HANDLE, CK_SLOT_ID]
)
CA_ResetDevice = make_late_binding_function("CA_ResetDevice", [CK_SLOT_ID, CK_FLAGS])
CA_Zeroize = make_late_binding_function("CA_Zeroize", [CK_SLOT_ID, CK_FLAGS])
CA_FactoryReset = make_late_binding_function("CA_FactoryReset", [CK_SLOT_ID, CK_FLAGS])
CA_SetPedId = make_late_binding_function("CA_SetPedId", [CK_SLOT_ID, CK_ULONG])
CA_GetPedId = make_late_binding_function("CA_GetPedId", [CK_SLOT_ID, POINTER(CK_ULONG)])
CA_SpRawRead = make_late_binding_function("CA_SpRawRead", [CK_SLOT_ID, CK_ULONG_PTR])
CA_SpRawWrite = make_late_binding_function("CA_SpRawWrite", [CK_SLOT_ID, CK_ULONG_PTR])

CA_CheckOperationState = make_late_binding_function(
    "CA_CheckOperationState", [CK_SESSION_HANDLE, CK_ULONG, POINTER(CK_BBOOL)]
)
CA_DestroyMultipleObjects = make_late_binding_function(
    "CA_DestroyMultipleObjects", [CK_SESSION_HANDLE, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_ULONG_PTR]
)
CA_OpenSecureToken = make_late_binding_function(
    "CA_OpenSecureToken",
    [
        CK_SESSION_HANDLE,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG_PTR,
        CK_ULONG_PTR,
        CK_ULONG,
        CK_CHAR_PTR,
    ],
)
CA_CloseSecureToken = make_late_binding_function(
    "CA_CloseSecureToken", [CK_SESSION_HANDLE, CK_ULONG]
)
CA_ListSecureTokenInit = make_late_binding_function(
    "CA_ListSecureTokenInit",
    [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_BYTE_PTR],
)
CA_ListSecureTokenUpdate = make_late_binding_function(
    "CA_ListSecureTokenUpdate", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG]
)
CA_GetSecureElementMeta = make_late_binding_function(
    "CA_GetSecureElementMeta",
    [
        CK_SESSION_HANDLE,
        CK_ULONG,
        CK_MECHANISM_PTR,
        CK_ULONG_PTR,
        CK_ULONG_PTR,
        CK_BYTE_PTR,
        CK_ULONG,
    ],
)
CA_HAInit = make_late_binding_function("CA_HAInit", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE])
CA_HAInitExtended = make_late_binding_function(
    "CA_HAInitExtended",
    [
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_ULONG_PTR,
        CK_ULONG_PTR,
        CK_ULONG,
    ],
)
CA_HAGetMasterPublic = make_late_binding_function(
    "CA_HAGetMasterPublic", [CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_HAGetLoginChallenge = make_late_binding_function(
    "CA_HAGetLoginChallenge",
    [CK_SESSION_HANDLE, CK_USER_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR],
)
CA_HAAnswerLoginChallenge = make_late_binding_function(
    "CA_HAAnswerLoginChallenge",
    [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR],
)
CA_HALogin = make_late_binding_function(
    "CA_HALogin", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_HAAnswerMofNChallenge = make_late_binding_function(
    "CA_HAAnswerMofNChallenge",
    [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR],
)
CA_HAActivateMofN = make_late_binding_function(
    "CA_HAActivateMofN", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
)
CA_GetHAState = make_late_binding_function("CA_GetHAState", [CK_SLOT_ID, CK_HA_STATE_PTR])
CA_GetTokenCertificates = make_late_binding_function(
    "CA_GetTokenCertificates", [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_ExtractMaskedObject = make_late_binding_function(
    "CA_ExtractMaskedObject", [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_InsertMaskedObject = make_late_binding_function(
    "CA_InsertMaskedObject", [CK_SESSION_HANDLE, CK_ULONG_PTR, CK_BYTE_PTR, CK_ULONG]
)
CA_MultisignValue = make_late_binding_function(
    "CA_MultisignValue",
    [
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
        CK_ULONG_PTR,
        POINTER(CK_BYTE_PTR),
        CK_ULONG_PTR,
        POINTER(CK_BYTE_PTR),
    ],
)
CA_SIMExtract = make_late_binding_function(
    "CA_SIMExtract",
    [
        CK_SESSION_HANDLE,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
        CK_ULONG,
        CK_ULONG,
        CKA_SIM_AUTH_FORM,
        CK_ULONG_PTR,
        POINTER(CK_BYTE_PTR),
        CK_BBOOL,
        CK_ULONG_PTR,
        CK_BYTE_PTR,
    ],
)
CA_SIMInsert = make_late_binding_function(
    "CA_SIMInsert",
    [
        CK_SESSION_HANDLE,
        CK_ULONG,
        CKA_SIM_AUTH_FORM,
        CK_ULONG_PTR,
        POINTER(CK_BYTE_PTR),
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
        CK_OBJECT_HANDLE_PTR,
    ],
)
CA_SIMMultiSign = make_late_binding_function(
    "CA_SIMMultiSign",
    [
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_ULONG,
        CKA_SIM_AUTH_FORM,
        CK_ULONG_PTR,
        POINTER(CK_BYTE_PTR),
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_ULONG_PTR,
        POINTER(CK_BYTE_PTR),
        CK_ULONG_PTR,
        POINTER(CK_BYTE_PTR),
    ],
)
CA_Extract = make_late_binding_function("CA_Extract", [CK_SESSION_HANDLE, CK_MECHANISM_PTR])
CA_Insert = make_late_binding_function("CA_Insert", [CK_SESSION_HANDLE, CK_MECHANISM_PTR])
CA_MigrateKeys = make_late_binding_function(
    "CA_MigrateKeys",
    [CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_OBJECT_MIGRATION_DATA_PTR],
)
CA_MigrationStartSessionNegotiation = make_late_binding_function(
    "CA_MigrationStartSessionNegotiation",
    [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_BYTE_PTR],
)

CA_MigrationContinueSessionNegotiation = make_late_binding_function(
    "CA_MigrationContinueSessionNegotiation",
    [
        CK_SESSION_HANDLE,
        CK_ULONG,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
        CK_ULONG_PTR,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
        CK_ULONG_PTR,
        CK_BYTE_PTR,
    ],
)

CA_MigrationCloseSession = make_late_binding_function(
    "CA_MigrationCloseSession", [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR]
)

CA_GetTokenObjectUID = make_late_binding_function(
    "CA_GetTokenObjectUID", [CK_SLOT_ID, CK_ULONG, CK_ULONG, POINTER(CK_BYTE)]
)
CA_GetTokenObjectHandle = make_late_binding_function(
    "CA_GetTokenObjectHandle", [CK_SLOT_ID, POINTER(CK_BYTE), CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_GetObjectUID = make_late_binding_function(
    "CA_GetObjectUID", [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG, POINTER(CK_BYTE)]
)
CA_GetObjectHandle = make_late_binding_function(
    "CA_GetObjectHandle", [CK_SLOT_ID, CK_ULONG, POINTER(CK_BYTE), CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_DeleteContainer = make_late_binding_function("CA_DeleteContainer", [CK_SESSION_HANDLE])
CA_MTKSetStorage = make_late_binding_function("CA_MTKSetStorage", [CK_SESSION_HANDLE, CK_ULONG])
CA_MTKRestore = make_late_binding_function("CA_MTKRestore", [CK_SLOT_ID])
CA_MTKResplit = make_late_binding_function("CA_MTKResplit", [CK_SLOT_ID])
CA_MTKZeroize = make_late_binding_function("CA_MTKZeroize", [CK_SLOT_ID])
CA_MTKGetState = make_late_binding_function("CA_MTKGetState", [CK_SLOT_ID, CK_ULONG_PTR])
CA_TamperClear = make_late_binding_function("CA_TamperClear", [CK_SESSION_HANDLE])
CA_STMToggle = make_late_binding_function("CA_STMToggle", [CK_SESSION_HANDLE, CK_ULONG])
CA_STMGetState = make_late_binding_function("CA_STMGetState", [CK_SLOT_ID, CK_ULONG_PTR])
CA_GetTSV = make_late_binding_function("CA_GetTSV", [CK_SLOT_ID, CK_ULONG_PTR])
CA_InvokeServiceInit = make_late_binding_function(
    "CA_InvokeServiceInit", [CK_SESSION_HANDLE, CK_ULONG]
)
CA_InvokeService = make_late_binding_function(
    "CA_InvokeService", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ULONG_PTR]
)
CA_InvokeServiceFinal = make_late_binding_function(
    "CA_InvokeServiceFinal", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_InvokeServiceAsynch = make_late_binding_function(
    "CA_InvokeServiceAsynch", [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG]
)
CA_InvokeServiceSinglePart = make_late_binding_function(
    "CA_InvokeServiceSinglePart",
    [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR],
)
CA_EncodeECPrimeParams = make_late_binding_function(
    "CA_EncodeECPrimeParams",
    [
        CK_BYTE_PTR,
        CK_ULONG_PTR,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ],
)
CA_EncodeECChar2Params = make_late_binding_function(
    "CA_EncodeECChar2Params",
    [
        CK_BYTE_PTR,
        CK_ULONG_PTR,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ],
)
CA_EncodeECParamsFromFile = make_late_binding_function(
    "CA_EncodeECParamsFromFile", [CK_BYTE_PTR, CK_ULONG_PTR, CK_BYTE_PTR]
)
CA_GetHSMStats = make_late_binding_function(
    "CA_GetHSMStats", [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, POINTER(HSM_STATS_PARAMS)]
)
CA_GetHSMStorageInformation = make_late_binding_function(
    "CA_GetHSMStorageInformation",
    [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR],
)
CA_GetTokenStorageInformation = make_late_binding_function(
    "CA_GetTokenStorageInformation",
    [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR],
)
CA_GetContainerStorageInformation = make_late_binding_function(
    "CA_GetContainerStorageInformation",
    [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR],
)
CA_SetContainerSize = make_late_binding_function(
    "CA_SetContainerSize", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)
CA_CreateContainerWithPolicy = make_late_binding_function(
    "CA_CreateContainerWithPolicy",
    [
        CK_SESSION_HANDLE,
        CK_ULONG,
        CK_CHAR_PTR,
        CK_ULONG,
        CK_CHAR_PTR,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG_PTR,
        CK_ULONG,
        CK_ULONG,
        CK_BYTE_PTR,
    ],
)
CA_CreateContainer = make_late_binding_function(
    "CA_CreateContainer",
    [
        CK_SESSION_HANDLE,
        CK_ULONG,
        CK_CHAR_PTR,
        CK_ULONG,
        CK_CHAR_PTR,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG,
        CK_ULONG_PTR,
    ],
)
CA_InitAudit = make_late_binding_function(
    "CA_InitAudit", [CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR]
)
CA_LogVerify = make_late_binding_function(
    "CA_LogVerify", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ULONG, CK_ULONG_PTR]
)
CA_LogVerifyFile = make_late_binding_function(
    "CA_LogVerifyFile", [CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG_PTR]
)
CA_LogExternal = make_late_binding_function(
    "CA_LogExternal", [CK_SLOT_ID, CK_SESSION_HANDLE, POINTER(CK_CHAR), CK_ULONG]
)
CA_LogImportSecret = make_late_binding_function(
    "CA_LogImportSecret", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
)
CA_LogExportSecret = make_late_binding_function(
    "CA_LogExportSecret", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_TimeSync = make_late_binding_function("CA_TimeSync", [CK_SESSION_HANDLE, CK_ULONG])
CA_GetTime = make_late_binding_function("CA_GetTime", [CK_SESSION_HANDLE, CK_ULONG_PTR])
CA_LogSetConfig = make_late_binding_function(
    "CA_LogSetConfig", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_BYTE_PTR]
)
CA_LogGetConfig = make_late_binding_function(
    "CA_LogGetConfig",
    [
        CK_SESSION_HANDLE,
        POINTER(CK_ULONG),
        POINTER(CK_ULONG),
        POINTER(CK_ULONG),
        POINTER(CK_ULONG),
        CK_BYTE_PTR,
    ],
)
CA_ReplaceFastPathKEK = make_late_binding_function("CA_ReplaceFastPathKEK", [CK_SESSION_HANDLE])
CA_LogGetStatus = make_late_binding_function(
    "CA_LogGetStatus",
    [
        CK_SLOT_ID,
        POINTER(CK_ULONG),
        POINTER(CK_ULONG),
        POINTER(CK_ULONG),
        POINTER(CK_ULONG),
        POINTER(CK_ULONG),
    ],
)
CA_DeleteContainerWithHandle = make_late_binding_function(
    "CA_DeleteContainerWithHandle", [CK_SESSION_HANDLE, CK_ULONG]
)
CA_GetContainerList = make_late_binding_function(
    "CA_GetContainerList", [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_GetContainerName = make_late_binding_function(
    "CA_GetContainerName", [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_GetNumberOfAllowedContainers = make_late_binding_function(
    "CA_GetNumberOfAllowedContainers", [CK_SLOT_ID, CK_ULONG_PTR]
)
CA_GetTunnelSlotNumber = make_late_binding_function(
    "CA_GetTunnelSlotNumber", [CK_SLOT_ID, CK_SLOT_ID_PTR]
)
CA_GetClusterState = make_late_binding_function(
    "CA_GetClusterState", [CK_SLOT_ID, CK_CLUSTER_STATE_PTR]
)
CA_LockClusteredSlot = make_late_binding_function("CA_LockClusteredSlot", [CK_SLOT_ID])
CA_UnlockClusteredSlot = make_late_binding_function("CA_UnlockClusteredSlot", [CK_SLOT_ID])
CA_LKMInitiatorChallenge = make_late_binding_function(
    "CA_LKMInitiatorChallenge",
    [
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
        CK_ULONG,
        CK_LKM_TOKEN_ID_PTR,
        CK_LKM_TOKEN_ID_PTR,
        CK_CHAR_PTR,
        CK_ULONG_PTR,
    ],
)
CA_LKMReceiverResponse = make_late_binding_function(
    "CA_LKMReceiverResponse",
    [
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
        CK_ULONG,
        CK_LKM_TOKEN_ID_PTR,
        CK_CHAR_PTR,
        CK_ULONG,
        CK_CHAR_PTR,
        CK_ULONG_PTR,
    ],
)
CA_LKMInitiatorComplete = make_late_binding_function(
    "CA_LKMInitiatorComplete",
    [
        CK_SESSION_HANDLE,
        CK_CHAR_PTR,
        CK_ULONG,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_CHAR_PTR,
        CK_ULONG_PTR,
        CK_OBJECT_HANDLE_PTR,
        CK_OBJECT_HANDLE_PTR,
    ],
)
CA_LKMReceiverComplete = make_late_binding_function(
    "CA_LKMReceiverComplete",
    [
        CK_SESSION_HANDLE,
        CK_CHAR_PTR,
        CK_ULONG,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
        CK_OBJECT_HANDLE_PTR,
    ],
)
CA_ModifyUsageCount = make_late_binding_function(
    "CA_ModifyUsageCount", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG, CK_ULONG]
)
CA_EnableUnauthTokenInsertion = make_late_binding_function(
    "CA_EnableUnauthTokenInsertion", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
)
CA_GetUnauthTokenInsertionStatus = make_late_binding_function(
    "CA_GetUnauthTokenInsertionStatus",
    [CK_SESSION_HANDLE, CK_ULONG, POINTER(CK_ULONG), POINTER(CK_ULONG)],
)
CA_DisableUnauthTokenInsertion = make_late_binding_function(
    "CA_DisableUnauthTokenInsertion", [CK_SESSION_HANDLE, CK_ULONG]
)
CA_STCRegister = make_late_binding_function(
    "CA_STCRegister",
    [
        CK_SESSION_HANDLE,
        CK_SLOT_ID,
        POINTER(CK_CHAR),
        CK_ULONG,
        POINTER(CK_CHAR),
        CK_ULONG,
        POINTER(CK_CHAR),
        CK_ULONG,
    ],
)
CA_STCDeregister = make_late_binding_function(
    "CA_STCDeregister", [CK_SESSION_HANDLE, CK_SLOT_ID, POINTER(CK_CHAR)]
)
CA_STCGetPubKey = make_late_binding_function(
    "CA_STCGetPubKey",
    [
        CK_SESSION_HANDLE,
        CK_SLOT_ID,
        POINTER(CK_CHAR),
        POINTER(CK_CHAR),
        CK_ULONG_PTR,
        POINTER(CK_CHAR),
        CK_ULONG_PTR,
    ],
)
CA_STCGetClientsList = make_late_binding_function(
    "CA_STCGetClientsList", [CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR]
)
CA_STCGetClientInfo = make_late_binding_function(
    "CA_STCGetClientInfo",
    [
        CK_SESSION_HANDLE,
        CK_SLOT_ID,
        CK_ULONG,
        POINTER(CK_CHAR),
        CK_ULONG_PTR,
        CK_ULONG_PTR,
        POINTER(CK_CHAR),
        CK_ULONG_PTR,
        POINTER(CK_CHAR),
        CK_ULONG_PTR,
    ],
)
CA_STCGetPartPubKey = make_late_binding_function(
    "CA_STCGetPartPubKey",
    [CK_SESSION_HANDLE, CK_SLOT_ID, POINTER(CK_CHAR), CK_ULONG_PTR, POINTER(CK_CHAR), CK_ULONG_PTR],
)
CA_STCGetAdminPubKey = make_late_binding_function(
    "CA_STCGetAdminPubKey",
    [CK_SLOT_ID, POINTER(CK_CHAR), CK_ULONG_PTR, POINTER(CK_CHAR), CK_ULONG_PTR],
)
CA_STCSetCipherAlgorithm = make_late_binding_function(
    "CA_STCSetCipherAlgorithm", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)
CA_STCGetCipherAlgorithm = make_late_binding_function(
    "CA_STCGetCipherAlgorithm", [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_STCClearCipherAlgorithm = make_late_binding_function(
    "CA_STCClearCipherAlgorithm", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)
CA_STCSetDigestAlgorithm = make_late_binding_function(
    "CA_STCSetDigestAlgorithm", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)
CA_STCGetDigestAlgorithm = make_late_binding_function(
    "CA_STCGetDigestAlgorithm", [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_STCClearDigestAlgorithm = make_late_binding_function(
    "CA_STCClearDigestAlgorithm", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)
CA_STCSetKeyLifeTime = make_late_binding_function(
    "CA_STCSetKeyLifeTime", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)
CA_STCGetKeyLifeTime = make_late_binding_function(
    "CA_STCGetKeyLifeTime", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
)
CA_STCSetKeyActivationTimeOut = make_late_binding_function(
    "CA_STCSetKeyActivationTimeOut", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)
CA_STCGetKeyActivationTimeOut = make_late_binding_function(
    "CA_STCGetKeyActivationTimeOut", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
)
CA_STCSetMaxSessions = make_late_binding_function(
    "CA_STCSetMaxSessions", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)
CA_STCGetMaxSessions = make_late_binding_function(
    "CA_STCGetMaxSessions", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
)
CA_STCSetSequenceWindowSize = make_late_binding_function(
    "CA_STCSetSequenceWindowSize", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)
CA_STCGetSequenceWindowSize = make_late_binding_function(
    "CA_STCGetSequenceWindowSize", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
)
CA_STCIsEnabled = make_late_binding_function("CA_STCIsEnabled", [CK_ULONG, CK_BYTE_PTR])
CA_STCGetState = make_late_binding_function("CA_STCGetState", [CK_ULONG, POINTER(CK_CHAR), CK_BYTE])
CA_STCGetCurrentKeyLife = make_late_binding_function(
    "CA_STCGetCurrentKeyLife", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
)
CA_GetSlotIdForPhysicalSlot = make_late_binding_function(
    "CA_GetSlotIdForPhysicalSlot", [CK_ULONG, CK_SLOT_ID_PTR]
)
CA_GetSlotIdForContainer = make_late_binding_function(
    "CA_GetSlotIdForContainer", [CK_ULONG, CK_ULONG, CK_SLOT_ID_PTR]
)
CA_STCGetChannelID = make_late_binding_function("CA_STCGetChannelID", [CK_SLOT_ID, CK_ULONG_PTR])
CA_STCGetCipherID = make_late_binding_function("CA_STCGetCipherID", [CK_SLOT_ID, CK_ULONG_PTR])
CA_STCGetDigestID = make_late_binding_function("CA_STCGetDigestID", [CK_SLOT_ID, CK_ULONG_PTR])
CA_STCGetCipherIDs = make_late_binding_function(
    "CA_STCGetCipherIDs", [CK_SLOT_ID, CK_ULONG_PTR, CK_BYTE_PTR]
)
CA_STCGetCipherNameByID = make_late_binding_function(
    "CA_STCGetCipherNameByID", [CK_SLOT_ID, CK_ULONG, CK_CHAR_PTR, CK_BYTE]
)
CA_STCGetDigestIDs = make_late_binding_function(
    "CA_STCGetDigestIDs", [CK_SLOT_ID, CK_ULONG_PTR, CK_BYTE_PTR]
)
CA_STCGetDigestNameByID = make_late_binding_function(
    "CA_STCGetDigestNameByID", [CK_SLOT_ID, CK_ULONG, CK_CHAR_PTR, CK_BYTE]
)
CA_GetServerInstanceBySlotID = make_late_binding_function(
    "CA_GetServerInstanceBySlotID", [CK_SLOT_ID, CK_ULONG_PTR]
)
CA_GetSlotListFromServerInstance = make_late_binding_function(
    "CA_GetSlotListFromServerInstance", [CK_ULONG, CK_SLOT_ID_PTR, CK_ULONG_PTR]
)
CA_PerformSelfTest = make_late_binding_function(
    "CA_PerformSelfTest", [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
CA_DeriveKeyAndWrap = make_late_binding_function(
    "CA_DeriveKeyAndWrap",
    [
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ],
)

CA_Get = make_late_binding_function("CA_Get", [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR])

CA_GetFirmwareVersion = make_late_binding_function(
    "CA_GetFirmwareVersion", [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
)

C_Initialize = make_late_binding_function("C_Initialize", [CK_VOID_PTR])
C_Finalize = make_late_binding_function("C_Finalize", [CK_VOID_PTR])
C_GetInfo = make_late_binding_function("C_GetInfo", [CK_INFO_PTR])
C_GetFunctionList = make_late_binding_function("C_GetFunctionList", [CK_FUNCTION_LIST_PTR_PTR])
C_GetSlotList = make_late_binding_function(
    "C_GetSlotList", [CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR]
)
C_GetSlotInfo = make_late_binding_function("C_GetSlotInfo", [CK_SLOT_ID, CK_SLOT_INFO_PTR])
C_GetTokenInfo = make_late_binding_function("C_GetTokenInfo", [CK_SLOT_ID, CK_TOKEN_INFO_PTR])
C_GetMechanismList = make_late_binding_function(
    "C_GetMechanismList", [CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR]
)
C_GetMechanismInfo = make_late_binding_function(
    "C_GetMechanismInfo", [CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR]
)
C_InitToken = make_late_binding_function(
    "C_InitToken", [CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR]
)
CA_InitToken = make_late_binding_function(
    "CA_InitToken",
    [
        CK_SLOT_ID,
        CK_UTF8CHAR_PTR,
        CK_ULONG,
        CK_UTF8CHAR_PTR,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_ULONG,
        CK_POLICY_INFO_PTR,
        CK_ULONG,
        CK_POLICY_INFO_PTR,
    ],
)
C_InitPIN = make_late_binding_function("C_InitPIN", [CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG])
C_SetPIN = make_late_binding_function(
    "C_SetPIN", [CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG]
)
C_OpenSession = make_late_binding_function(
    "C_OpenSession", [CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR]
)
C_CloseSession = make_late_binding_function("C_CloseSession", [CK_SESSION_HANDLE])
C_CloseAllSessions = make_late_binding_function("C_CloseAllSessions", [CK_SLOT_ID])
C_GetSessionInfo = make_late_binding_function(
    "C_GetSessionInfo", [CK_SESSION_HANDLE, CK_SESSION_INFO_PTR]
)
C_GetOperationState = make_late_binding_function(
    "C_GetOperationState", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_SetOperationState = make_late_binding_function(
    "C_SetOperationState",
    [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE],
)
C_Login = make_late_binding_function(
    "C_Login", [CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG]
)
C_Logout = make_late_binding_function("C_Logout", [CK_SESSION_HANDLE])
C_CreateObject = make_late_binding_function(
    "C_CreateObject", [CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR]
)
C_CopyObject = make_late_binding_function(
    "C_CopyObject",
    [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR],
)
C_DestroyObject = make_late_binding_function(
    "C_DestroyObject", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
)
C_GetObjectSize = make_late_binding_function(
    "C_GetObjectSize", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR]
)
C_GetAttributeValue = make_late_binding_function(
    "C_GetAttributeValue", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
)
C_SetAttributeValue = make_late_binding_function(
    "C_SetAttributeValue", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
)
C_FindObjectsInit = make_late_binding_function(
    "C_FindObjectsInit", [CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
)
C_FindObjects = make_late_binding_function(
    "C_FindObjects", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR]
)
C_FindObjectsFinal = make_late_binding_function("C_FindObjectsFinal", [CK_SESSION_HANDLE])
C_EncryptInit = make_late_binding_function(
    "C_EncryptInit", [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
)
C_Encrypt = make_late_binding_function(
    "C_Encrypt", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_EncryptUpdate = make_late_binding_function(
    "C_EncryptUpdate", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_EncryptFinal = make_late_binding_function(
    "C_EncryptFinal", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_DecryptInit = make_late_binding_function(
    "C_DecryptInit", [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
)
C_Decrypt = make_late_binding_function(
    "C_Decrypt", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_DecryptUpdate = make_late_binding_function(
    "C_DecryptUpdate", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_DecryptFinal = make_late_binding_function(
    "C_DecryptFinal", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_DigestInit = make_late_binding_function("C_DigestInit", [CK_SESSION_HANDLE, CK_MECHANISM_PTR])
C_Digest = make_late_binding_function(
    "C_Digest", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_DigestUpdate = make_late_binding_function(
    "C_DigestUpdate", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
)
C_DigestKey = make_late_binding_function("C_DigestKey", [CK_SESSION_HANDLE, CK_OBJECT_HANDLE])
C_DigestFinal = make_late_binding_function(
    "C_DigestFinal", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_SignInit = make_late_binding_function(
    "C_SignInit", [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
)
C_Sign = make_late_binding_function(
    "C_Sign", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_SignUpdate = make_late_binding_function(
    "C_SignUpdate", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
)
C_SignFinal = make_late_binding_function(
    "C_SignFinal", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_SignRecoverInit = make_late_binding_function(
    "C_SignRecoverInit", [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
)
C_SignRecover = make_late_binding_function(
    "C_SignRecover", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_VerifyInit = make_late_binding_function(
    "C_VerifyInit", [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
)
C_Verify = make_late_binding_function(
    "C_Verify", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG]
)
C_VerifyUpdate = make_late_binding_function(
    "C_VerifyUpdate", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
)
C_VerifyFinal = make_late_binding_function(
    "C_VerifyFinal", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
)
C_VerifyRecoverInit = make_late_binding_function(
    "C_VerifyRecoverInit", [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
)
C_VerifyRecover = make_late_binding_function(
    "C_VerifyRecover", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_DigestEncryptUpdate = make_late_binding_function(
    "C_DigestEncryptUpdate", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_DecryptDigestUpdate = make_late_binding_function(
    "C_DecryptDigestUpdate", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_SignEncryptUpdate = make_late_binding_function(
    "C_SignEncryptUpdate", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_DecryptVerifyUpdate = make_late_binding_function(
    "C_DecryptVerifyUpdate", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)
C_GenerateKey = make_late_binding_function(
    "C_GenerateKey",
    [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR],
)
C_GenerateKeyPair = make_late_binding_function(
    "C_GenerateKeyPair",
    [
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
        CK_OBJECT_HANDLE_PTR,
    ],
)
C_WrapKey = make_late_binding_function(
    "C_WrapKey",
    [
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ],
)
C_UnwrapKey = make_late_binding_function(
    "C_UnwrapKey",
    [
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ],
)
C_DeriveKey = make_late_binding_function(
    "C_DeriveKey",
    [
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ],
)
C_SeedRandom = make_late_binding_function(
    "C_SeedRandom", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
)

C_GenerateRandom = make_late_binding_function(
    "C_GenerateRandom", [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
)
C_GetFunctionStatus = make_late_binding_function("C_GetFunctionStatus", [CK_SESSION_HANDLE])

C_CancelFunction = make_late_binding_function("C_CancelFunction", [CK_SESSION_HANDLE])
C_WaitForSlotEvent = make_late_binding_function(
    "C_WaitForSlotEvent", [CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR]
)

CA_RandomizeApplicationID = make_late_binding_function("CA_RandomizeApplicationID", [])

CA_GetApplicationID = make_late_binding_function(
    "CA_GetApplicationID", [POINTER(CK_APPLICATION_ID)]
)

CA_OpenApplicationIDV2 = make_late_binding_function(
    "CA_OpenApplicationIDV2", [CK_SLOT_ID, POINTER(CK_APPLICATION_ID)]
)

CA_CloseApplicationIDV2 = make_late_binding_function(
    "CA_CloseApplicationIDV2", [CK_SLOT_ID, POINTER(CK_APPLICATION_ID)]
)

CA_SetApplicationIDV2 = make_late_binding_function(
    "CA_SetApplicationIDV2", [POINTER(CK_APPLICATION_ID)]
)

CA_OpenSessionWithAppIDV2 = make_late_binding_function(
    "CA_OpenSessionWithAppIDV2",
    [
        CK_SLOT_ID,
        CK_FLAGS,
        POINTER(CK_APPLICATION_ID),
        CK_VOID_PTR,
        CK_NOTIFY,
        CK_SESSION_HANDLE_PTR,
    ],
)

CA_OpenApplicationIDForContainerV2 = make_late_binding_function(
    "CA_OpenApplicationIDForContainerV2", [CK_SLOT_ID, POINTER(CK_APPLICATION_ID), CK_ULONG]
)

CA_CloseApplicationIDForContainerV2 = make_late_binding_function(
    "CA_CloseApplicationIDForContainerV2", [CK_SLOT_ID, POINTER(CK_APPLICATION_ID), CK_ULONG]
)

CA_Bip32ImportPublicKey = make_late_binding_function(
    "CA_Bip32ImportPublicKey",
    [
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,  # Base58 encoded data src.
        CK_ULONG,  # encoded data size
        CK_ATTRIBUTE_PTR,  # user-specified attributes
        CK_ULONG,  # Attribute length
        CK_OBJECT_HANDLE_PTR,  # returned handle of created key
    ],
)

CA_Bip32ExportPublicKey = make_late_binding_function(
    "CA_Bip32ExportPublicKey",
    [
        CK_SESSION_HANDLE,
        CK_ULONG,  # BIP32 public key to export
        CK_BYTE_PTR,  # Base58 encoded data dest.
        CK_ULONG_PTR,  # Output length
    ],
)


CA_STCRegisterV2 = make_late_binding_function(
    "CA_STCRegisterV2",
    [
        CK_SESSION_HANDLE,
        CK_SLOT_ID,
        POINTER(CK_CHAR),
        CK_ULONG,
        CK_ULONG,
        POINTER(CK_BYTE),
        CK_ULONG,
    ],
)


CA_STCGetPubKey = make_late_binding_function(
    "CA_STCGetPubKey",
    [
        CK_SESSION_HANDLE,
        CK_SLOT_ID,
        POINTER(CK_CHAR),
        POINTER(CK_CHAR),
        CK_ULONG_PTR,
        POINTER(CK_CHAR),
        CK_ULONG_PTR,
    ],
)


CA_STCGetClientsList = make_late_binding_function(
    "CA_STCGetClientsList", [CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR]
)


CA_STCGetClientInfoV2 = make_late_binding_function(
    "CA_STCGetClientInfoV2",
    [
        CK_SESSION_HANDLE,
        CK_SLOT_ID,
        CK_ULONG,
        POINTER(CK_CHAR),
        CK_ULONG_PTR,
        CK_ULONG_PTR,
        POINTER(CK_BYTE),
        CK_ULONG_PTR,
    ],
)


CA_STCGetPartPubKey = make_late_binding_function(
    "CA_STCGetPartPubKey",
    [CK_SESSION_HANDLE, CK_SLOT_ID, POINTER(CK_CHAR), CK_ULONG_PTR, POINTER(CK_CHAR), CK_ULONG_PTR],
)


CA_STCGetAdminPubKey = make_late_binding_function(
    "CA_STCGetAdminPubKey",
    [CK_SLOT_ID, POINTER(CK_CHAR), CK_ULONG_PTR, POINTER(CK_CHAR), CK_ULONG_PTR],
)


CA_STCGetPID = make_late_binding_function(
    "CA_STCGetPID", [CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG_PTR, CK_BYTE_PTR, CK_ULONG_PTR]
)


CA_STCGetAdminPID = make_late_binding_function(
    "CA_STCGetAdminPID", [CK_SLOT_ID, CK_ULONG_PTR, CK_BYTE_PTR, CK_ULONG_PTR]
)


CA_STCSetCipherAlgorithm = make_late_binding_function(
    "CA_STCSetCipherAlgorithm", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)


CA_STCGetCipherAlgorithm = make_late_binding_function(
    "CA_STCGetCipherAlgorithm", [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)


CA_STCClearCipherAlgorithm = make_late_binding_function(
    "CA_STCClearCipherAlgorithm", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)


CA_STCSetDigestAlgorithm = make_late_binding_function(
    "CA_STCSetDigestAlgorithm", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)


CA_STCGetDigestAlgorithm = make_late_binding_function(
    "CA_STCGetDigestAlgorithm", [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
)


CA_STCClearDigestAlgorithm = make_late_binding_function(
    "CA_STCClearDigestAlgorithm", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)


CA_STCSetKeyLifeTime = make_late_binding_function(
    "CA_STCSetKeyLifeTime", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)


CA_STCGetKeyLifeTime = make_late_binding_function(
    "CA_STCGetKeyLifeTime", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
)


CA_STCSetKeyActivationTimeOut = make_late_binding_function(
    "CA_STCSetKeyActivationTimeOut", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)


CA_STCGetKeyActivationTimeOut = make_late_binding_function(
    "CA_STCGetKeyActivationTimeOut", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
)


CA_STCSetMaxSessions = make_late_binding_function(
    "CA_STCSetMaxSessions", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)


CA_STCGetMaxSessions = make_late_binding_function(
    "CA_STCGetMaxSessions", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
)


CA_STCSetSequenceWindowSize = make_late_binding_function(
    "CA_STCSetSequenceWindowSize", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
)


CA_STCGetSequenceWindowSize = make_late_binding_function(
    "CA_STCGetSequenceWindowSize", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
)


CA_STCIsEnabled = make_late_binding_function("CA_STCIsEnabled", [CK_ULONG, CK_BYTE_PTR])


CA_STCGetState = make_late_binding_function("CA_STCGetState", [CK_ULONG, POINTER(CK_CHAR), CK_BYTE])


CA_STCGetChannelID = make_late_binding_function("CA_STCGetChannelID", [CK_SLOT_ID, CK_ULONG_PTR])


CA_STCGetCipherID = make_late_binding_function("CA_STCGetCipherID", [CK_SLOT_ID, CK_ULONG_PTR])


CA_STCGetDigestID = make_late_binding_function("CA_STCGetDigestID", [CK_SLOT_ID, CK_ULONG_PTR])


CA_STCGetCurrentKeyLife = make_late_binding_function(
    "CA_STCGetCurrentKeyLife", [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
)


CA_STCGetCipherIDs = make_late_binding_function(
    "CA_STCGetCipherIDs", [CK_SLOT_ID, CK_ULONG_PTR, CK_BYTE_PTR]
)


CA_STCGetCipherNameByID = make_late_binding_function(
    "CA_STCGetCipherNameByID", [CK_SLOT_ID, CK_ULONG, CK_CHAR_PTR, CK_BYTE]
)


CA_STCGetDigestIDs = make_late_binding_function(
    "CA_STCGetDigestIDs", [CK_SLOT_ID, CK_ULONG_PTR, CK_BYTE_PTR]
)


CA_STCGetDigestNameByID = make_late_binding_function(
    "CA_STCGetDigestNameByID", [CK_SLOT_ID, CK_ULONG, CK_CHAR_PTR, CK_BYTE]
)
