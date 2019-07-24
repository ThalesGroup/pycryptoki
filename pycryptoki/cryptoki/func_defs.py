"""
PKCS11 & CA Extension ctypes function bindings.

Note to maintainers: This is where new functions added to the libCryptoki C API should
be defined.
"""
from pycryptoki.cryptoki._ck_func_list import CK_SFNT_CA_FUNCTION_LIST_PTR_PTR, CK_NOTIFY, CK_FUNCTION_LIST_PTR_PTR
from pycryptoki.cryptoki.ck_defs import *
from pycryptoki.cryptoki_helpers import make_late_binding_function

CA_GetFunctionList = make_late_binding_function("CA_GetFunctionList")
CA_GetFunctionList.restype = CK_RV
CA_GetFunctionList.argtypes = [CK_SFNT_CA_FUNCTION_LIST_PTR_PTR]
CA_WaitForSlotEvent = make_late_binding_function("CA_WaitForSlotEvent")
CA_WaitForSlotEvent.restype = CK_RV
CA_WaitForSlotEvent.argtypes = [CK_FLAGS, POINTER(CK_ULONG), CK_SLOT_ID_PTR, CK_VOID_PTR]
CA_InitIndirectToken = make_late_binding_function("CA_InitIndirectToken")
CA_InitIndirectToken.restype = CK_RV
CA_InitIndirectToken.argtypes = [CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR, CK_SESSION_HANDLE]
CA_InitIndirectPIN = make_late_binding_function("CA_InitIndirectPIN")
CA_InitIndirectPIN.restype = CK_RV
CA_InitIndirectPIN.argtypes = [CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG, CK_SESSION_HANDLE]
CA_ResetPIN = make_late_binding_function("CA_ResetPIN")
CA_ResetPIN.restype = CK_RV
CA_ResetPIN.argtypes = [CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG]
CA_InitRolePIN = make_late_binding_function("CA_InitRolePIN")
CA_InitRolePIN.restype = CK_RV
CA_InitRolePIN.argtypes = [CK_SESSION_HANDLE, CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG]
CA_InitSlotRolePIN = make_late_binding_function("CA_InitSlotRolePIN")
CA_InitSlotRolePIN.restype = CK_RV
CA_InitSlotRolePIN.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID, CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG]
CA_RoleStateGet = make_late_binding_function("CA_RoleStateGet")
CA_RoleStateGet.restype = CK_RV
CA_RoleStateGet.argtypes = [CK_SLOT_ID, CK_USER_TYPE, POINTER(CA_ROLE_STATE)]
CA_CreateLoginChallenge = make_late_binding_function("CA_CreateLoginChallenge")
CA_CreateLoginChallenge.restype = CK_RV
CA_CreateLoginChallenge.argtypes = [
    CK_SESSION_HANDLE,
    CK_USER_TYPE,
    CK_ULONG,
    CK_CHAR_PTR,
    CK_ULONG_PTR,
    CK_CHAR_PTR,
]
CA_CreateContainerLoginChallenge = make_late_binding_function("CA_CreateContainerLoginChallenge")
CA_CreateContainerLoginChallenge.restype = CK_RV
CA_CreateContainerLoginChallenge.argtypes = [
    CK_SESSION_HANDLE,
    CK_SLOT_ID,
    CK_USER_TYPE,
    CK_ULONG,
    CK_CHAR_PTR,
    CK_ULONG_PTR,
    CK_CHAR_PTR,
]
CA_Deactivate = make_late_binding_function("CA_Deactivate")
CA_Deactivate.restype = CK_RV
CA_Deactivate.argtypes = [CK_SLOT_ID, CK_USER_TYPE]
CA_FindAdminSlotForSlot = make_late_binding_function("CA_FindAdminSlotForSlot")
CA_FindAdminSlotForSlot.restype = CK_RV
CA_FindAdminSlotForSlot.argtypes = [CK_SLOT_ID, POINTER(CK_SLOT_ID), POINTER(CK_SLOT_ID)]
CA_TokenInsert = make_late_binding_function("CA_TokenInsert")
CA_TokenInsert.restype = CK_RV
CA_TokenInsert.argtypes = [CK_SESSION_HANDLE, CT_TokenHndle, CK_SLOT_ID]
CA_TokenInsertNoAuth = make_late_binding_function("CA_TokenInsertNoAuth")
CA_TokenInsertNoAuth.restype = CK_RV
CA_TokenInsertNoAuth.argtypes = [CT_TokenHndle, CK_SLOT_ID]
CA_TokenZeroize = make_late_binding_function("CA_TokenZeroize")
CA_TokenZeroize.restype = CK_RV
CA_TokenZeroize.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID, CK_FLAGS]
CA_TokenDelete = make_late_binding_function("CA_TokenDelete")
CA_TokenDelete.restype = CK_RV
CA_TokenDelete.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID]
CA_OpenSession = make_late_binding_function("CA_OpenSession")
CA_OpenSession.restype = CK_RV
CA_OpenSession.argtypes = [
    CK_SLOT_ID,
    CK_ULONG,
    CK_FLAGS,
    CK_VOID_PTR,
    CK_NOTIFY,
    CK_SESSION_HANDLE_PTR,
]
CA_OpenSessionWithAppID = make_late_binding_function("CA_OpenSessionWithAppID")
CA_OpenSessionWithAppID.restype = CK_RV
CA_OpenSessionWithAppID.argtypes = [
    CK_SLOT_ID,
    CK_FLAGS,
    CK_ULONG,
    CK_ULONG,
    CK_VOID_PTR,
    CK_NOTIFY,
    CK_SESSION_HANDLE_PTR,
]
CA_IndirectLogin = make_late_binding_function("CA_IndirectLogin")
CA_IndirectLogin.restype = CK_RV
CA_IndirectLogin.argtypes = [CK_SESSION_HANDLE, CK_USER_TYPE, CK_SESSION_HANDLE]
CA_InitializeRemotePEDVector = make_late_binding_function("CA_InitializeRemotePEDVector")
CA_InitializeRemotePEDVector.restype = CK_RV
CA_InitializeRemotePEDVector.argtypes = [CK_SESSION_HANDLE]
CA_DeleteRemotePEDVector = make_late_binding_function("CA_DeleteRemotePEDVector")
CA_DeleteRemotePEDVector.restype = CK_RV
CA_DeleteRemotePEDVector.argtypes = [CK_SESSION_HANDLE]
CA_GetRemotePEDVectorStatus = make_late_binding_function("CA_GetRemotePEDVectorStatus")
CA_GetRemotePEDVectorStatus.restype = CK_RV
CA_GetRemotePEDVectorStatus.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_ConfigureRemotePED = make_late_binding_function("CA_ConfigureRemotePED")
CA_ConfigureRemotePED.restype = CK_RV
CA_ConfigureRemotePED.argtypes = [CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_ULONG_PTR]
CA_DismantleRemotePED = make_late_binding_function("CA_DismantleRemotePED")
CA_DismantleRemotePED.restype = CK_RV
CA_DismantleRemotePED.argtypes = [CK_SLOT_ID, CK_ULONG]
CA_Restart = make_late_binding_function("CA_Restart")
CA_Restart.restype = CK_RV
CA_Restart.argtypes = [CK_SLOT_ID]
CA_RestartForContainer = make_late_binding_function("CA_RestartForContainer")
CA_RestartForContainer.restype = CK_RV
CA_RestartForContainer.argtypes = [CK_SLOT_ID, CK_ULONG]
CA_CloseApplicationID = make_late_binding_function("CA_CloseApplicationID")
CA_CloseApplicationID.restype = CK_RV
CA_CloseApplicationID.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG]
CA_CloseApplicationIDForContainer = make_late_binding_function("CA_CloseApplicationIDForContainer")
CA_CloseApplicationIDForContainer.restype = CK_RV
CA_CloseApplicationIDForContainer.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG]
CA_OpenApplicationID = make_late_binding_function("CA_OpenApplicationID")
CA_OpenApplicationID.restype = CK_RV
CA_OpenApplicationID.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG]
CA_OpenApplicationIDForContainer = make_late_binding_function("CA_OpenApplicationIDForContainer")
CA_OpenApplicationIDForContainer.restype = CK_RV
CA_OpenApplicationIDForContainer.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG]
CA_SetApplicationID = make_late_binding_function("CA_SetApplicationID")
CA_SetApplicationID.restype = CK_RV
CA_SetApplicationID.argtypes = [CK_ULONG, CK_ULONG]
CA_DescribeUtilizationBinId = make_late_binding_function("CA_DescribeUtilizationBinId")
CA_DescribeUtilizationBinId.restype = CK_RV
CA_DescribeUtilizationBinId.argtypes = [CK_ULONG, CK_CHAR_PTR]
CA_ReadUtilizationMetrics = make_late_binding_function("CA_ReadUtilizationMetrics")
CA_ReadUtilizationMetrics.restype = CK_RV
CA_ReadUtilizationMetrics.argtypes = [CK_SESSION_HANDLE]
CA_ReadAndResetUtilizationMetrics = make_late_binding_function("CA_ReadAndResetUtilizationMetrics")
CA_ReadAndResetUtilizationMetrics.restype = CK_RV
CA_ReadAndResetUtilizationMetrics.argtypes = [CK_SESSION_HANDLE]
CA_ReadAllUtilizationCounters = make_late_binding_function("CA_ReadAllUtilizationCounters")
CA_ReadAllUtilizationCounters.restype = CK_RV
CA_ReadAllUtilizationCounters.argtypes = [
    CK_SESSION_HANDLE,
    CK_UTILIZATION_COUNTER_PTR,
    CK_ULONG_PTR,
]
# pka
CA_SetAuthorizationData = make_late_binding_function("CA_SetAuthorizationData")
CA_SetAuthorizationData.restype = CK_RV
CA_SetAuthorizationData.argtypes = [
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    CK_UTF8CHAR_PTR,
    CK_ULONG,
    CK_UTF8CHAR_PTR,
    CK_ULONG,
]
CA_ResetAuthorizationData = make_late_binding_function("CA_ResetAuthorizationData")
CA_ResetAuthorizationData.restype = CK_RV
CA_ResetAuthorizationData.argtypes = [
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    CK_UTF8CHAR_PTR,
    CK_ULONG,
]
CA_AuthorizeKey = make_late_binding_function("CA_AuthorizeKey")
CA_AuthorizeKey.restype = CK_RV
CA_AuthorizeKey.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG]
CA_AssignKey = make_late_binding_function("CA_AssignKey")
CA_AssignKey.restype = CK_RV
CA_AssignKey.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
CA_IncrementFailedAuthCount = make_late_binding_function("CA_IncrementFailedAuthCount")
CA_IncrementFailedAuthCount.restype = CK_RV
CA_IncrementFailedAuthCount.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
CA_ManualKCV = make_late_binding_function("CA_ManualKCV")
CA_ManualKCV.restype = CK_RV
CA_ManualKCV.argtypes = [CK_SESSION_HANDLE]
CA_SetLKCV = make_late_binding_function("CA_SetLKCV")
CA_SetLKCV.restype = CK_RV
CA_SetLKCV.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
CA_SetKCV = make_late_binding_function("CA_SetKCV")
CA_SetKCV.restype = CK_RV
CA_SetKCV.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
CA_SetRDK = make_late_binding_function("CA_SetRDK")
CA_SetRDK.restype = CK_RV
CA_SetRDK.argtypes = [CK_SESSION_HANDLE, POINTER(CK_BYTE), CK_ULONG]
CA_SetCloningDomain = make_late_binding_function("CA_SetCloningDomain")
CA_SetCloningDomain.restype = CK_RV
CA_SetCloningDomain.argtypes = [CK_BYTE_PTR, CK_ULONG]
CA_ClonePrivateKey = make_late_binding_function("CA_ClonePrivateKey")
CA_ClonePrivateKey.restype = CK_RV
CA_ClonePrivateKey.argtypes = [
    CK_SESSION_HANDLE,
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE_PTR,
]
CA_CloneObject = make_late_binding_function("CA_CloneObject")
CA_CloneObject.restype = CK_RV
CA_CloneObject.argtypes = [
    CK_SESSION_HANDLE,
    CK_SESSION_HANDLE,
    CK_ULONG,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE_PTR,
]
CA_GenerateCloningKEV = make_late_binding_function("CA_GenerateCloningKEV")
CA_GenerateCloningKEV.restype = CK_RV
CA_GenerateCloningKEV.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
CA_CloneAsTargetInit = make_late_binding_function("CA_CloneAsTargetInit")
CA_CloneAsTargetInit.restype = CK_RV
CA_CloneAsTargetInit.argtypes = [
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BBOOL,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
]
CA_CloneAsSource = make_late_binding_function("CA_CloneAsSource")
CA_CloneAsSource.restype = CK_RV
CA_CloneAsSource.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BBOOL,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
]
CA_CloneAsTarget = make_late_binding_function("CA_CloneAsTarget")
CA_CloneAsTarget.restype = CK_RV
CA_CloneAsTarget.argtypes = [
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_ULONG,
    CK_ULONG,
    CK_BBOOL,
    CK_OBJECT_HANDLE_PTR,
]
CA_SetMofN = make_late_binding_function("CA_SetMofN")
CA_SetMofN.restype = CK_RV
CA_SetMofN.argtypes = [CK_BBOOL]
CA_GenerateMofN = make_late_binding_function("CA_GenerateMofN")
CA_GenerateMofN.restype = CK_RV
CA_GenerateMofN.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    CA_MOFN_GENERATION_PTR,
    CK_ULONG,
    CK_ULONG,
    CK_VOID_PTR,
]
CA_GenerateCloneableMofN = make_late_binding_function("CA_GenerateCloneableMofN")
CA_GenerateCloneableMofN.restype = CK_RV
CA_GenerateCloneableMofN.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    CA_MOFN_GENERATION_PTR,
    CK_ULONG,
    CK_ULONG,
    CK_VOID_PTR,
]
CA_ModifyMofN = make_late_binding_function("CA_ModifyMofN")
CA_ModifyMofN.restype = CK_RV
CA_ModifyMofN.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    CA_MOFN_GENERATION_PTR,
    CK_ULONG,
    CK_ULONG,
    CK_VOID_PTR,
]
CA_CloneMofN = make_late_binding_function("CA_CloneMofN")
CA_CloneMofN.restype = CK_RV
CA_CloneMofN.argtypes = [CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_VOID_PTR]
CA_CloneModifyMofN = make_late_binding_function("CA_CloneModifyMofN")
CA_CloneModifyMofN.restype = CK_RV
CA_CloneModifyMofN.argtypes = [CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_VOID_PTR]
CA_ActivateMofN = make_late_binding_function("CA_ActivateMofN")
CA_ActivateMofN.restype = CK_RV
CA_ActivateMofN.argtypes = [CK_SESSION_HANDLE, CA_MOFN_ACTIVATION_PTR, CK_ULONG]
CA_DeactivateMofN = make_late_binding_function("CA_DeactivateMofN")
CA_DeactivateMofN.restype = CK_RV
CA_DeactivateMofN.argtypes = [CK_SESSION_HANDLE]
CA_GetMofNStatus = make_late_binding_function("CA_GetMofNStatus")
CA_GetMofNStatus.restype = CK_RV
CA_GetMofNStatus.argtypes = [CK_SLOT_ID, CA_MOFN_STATUS_PTR]
CA_DuplicateMofN = make_late_binding_function("CA_DuplicateMofN")
CA_DuplicateMofN.restype = CK_RV
CA_DuplicateMofN.argtypes = [CK_SESSION_HANDLE]
CA_IsMofNEnabled = make_late_binding_function("CA_IsMofNEnabled")
CA_IsMofNEnabled.restype = CK_RV
CA_IsMofNEnabled.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_IsMofNRequired = make_late_binding_function("CA_IsMofNRequired")
CA_IsMofNRequired.restype = CK_RV
CA_IsMofNRequired.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GenerateTokenKeys = make_late_binding_function("CA_GenerateTokenKeys")
CA_GenerateTokenKeys.restype = CK_RV
CA_GenerateTokenKeys.argtypes = [CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
CA_GetTokenCertificateInfo = make_late_binding_function("CA_GetTokenCertificateInfo")
CA_GetTokenCertificateInfo.restype = CK_RV
CA_GetTokenCertificateInfo.argtypes = [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_SetTokenCertificateSignature = make_late_binding_function("CA_SetTokenCertificateSignature")
CA_SetTokenCertificateSignature.restype = CK_RV
CA_SetTokenCertificateSignature.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    CK_ULONG,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
]
CA_GetModuleList = make_late_binding_function("CA_GetModuleList")
CA_GetModuleList.restype = CK_RV
CA_GetModuleList.argtypes = [CK_SLOT_ID, CKCA_MODULE_ID_PTR, CK_ULONG, CK_ULONG_PTR]
CA_GetModuleInfo = make_late_binding_function("CA_GetModuleInfo")
CA_GetModuleInfo.restype = CK_RV
CA_GetModuleInfo.argtypes = [CK_SLOT_ID, CKCA_MODULE_ID, CKCA_MODULE_INFO_PTR]
CA_LoadModule = make_late_binding_function("CA_LoadModule")
CA_LoadModule.restype = CK_RV
CA_LoadModule.argtypes = [
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
]
CA_LoadEncryptedModule = make_late_binding_function("CA_LoadEncryptedModule")
CA_LoadEncryptedModule.restype = CK_RV
CA_LoadEncryptedModule.argtypes = [
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
]
CA_UnloadModule = make_late_binding_function("CA_UnloadModule")
CA_UnloadModule.restype = CK_RV
CA_UnloadModule.argtypes = [CK_SESSION_HANDLE, CKCA_MODULE_ID]
CA_PerformModuleCall = make_late_binding_function("CA_PerformModuleCall")
CA_PerformModuleCall.restype = CK_RV
CA_PerformModuleCall.argtypes = [
    CK_SESSION_HANDLE,
    CKCA_MODULE_ID,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_ULONG_PTR,
]
CA_FirmwareUpdate = make_late_binding_function("CA_FirmwareUpdate")
CA_FirmwareUpdate.restype = CK_RV
CA_FirmwareUpdate.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
]
CA_FirmwareRollback = make_late_binding_function("CA_FirmwareRollback")
CA_FirmwareRollback.restype = CK_RV
CA_FirmwareRollback.argtypes = [CK_SESSION_HANDLE]
CA_CapabilityUpdate = make_late_binding_function("CA_CapabilityUpdate")
CA_CapabilityUpdate.restype = CK_RV
CA_CapabilityUpdate.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR]
CA_GetUserContainerNumber = make_late_binding_function("CA_GetUserContainerNumber")
CA_GetUserContainerNumber.restype = CK_RV
CA_GetUserContainerNumber.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetUserContainerName = make_late_binding_function("CA_GetUserContainerName")
CA_GetUserContainerName.restype = CK_RV
CA_GetUserContainerName.argtypes = [CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG_PTR]
CA_SetUserContainerName = make_late_binding_function("CA_SetUserContainerName")
CA_SetUserContainerName.restype = CK_RV
CA_SetUserContainerName.argtypes = [CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG]
CA_GetTokenInsertionCount = make_late_binding_function("CA_GetTokenInsertionCount")
CA_GetTokenInsertionCount.restype = CK_RV
CA_GetTokenInsertionCount.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetRollbackFirmwareVersion = make_late_binding_function("CA_GetRollbackFirmwareVersion")
CA_GetRollbackFirmwareVersion.restype = CK_RV
CA_GetRollbackFirmwareVersion.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetFPV = make_late_binding_function("CA_GetFPV")
CA_GetFPV.restype = CK_RV
CA_GetFPV.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetTPV = make_late_binding_function("CA_GetTPV")
CA_GetTPV.restype = CK_RV
CA_GetTPV.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetExtendedTPV = make_late_binding_function("CA_GetExtendedTPV")
CA_GetExtendedTPV.restype = CK_RV
CA_GetExtendedTPV.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetConfigurationElementDescription = make_late_binding_function(
    "CA_GetConfigurationElementDescription"
)
CA_GetConfigurationElementDescription.restype = CK_RV
CA_GetConfigurationElementDescription.argtypes = [
    CK_SLOT_ID,
    CK_ULONG,
    CK_ULONG,
    CK_ULONG,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_CHAR_PTR,
]
CA_GetHSMCapabilitySet = make_late_binding_function("CA_GetHSMCapabilitySet")
CA_GetHSMCapabilitySet.restype = CK_RV
CA_GetHSMCapabilitySet.argtypes = [
    CK_SLOT_ID,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
]
CA_GetHSMCapabilitySetting = make_late_binding_function("CA_GetHSMCapabilitySetting")
CA_GetHSMCapabilitySetting.restype = CK_RV
CA_GetHSMCapabilitySetting.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR]
CA_GetHSMPolicySet = make_late_binding_function("CA_GetHSMPolicySet")
CA_GetHSMPolicySet.restype = CK_RV
CA_GetHSMPolicySet.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetHSMPolicySetting = make_late_binding_function("CA_GetHSMPolicySetting")
CA_GetHSMPolicySetting.restype = CK_RV
CA_GetHSMPolicySetting.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR]
CA_GetContainerCapabilitySet = make_late_binding_function("CA_GetContainerCapabilitySet")
CA_GetContainerCapabilitySet.restype = CK_RV
CA_GetContainerCapabilitySet.argtypes = [
    CK_SLOT_ID,
    CK_ULONG,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
]
CA_GetContainerCapabilitySetting = make_late_binding_function("CA_GetContainerCapabilitySetting")
CA_GetContainerCapabilitySetting.restype = CK_RV
CA_GetContainerCapabilitySetting.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR]
CA_GetContainerPolicySet = make_late_binding_function("CA_GetContainerPolicySet")
CA_GetContainerPolicySet.restype = CK_RV
CA_GetContainerPolicySet.argtypes = [
    CK_SLOT_ID,
    CK_ULONG,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
]
CA_GetContainerPolicySetting = make_late_binding_function("CA_GetContainerPolicySetting")
CA_GetContainerPolicySetting.restype = CK_RV
CA_GetContainerPolicySetting.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR]
CA_GetPartitionPolicyTemplate = make_late_binding_function("CA_GetPartitionPolicyTemplate")
CA_GetPartitionPolicyTemplate.restype = CK_RV
CA_GetPartitionPolicyTemplate.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_BYTE_PTR]
CA_SetTPV = make_late_binding_function("CA_SetTPV")
CA_SetTPV.restype = CK_RV
CA_SetTPV.argtypes = [CK_SESSION_HANDLE, CK_ULONG]
CA_SetExtendedTPV = make_late_binding_function("CA_SetExtendedTPV")
CA_SetExtendedTPV.restype = CK_RV
CA_SetExtendedTPV.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_SetHSMPolicy = make_late_binding_function("CA_SetHSMPolicy")
CA_SetHSMPolicy.restype = CK_RV
CA_SetHSMPolicy.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_SetHSMPolicies = make_late_binding_function("CA_SetHSMPolicies")
CA_SetHSMPolicies.restype = CK_RV
CA_SetHSMPolicies.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR]
CA_SetDestructiveHSMPolicy = make_late_binding_function("CA_SetDestructiveHSMPolicy")
CA_SetDestructiveHSMPolicy.restype = CK_RV
CA_SetDestructiveHSMPolicy.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_SetDestructiveHSMPolicies = make_late_binding_function("CA_SetDestructiveHSMPolicies")
CA_SetDestructiveHSMPolicies.restype = CK_RV
CA_SetDestructiveHSMPolicies.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR]
CA_SetContainerPolicy = make_late_binding_function("CA_SetContainerPolicy")
CA_SetContainerPolicy.restype = CK_RV
CA_SetContainerPolicy.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG]
CA_SetContainerPolicies = make_late_binding_function("CA_SetContainerPolicies")
CA_SetContainerPolicies.restype = CK_RV
CA_SetContainerPolicies.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    CK_ULONG,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
]
CA_GetTokenCapabilities = make_late_binding_function("CA_GetTokenCapabilities")
CA_GetTokenCapabilities.restype = CK_RV
CA_GetTokenCapabilities.argtypes = [
    CK_SLOT_ID,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
]
CA_SetTokenPolicies = make_late_binding_function("CA_SetTokenPolicies")
CA_SetTokenPolicies.restype = CK_RV
CA_SetTokenPolicies.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetTokenPolicies = make_late_binding_function("CA_GetTokenPolicies")
CA_GetTokenPolicies.restype = CK_RV
CA_GetTokenPolicies.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
CA_RetrieveLicenseList = make_late_binding_function("CA_RetrieveLicenseList")
CA_RetrieveLicenseList.restype = CK_RV
CA_RetrieveLicenseList.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR]
CA_QueryLicense = make_late_binding_function("CA_QueryLicense")
CA_QueryLicense.restype = CK_RV
CA_QueryLicense.argtypes = [
    CK_SLOT_ID,
    CK_ULONG,
    CK_ULONG,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_BYTE_PTR,
]
CA_GetContainerStatus = make_late_binding_function("CA_GetContainerStatus")
CA_GetContainerStatus.restype = CK_RV
CA_GetContainerStatus.argtypes = [
    CK_SLOT_ID,
    CK_ULONG,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
]
CA_GetTokenStatus = make_late_binding_function("CA_GetTokenStatus")
CA_GetTokenStatus.restype = CK_RV
CA_GetTokenStatus.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetSessionInfo = make_late_binding_function("CA_GetSessionInfo")
CA_GetSessionInfo.restype = CK_RV
CA_GetSessionInfo.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
]
CA_GetCVFirmwareVersion = make_late_binding_function("CA_GetCVFirmwareVersion")
CA_GetCVFirmwareVersion.restype = CK_RV
CA_GetCVFirmwareVersion.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
CA_ReadCommonStore = make_late_binding_function("CA_ReadCommonStore")
CA_ReadCommonStore.restype = CK_RV
CA_ReadCommonStore.argtypes = [CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_WriteCommonStore = make_late_binding_function("CA_WriteCommonStore")
CA_WriteCommonStore.restype = CK_RV
CA_WriteCommonStore.argtypes = [CK_ULONG, CK_BYTE_PTR, CK_ULONG]
CA_GetPrimarySlot = make_late_binding_function("CA_GetPrimarySlot")
CA_GetPrimarySlot.restype = CK_RV
CA_GetPrimarySlot.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID_PTR]
CA_GetSecondarySlot = make_late_binding_function("CA_GetSecondarySlot")
CA_GetSecondarySlot.restype = CK_RV
CA_GetSecondarySlot.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID_PTR]
CA_SwitchSecondarySlot = make_late_binding_function("CA_SwitchSecondarySlot")
CA_SwitchSecondarySlot.restype = CK_RV
CA_SwitchSecondarySlot.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG]
CA_CloseSecondarySession = make_late_binding_function("CA_CloseSecondarySession")
CA_CloseSecondarySession.restype = CK_RV
CA_CloseSecondarySession.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG]
CA_CloseAllSecondarySessions = make_late_binding_function("CA_CloseAllSecondarySessions")
CA_CloseAllSecondarySessions.restype = CK_RV
CA_CloseAllSecondarySessions.argtypes = [CK_SESSION_HANDLE]
CA_ChoosePrimarySlot = make_late_binding_function("CA_ChoosePrimarySlot")
CA_ChoosePrimarySlot.restype = CK_RV
CA_ChoosePrimarySlot.argtypes = [CK_SESSION_HANDLE]
CA_ChooseSecondarySlot = make_late_binding_function("CA_ChooseSecondarySlot")
CA_ChooseSecondarySlot.restype = CK_RV
CA_ChooseSecondarySlot.argtypes = [CK_SESSION_HANDLE]
CA_CloneObjectToAllSessions = make_late_binding_function("CA_CloneObjectToAllSessions")
CA_CloneObjectToAllSessions.restype = CK_RV
CA_CloneObjectToAllSessions.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
CA_CloneAllObjectsToSession = make_late_binding_function("CA_CloneAllObjectsToSession")
CA_CloneAllObjectsToSession.restype = CK_RV
CA_CloneAllObjectsToSession.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID]
CA_ResetDevice = make_late_binding_function("CA_ResetDevice")
CA_ResetDevice.restype = CK_RV
CA_ResetDevice.argtypes = [CK_SLOT_ID, CK_FLAGS]
CA_Zeroize = make_late_binding_function("CA_Zeroize")
CA_Zeroize.restype = CK_RV
CA_Zeroize.argtypes = [CK_SLOT_ID, CK_FLAGS]
CA_FactoryReset = make_late_binding_function("CA_FactoryReset")
CA_FactoryReset.restype = CK_RV
CA_FactoryReset.argtypes = [CK_SLOT_ID, CK_FLAGS]
CA_SetPedId = make_late_binding_function("CA_SetPedId")
CA_SetPedId.restype = CK_RV
CA_SetPedId.argtypes = [CK_SLOT_ID, CK_ULONG]
CA_GetPedId = make_late_binding_function("CA_GetPedId")
CA_GetPedId.restype = CK_RV
CA_GetPedId.argtypes = [CK_SLOT_ID, POINTER(CK_ULONG)]
CA_SpRawRead = make_late_binding_function("CA_SpRawRead")
CA_SpRawRead.restype = CK_RV
CA_SpRawRead.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_SpRawWrite = make_late_binding_function("CA_SpRawWrite")
CA_SpRawWrite.restype = CK_RV
CA_SpRawWrite.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_CheckOperationState = make_late_binding_function("CA_CheckOperationState")
CA_CheckOperationState.restype = CK_RV
CA_CheckOperationState.argtypes = [CK_SESSION_HANDLE, CK_ULONG, POINTER(CK_BBOOL)]
CA_DestroyMultipleObjects = make_late_binding_function("CA_DestroyMultipleObjects")
CA_DestroyMultipleObjects.restype = CK_RV
CA_DestroyMultipleObjects.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
    CK_ULONG_PTR,
]
CA_OpenSecureToken = make_late_binding_function("CA_OpenSecureToken")
CA_OpenSecureToken.restype = CK_RV
CA_OpenSecureToken.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    CK_ULONG,
    CK_ULONG,
    CK_ULONG,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG,
    CK_CHAR_PTR,
]
CA_CloseSecureToken = make_late_binding_function("CA_CloseSecureToken")
CA_CloseSecureToken.restype = CK_RV
CA_CloseSecureToken.argtypes = [CK_SESSION_HANDLE, CK_ULONG]
CA_ListSecureTokenInit = make_late_binding_function("CA_ListSecureTokenInit")
CA_ListSecureTokenInit.restype = CK_RV
CA_ListSecureTokenInit.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    CK_ULONG,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_BYTE_PTR,
]
CA_ListSecureTokenUpdate = make_late_binding_function("CA_ListSecureTokenUpdate")
CA_ListSecureTokenUpdate.restype = CK_RV
CA_ListSecureTokenUpdate.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG]
CA_GetSecureElementMeta = make_late_binding_function("CA_GetSecureElementMeta")
CA_GetSecureElementMeta.restype = CK_RV
CA_GetSecureElementMeta.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    CK_MECHANISM_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_BYTE_PTR,
    CK_ULONG,
]
CA_HAInit = make_late_binding_function("CA_HAInit")
CA_HAInit.restype = CK_RV
CA_HAInit.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
CA_HAGetMasterPublic = make_late_binding_function("CA_HAGetMasterPublic")
CA_HAGetMasterPublic.restype = CK_RV
CA_HAGetMasterPublic.argtypes = [CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG_PTR]
CA_HAGetLoginChallenge = make_late_binding_function("CA_HAGetLoginChallenge")
CA_HAGetLoginChallenge.restype = CK_RV
CA_HAGetLoginChallenge.argtypes = [
    CK_SESSION_HANDLE,
    CK_USER_TYPE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
]
CA_HAAnswerLoginChallenge = make_late_binding_function("CA_HAAnswerLoginChallenge")
CA_HAAnswerLoginChallenge.restype = CK_RV
CA_HAAnswerLoginChallenge.argtypes = [
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
]
CA_HALogin = make_late_binding_function("CA_HALogin")
CA_HALogin.restype = CK_RV
CA_HALogin.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_HAAnswerMofNChallenge = make_late_binding_function("CA_HAAnswerMofNChallenge")
CA_HAAnswerMofNChallenge.restype = CK_RV
CA_HAAnswerMofNChallenge.argtypes = [
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
]
CA_HAActivateMofN = make_late_binding_function("CA_HAActivateMofN")
CA_HAActivateMofN.restype = CK_RV
CA_HAActivateMofN.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
CA_GetHAState = make_late_binding_function("CA_GetHAState")
CA_GetHAState.restype = CK_RV
CA_GetHAState.argtypes = [CK_SLOT_ID, CK_HA_STATE_PTR]
CA_GetTokenCertificates = make_late_binding_function("CA_GetTokenCertificates")
CA_GetTokenCertificates.restype = CK_RV
CA_GetTokenCertificates.argtypes = [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_ExtractMaskedObject = make_late_binding_function("CA_ExtractMaskedObject")
CA_ExtractMaskedObject.restype = CK_RV
CA_ExtractMaskedObject.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_InsertMaskedObject = make_late_binding_function("CA_InsertMaskedObject")
CA_InsertMaskedObject.restype = CK_RV
CA_InsertMaskedObject.argtypes = [CK_SESSION_HANDLE, CK_ULONG_PTR, CK_BYTE_PTR, CK_ULONG]
CA_MultisignValue = make_late_binding_function("CA_MultisignValue")
CA_MultisignValue.restype = CK_RV
CA_MultisignValue.argtypes = [
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    POINTER(CK_BYTE_PTR),
    CK_ULONG_PTR,
    POINTER(CK_BYTE_PTR),
]
CA_SIMExtract = make_late_binding_function("CA_SIMExtract")
CA_SIMExtract.restype = CK_RV
CA_SIMExtract.argtypes = [
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
]
CA_SIMInsert = make_late_binding_function("CA_SIMInsert")
CA_SIMInsert.restype = CK_RV
CA_SIMInsert.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    CKA_SIM_AUTH_FORM,
    CK_ULONG_PTR,
    POINTER(CK_BYTE_PTR),
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
    CK_OBJECT_HANDLE_PTR,
]
CA_SIMMultiSign = make_late_binding_function("CA_SIMMultiSign")
CA_SIMMultiSign.restype = CK_RV
CA_SIMMultiSign.argtypes = [
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
]
CA_Extract = make_late_binding_function("CA_Extract")
CA_Extract.restype = CK_RV
CA_Extract.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR]
CA_Insert = make_late_binding_function("CA_Insert")
CA_Insert.restype = CK_RV
CA_Insert.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR]
CA_GetTokenObjectUID = make_late_binding_function("CA_GetTokenObjectUID")
CA_GetTokenObjectUID.restype = CK_RV
CA_GetTokenObjectUID.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, POINTER(CK_BYTE)]
CA_GetTokenObjectHandle = make_late_binding_function("CA_GetTokenObjectHandle")
CA_GetTokenObjectHandle.restype = CK_RV
CA_GetTokenObjectHandle.argtypes = [CK_SLOT_ID, POINTER(CK_BYTE), CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetObjectUID = make_late_binding_function("CA_GetObjectUID")
CA_GetObjectUID.restype = CK_RV
CA_GetObjectUID.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG, POINTER(CK_BYTE)]
CA_GetObjectHandle = make_late_binding_function("CA_GetObjectHandle")
CA_GetObjectHandle.restype = CK_RV
CA_GetObjectHandle.argtypes = [CK_SLOT_ID, CK_ULONG, POINTER(CK_BYTE), CK_ULONG_PTR, CK_ULONG_PTR]
CA_DeleteContainer = make_late_binding_function("CA_DeleteContainer")
CA_DeleteContainer.restype = CK_RV
CA_DeleteContainer.argtypes = [CK_SESSION_HANDLE]
CA_MTKSetStorage = make_late_binding_function("CA_MTKSetStorage")
CA_MTKSetStorage.restype = CK_RV
CA_MTKSetStorage.argtypes = [CK_SESSION_HANDLE, CK_ULONG]
CA_MTKRestore = make_late_binding_function("CA_MTKRestore")
CA_MTKRestore.restype = CK_RV
CA_MTKRestore.argtypes = [CK_SLOT_ID]
CA_MTKResplit = make_late_binding_function("CA_MTKResplit")
CA_MTKResplit.restype = CK_RV
CA_MTKResplit.argtypes = [CK_SLOT_ID]
CA_MTKZeroize = make_late_binding_function("CA_MTKZeroize")
CA_MTKZeroize.restype = CK_RV
CA_MTKZeroize.argtypes = [CK_SLOT_ID]
CA_MTKGetState = make_late_binding_function("CA_MTKGetState")
CA_MTKGetState.restype = CK_RV
CA_MTKGetState.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_TamperClear = make_late_binding_function("CA_TamperClear")
CA_TamperClear.restype = CK_RV
CA_TamperClear.argtypes = [CK_SESSION_HANDLE]
CA_STMToggle = make_late_binding_function("CA_STMToggle")
CA_STMToggle.restype = CK_RV
CA_STMToggle.argtypes = [CK_SESSION_HANDLE, CK_ULONG]
CA_STMGetState = make_late_binding_function("CA_STMGetState")
CA_STMGetState.restype = CK_RV
CA_STMGetState.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetTSV = make_late_binding_function("CA_GetTSV")
CA_GetTSV.restype = CK_RV
CA_GetTSV.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_InvokeServiceInit = make_late_binding_function("CA_InvokeServiceInit")
CA_InvokeServiceInit.restype = CK_RV
CA_InvokeServiceInit.argtypes = [CK_SESSION_HANDLE, CK_ULONG]
CA_InvokeService = make_late_binding_function("CA_InvokeService")
CA_InvokeService.restype = CK_RV
CA_InvokeService.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ULONG_PTR]
CA_InvokeServiceFinal = make_late_binding_function("CA_InvokeServiceFinal")
CA_InvokeServiceFinal.restype = CK_RV
CA_InvokeServiceFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
CA_InvokeServiceAsynch = make_late_binding_function("CA_InvokeServiceAsynch")
CA_InvokeServiceAsynch.restype = CK_RV
CA_InvokeServiceAsynch.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG]
CA_InvokeServiceSinglePart = make_late_binding_function("CA_InvokeServiceSinglePart")
CA_InvokeServiceSinglePart.restype = CK_RV
CA_InvokeServiceSinglePart.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
]
CA_EncodeECPrimeParams = make_late_binding_function("CA_EncodeECPrimeParams")
CA_EncodeECPrimeParams.restype = CK_RV
CA_EncodeECPrimeParams.argtypes = [
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
]
CA_EncodeECChar2Params = make_late_binding_function("CA_EncodeECChar2Params")
CA_EncodeECChar2Params.restype = CK_RV
CA_EncodeECChar2Params.argtypes = [
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
]
CA_EncodeECParamsFromFile = make_late_binding_function("CA_EncodeECParamsFromFile")
CA_EncodeECParamsFromFile.restype = CK_RV
CA_EncodeECParamsFromFile.argtypes = [CK_BYTE_PTR, CK_ULONG_PTR, CK_BYTE_PTR]
CA_GetHSMStats = make_late_binding_function("CA_GetHSMStats")
CA_GetHSMStats.restype = CK_RV
CA_GetHSMStats.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, POINTER(HSM_STATS_PARAMS)]
CA_GetHSMStorageInformation = make_late_binding_function("CA_GetHSMStorageInformation")
CA_GetHSMStorageInformation.restype = CK_RV
CA_GetHSMStorageInformation.argtypes = [
    CK_SLOT_ID,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
]
CA_GetTokenStorageInformation = make_late_binding_function("CA_GetTokenStorageInformation")
CA_GetTokenStorageInformation.restype = CK_RV
CA_GetTokenStorageInformation.argtypes = [
    CK_SLOT_ID,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
]
CA_GetContainerStorageInformation = make_late_binding_function("CA_GetContainerStorageInformation")
CA_GetContainerStorageInformation.restype = CK_RV
CA_GetContainerStorageInformation.argtypes = [
    CK_SLOT_ID,
    CK_ULONG,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
    CK_ULONG_PTR,
]
CA_SetContainerSize = make_late_binding_function("CA_SetContainerSize")
CA_SetContainerSize.restype = CK_RV
CA_SetContainerSize.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_CreateContainerWithPolicy = make_late_binding_function("CA_CreateContainerWithPolicy")
CA_CreateContainerWithPolicy.restype = CK_RV
CA_CreateContainerWithPolicy.argtypes = [
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
]
CA_CreateContainer = make_late_binding_function("CA_CreateContainer")
CA_CreateContainer.restype = CK_RV
CA_CreateContainer.argtypes = [
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
]
CA_InitAudit = make_late_binding_function("CA_InitAudit")
CA_InitAudit.restype = CK_RV
CA_InitAudit.argtypes = [CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR]
CA_LogVerify = make_late_binding_function("CA_LogVerify")
CA_LogVerify.restype = CK_RV
CA_LogVerify.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ULONG, CK_ULONG_PTR]
CA_LogVerifyFile = make_late_binding_function("CA_LogVerifyFile")
CA_LogVerifyFile.restype = CK_RV
CA_LogVerifyFile.argtypes = [CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG_PTR]
CA_LogExternal = make_late_binding_function("CA_LogExternal")
CA_LogExternal.restype = CK_RV
CA_LogExternal.argtypes = [CK_SLOT_ID, CK_SESSION_HANDLE, POINTER(CK_CHAR), CK_ULONG]
CA_LogImportSecret = make_late_binding_function("CA_LogImportSecret")
CA_LogImportSecret.restype = CK_RV
CA_LogImportSecret.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
CA_LogExportSecret = make_late_binding_function("CA_LogExportSecret")
CA_LogExportSecret.restype = CK_RV
CA_LogExportSecret.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
CA_TimeSync = make_late_binding_function("CA_TimeSync")
CA_TimeSync.restype = CK_RV
CA_TimeSync.argtypes = [CK_SESSION_HANDLE, CK_ULONG]
CA_GetTime = make_late_binding_function("CA_GetTime")
CA_GetTime.restype = CK_RV
CA_GetTime.argtypes = [CK_SESSION_HANDLE, CK_ULONG_PTR]
CA_LogSetConfig = make_late_binding_function("CA_LogSetConfig")
CA_LogSetConfig.restype = CK_RV
CA_LogSetConfig.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_BYTE_PTR]
CA_LogGetConfig = make_late_binding_function("CA_LogGetConfig")
CA_LogGetConfig.restype = CK_RV
CA_LogGetConfig.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_ULONG),
    POINTER(CK_ULONG),
    POINTER(CK_ULONG),
    POINTER(CK_ULONG),
    CK_BYTE_PTR,
]
CA_ReplaceFastPathKEK = make_late_binding_function("CA_ReplaceFastPathKEK")
CA_ReplaceFastPathKEK.restype = CK_RV
CA_ReplaceFastPathKEK.argtypes = [CK_SESSION_HANDLE]
CA_LogGetStatus = make_late_binding_function("CA_LogGetStatus")
CA_LogGetStatus.restype = CK_RV
CA_LogGetStatus.argtypes = [
    CK_SLOT_ID,
    POINTER(CK_ULONG),
    POINTER(CK_ULONG),
    POINTER(CK_ULONG),
    POINTER(CK_ULONG),
    POINTER(CK_ULONG),
]
CA_DeleteContainerWithHandle = make_late_binding_function("CA_DeleteContainerWithHandle")
CA_DeleteContainerWithHandle.restype = CK_RV
CA_DeleteContainerWithHandle.argtypes = [CK_SESSION_HANDLE, CK_ULONG]
CA_GetContainerList = make_late_binding_function("CA_GetContainerList")
CA_GetContainerList.restype = CK_RV
CA_GetContainerList.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetContainerName = make_late_binding_function("CA_GetContainerName")
CA_GetContainerName.restype = CK_RV
CA_GetContainerName.argtypes = [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_GetNumberOfAllowedContainers = make_late_binding_function("CA_GetNumberOfAllowedContainers")
CA_GetNumberOfAllowedContainers.restype = CK_RV
CA_GetNumberOfAllowedContainers.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetTunnelSlotNumber = make_late_binding_function("CA_GetTunnelSlotNumber")
CA_GetTunnelSlotNumber.restype = CK_RV
CA_GetTunnelSlotNumber.argtypes = [CK_SLOT_ID, CK_SLOT_ID_PTR]
CA_GetClusterState = make_late_binding_function("CA_GetClusterState")
CA_GetClusterState.restype = CK_RV
CA_GetClusterState.argtypes = [CK_SLOT_ID, CK_CLUSTER_STATE_PTR]
CA_LockClusteredSlot = make_late_binding_function("CA_LockClusteredSlot")
CA_LockClusteredSlot.restype = CK_RV
CA_LockClusteredSlot.argtypes = [CK_SLOT_ID]
CA_UnlockClusteredSlot = make_late_binding_function("CA_UnlockClusteredSlot")
CA_UnlockClusteredSlot.restype = CK_RV
CA_UnlockClusteredSlot.argtypes = [CK_SLOT_ID]
CA_LKMInitiatorChallenge = make_late_binding_function("CA_LKMInitiatorChallenge")
CA_LKMInitiatorChallenge.restype = CK_RV
CA_LKMInitiatorChallenge.argtypes = [
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CK_LKM_TOKEN_ID_PTR,
    CK_LKM_TOKEN_ID_PTR,
    CK_CHAR_PTR,
    CK_ULONG_PTR,
]
CA_LKMReceiverResponse = make_late_binding_function("CA_LKMReceiverResponse")
CA_LKMReceiverResponse.restype = CK_RV
CA_LKMReceiverResponse.argtypes = [
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CK_LKM_TOKEN_ID_PTR,
    CK_CHAR_PTR,
    CK_ULONG,
    CK_CHAR_PTR,
    CK_ULONG_PTR,
]
CA_LKMInitiatorComplete = make_late_binding_function("CA_LKMInitiatorComplete")
CA_LKMInitiatorComplete.restype = CK_RV
CA_LKMInitiatorComplete.argtypes = [
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
]
CA_LKMReceiverComplete = make_late_binding_function("CA_LKMReceiverComplete")
CA_LKMReceiverComplete.restype = CK_RV
CA_LKMReceiverComplete.argtypes = [
    CK_SESSION_HANDLE,
    CK_CHAR_PTR,
    CK_ULONG,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
    CK_OBJECT_HANDLE_PTR,
]
CA_ModifyUsageCount = make_late_binding_function("CA_ModifyUsageCount")
CA_ModifyUsageCount.restype = CK_RV
CA_ModifyUsageCount.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG, CK_ULONG]
CA_EnableUnauthTokenInsertion = make_late_binding_function("CA_EnableUnauthTokenInsertion")
CA_EnableUnauthTokenInsertion.restype = CK_RV
CA_EnableUnauthTokenInsertion.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
CA_GetUnauthTokenInsertionStatus = make_late_binding_function("CA_GetUnauthTokenInsertionStatus")
CA_GetUnauthTokenInsertionStatus.restype = CK_RV
CA_GetUnauthTokenInsertionStatus.argtypes = [
    CK_SESSION_HANDLE,
    CK_ULONG,
    POINTER(CK_ULONG),
    POINTER(CK_ULONG),
]
CA_DisableUnauthTokenInsertion = make_late_binding_function("CA_DisableUnauthTokenInsertion")
CA_DisableUnauthTokenInsertion.restype = CK_RV
CA_DisableUnauthTokenInsertion.argtypes = [CK_SESSION_HANDLE, CK_ULONG]
CA_STCRegister = make_late_binding_function("CA_STCRegister")
CA_STCRegister.restype = CK_RV
CA_STCRegister.argtypes = [
    CK_SESSION_HANDLE,
    CK_SLOT_ID,
    POINTER(CK_CHAR),
    CK_ULONG,
    POINTER(CK_CHAR),
    CK_ULONG,
    POINTER(CK_CHAR),
    CK_ULONG,
]
CA_STCDeregister = make_late_binding_function("CA_STCDeregister")
CA_STCDeregister.restype = CK_RV
CA_STCDeregister.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID, POINTER(CK_CHAR)]
CA_STCGetPubKey = make_late_binding_function("CA_STCGetPubKey")
CA_STCGetPubKey.restype = CK_RV
CA_STCGetPubKey.argtypes = [
    CK_SESSION_HANDLE,
    CK_SLOT_ID,
    POINTER(CK_CHAR),
    POINTER(CK_CHAR),
    CK_ULONG_PTR,
    POINTER(CK_CHAR),
    CK_ULONG_PTR,
]
CA_STCGetClientsList = make_late_binding_function("CA_STCGetClientsList")
CA_STCGetClientsList.restype = CK_RV
CA_STCGetClientsList.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR]
CA_STCGetClientInfo = make_late_binding_function("CA_STCGetClientInfo")
CA_STCGetClientInfo.restype = CK_RV
CA_STCGetClientInfo.argtypes = [
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
]
CA_STCGetPartPubKey = make_late_binding_function("CA_STCGetPartPubKey")
CA_STCGetPartPubKey.restype = CK_RV
CA_STCGetPartPubKey.argtypes = [
    CK_SESSION_HANDLE,
    CK_SLOT_ID,
    POINTER(CK_CHAR),
    CK_ULONG_PTR,
    POINTER(CK_CHAR),
    CK_ULONG_PTR,
]
CA_STCGetAdminPubKey = make_late_binding_function("CA_STCGetAdminPubKey")
CA_STCGetAdminPubKey.restype = CK_RV
CA_STCGetAdminPubKey.argtypes = [
    CK_SLOT_ID,
    POINTER(CK_CHAR),
    CK_ULONG_PTR,
    POINTER(CK_CHAR),
    CK_ULONG_PTR,
]
CA_STCSetCipherAlgorithm = make_late_binding_function("CA_STCSetCipherAlgorithm")
CA_STCSetCipherAlgorithm.restype = CK_RV
CA_STCSetCipherAlgorithm.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_STCGetCipherAlgorithm = make_late_binding_function("CA_STCGetCipherAlgorithm")
CA_STCGetCipherAlgorithm.restype = CK_RV
CA_STCGetCipherAlgorithm.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_STCClearCipherAlgorithm = make_late_binding_function("CA_STCClearCipherAlgorithm")
CA_STCClearCipherAlgorithm.restype = CK_RV
CA_STCClearCipherAlgorithm.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_STCSetDigestAlgorithm = make_late_binding_function("CA_STCSetDigestAlgorithm")
CA_STCSetDigestAlgorithm.restype = CK_RV
CA_STCSetDigestAlgorithm.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_STCGetDigestAlgorithm = make_late_binding_function("CA_STCGetDigestAlgorithm")
CA_STCGetDigestAlgorithm.restype = CK_RV
CA_STCGetDigestAlgorithm.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_STCClearDigestAlgorithm = make_late_binding_function("CA_STCClearDigestAlgorithm")
CA_STCClearDigestAlgorithm.restype = CK_RV
CA_STCClearDigestAlgorithm.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_STCSetKeyLifeTime = make_late_binding_function("CA_STCSetKeyLifeTime")
CA_STCSetKeyLifeTime.restype = CK_RV
CA_STCSetKeyLifeTime.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_STCGetKeyLifeTime = make_late_binding_function("CA_STCGetKeyLifeTime")
CA_STCGetKeyLifeTime.restype = CK_RV
CA_STCGetKeyLifeTime.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
CA_STCSetKeyActivationTimeOut = make_late_binding_function("CA_STCSetKeyActivationTimeOut")
CA_STCSetKeyActivationTimeOut.restype = CK_RV
CA_STCSetKeyActivationTimeOut.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_STCGetKeyActivationTimeOut = make_late_binding_function("CA_STCGetKeyActivationTimeOut")
CA_STCGetKeyActivationTimeOut.restype = CK_RV
CA_STCGetKeyActivationTimeOut.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
CA_STCSetMaxSessions = make_late_binding_function("CA_STCSetMaxSessions")
CA_STCSetMaxSessions.restype = CK_RV
CA_STCSetMaxSessions.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_STCGetMaxSessions = make_late_binding_function("CA_STCGetMaxSessions")
CA_STCGetMaxSessions.restype = CK_RV
CA_STCGetMaxSessions.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
CA_STCSetSequenceWindowSize = make_late_binding_function("CA_STCSetSequenceWindowSize")
CA_STCSetSequenceWindowSize.restype = CK_RV
CA_STCSetSequenceWindowSize.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_STCGetSequenceWindowSize = make_late_binding_function("CA_STCGetSequenceWindowSize")
CA_STCGetSequenceWindowSize.restype = CK_RV
CA_STCGetSequenceWindowSize.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
CA_STCIsEnabled = make_late_binding_function("CA_STCIsEnabled")
CA_STCIsEnabled.restype = CK_RV
CA_STCIsEnabled.argtypes = [CK_ULONG, CK_BYTE_PTR]
CA_STCGetState = make_late_binding_function("CA_STCGetState")
CA_STCGetState.restype = CK_RV
CA_STCGetState.argtypes = [CK_ULONG, POINTER(CK_CHAR), CK_BYTE]
CA_STCGetCurrentKeyLife = make_late_binding_function("CA_STCGetCurrentKeyLife")
CA_STCGetCurrentKeyLife.restype = CK_RV
CA_STCGetCurrentKeyLife.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR]
CA_GetSlotIdForPhysicalSlot = make_late_binding_function("CA_GetSlotIdForPhysicalSlot")
CA_GetSlotIdForPhysicalSlot.restype = CK_RV
CA_GetSlotIdForPhysicalSlot.argtypes = [CK_ULONG, CK_SLOT_ID_PTR]
CA_GetSlotIdForContainer = make_late_binding_function("CA_GetSlotIdForContainer")
CA_GetSlotIdForContainer.restype = CK_RV
CA_GetSlotIdForContainer.argtypes = [CK_ULONG, CK_ULONG, CK_SLOT_ID_PTR]
CA_STCGetChannelID = make_late_binding_function("CA_STCGetChannelID")
CA_STCGetChannelID.restype = CK_RV
CA_STCGetChannelID.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_STCGetCipherID = make_late_binding_function("CA_STCGetCipherID")
CA_STCGetCipherID.restype = CK_RV
CA_STCGetCipherID.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_STCGetDigestID = make_late_binding_function("CA_STCGetDigestID")
CA_STCGetDigestID.restype = CK_RV
CA_STCGetDigestID.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_STCGetCipherIDs = make_late_binding_function("CA_STCGetCipherIDs")
CA_STCGetCipherIDs.restype = CK_RV
CA_STCGetCipherIDs.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_BYTE_PTR]
CA_STCGetCipherNameByID = make_late_binding_function("CA_STCGetCipherNameByID")
CA_STCGetCipherNameByID.restype = CK_RV
CA_STCGetCipherNameByID.argtypes = [CK_SLOT_ID, CK_ULONG, CK_CHAR_PTR, CK_BYTE]
CA_STCGetDigestIDs = make_late_binding_function("CA_STCGetDigestIDs")
CA_STCGetDigestIDs.restype = CK_RV
CA_STCGetDigestIDs.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_BYTE_PTR]
CA_STCGetDigestNameByID = make_late_binding_function("CA_STCGetDigestNameByID")
CA_STCGetDigestNameByID.restype = CK_RV
CA_STCGetDigestNameByID.argtypes = [CK_SLOT_ID, CK_ULONG, CK_CHAR_PTR, CK_BYTE]
CA_GetServerInstanceBySlotID = make_late_binding_function("CA_GetServerInstanceBySlotID")
CA_GetServerInstanceBySlotID.restype = CK_RV
CA_GetServerInstanceBySlotID.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetSlotListFromServerInstance = make_late_binding_function("CA_GetSlotListFromServerInstance")
CA_GetSlotListFromServerInstance.restype = CK_RV
CA_GetSlotListFromServerInstance.argtypes = [CK_ULONG, CK_SLOT_ID_PTR, CK_ULONG_PTR]
CA_PerformSelfTest = make_late_binding_function("CA_PerformSelfTest")
CA_PerformSelfTest.restype = CK_RV
CA_PerformSelfTest.argtypes = [
    CK_SLOT_ID,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
]
CA_DeriveKeyAndWrap = make_late_binding_function("CA_DeriveKeyAndWrap")
CA_DeriveKeyAndWrap.restype = CK_RV
CA_DeriveKeyAndWrap.argtypes = [
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
]

CA_Get = make_late_binding_function("CA_Get")
CA_Get.restype = CK_RV
CA_Get.argtypes = [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]

CA_GetFirmwareVersion = make_late_binding_function("CA_GetFirmwareVersion")
CA_GetFirmwareVersion.restype = CK_RV
CA_GetFirmwareVersion.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]

C_Initialize = make_late_binding_function("C_Initialize")
C_Initialize.restype = CK_RV
C_Initialize.argtypes = [CK_VOID_PTR]
C_Finalize = make_late_binding_function("C_Finalize")
C_Finalize.restype = CK_RV
C_Finalize.argtypes = [CK_VOID_PTR]
C_GetInfo = make_late_binding_function("C_GetInfo")
C_GetInfo.restype = CK_RV
C_GetInfo.argtypes = [CK_INFO_PTR]
C_GetFunctionList = make_late_binding_function("C_GetFunctionList")
C_GetFunctionList.restype = CK_RV
C_GetFunctionList.argtypes = [CK_FUNCTION_LIST_PTR_PTR]
C_GetSlotList = make_late_binding_function("C_GetSlotList")
C_GetSlotList.restype = CK_RV
C_GetSlotList.argtypes = [CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR]
C_GetSlotInfo = make_late_binding_function("C_GetSlotInfo")
C_GetSlotInfo.restype = CK_RV
C_GetSlotInfo.argtypes = [CK_SLOT_ID, CK_SLOT_INFO_PTR]
C_GetTokenInfo = make_late_binding_function("C_GetTokenInfo")
C_GetTokenInfo.restype = CK_RV
C_GetTokenInfo.argtypes = [CK_SLOT_ID, CK_TOKEN_INFO_PTR]
C_GetMechanismList = make_late_binding_function("C_GetMechanismList")
C_GetMechanismList.restype = CK_RV
C_GetMechanismList.argtypes = [CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR]
C_GetMechanismInfo = make_late_binding_function("C_GetMechanismInfo")
C_GetMechanismInfo.restype = CK_RV
C_GetMechanismInfo.argtypes = [CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR]
C_InitToken = make_late_binding_function("C_InitToken")
C_InitToken.restype = CK_RV
C_InitToken.argtypes = [CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR]
C_InitPIN = make_late_binding_function("C_InitPIN")
C_InitPIN.restype = CK_RV
C_InitPIN.argtypes = [CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG]
C_SetPIN = make_late_binding_function("C_SetPIN")
C_SetPIN.restype = CK_RV
C_SetPIN.argtypes = [CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG]
C_OpenSession = make_late_binding_function("C_OpenSession")
C_OpenSession.restype = CK_RV
C_OpenSession.argtypes = [CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR]
C_CloseSession = make_late_binding_function("C_CloseSession")
C_CloseSession.restype = CK_RV
C_CloseSession.argtypes = [CK_SESSION_HANDLE]
C_CloseAllSessions = make_late_binding_function("C_CloseAllSessions")
C_CloseAllSessions.restype = CK_RV
C_CloseAllSessions.argtypes = [CK_SLOT_ID]
C_GetSessionInfo = make_late_binding_function("C_GetSessionInfo")
C_GetSessionInfo.restype = CK_RV
C_GetSessionInfo.argtypes = [CK_SESSION_HANDLE, CK_SESSION_INFO_PTR]
C_GetOperationState = make_late_binding_function("C_GetOperationState")
C_GetOperationState.restype = CK_RV
C_GetOperationState.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_SetOperationState = make_late_binding_function("C_SetOperationState")
C_SetOperationState.restype = CK_RV
C_SetOperationState.argtypes = [
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
]
C_Login = make_late_binding_function("C_Login")
C_Login.restype = CK_RV
C_Login.argtypes = [CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG]
C_Logout = make_late_binding_function("C_Logout")
C_Logout.restype = CK_RV
C_Logout.argtypes = [CK_SESSION_HANDLE]
C_CreateObject = make_late_binding_function("C_CreateObject")
C_CreateObject.restype = CK_RV
C_CreateObject.argtypes = [CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR]
C_CopyObject = make_late_binding_function("C_CopyObject")
C_CopyObject.restype = CK_RV
C_CopyObject.argtypes = [
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
]
C_DestroyObject = make_late_binding_function("C_DestroyObject")
C_DestroyObject.restype = CK_RV
C_DestroyObject.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
C_GetObjectSize = make_late_binding_function("C_GetObjectSize")
C_GetObjectSize.restype = CK_RV
C_GetObjectSize.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR]
C_GetAttributeValue = make_late_binding_function("C_GetAttributeValue")
C_GetAttributeValue.restype = CK_RV
C_GetAttributeValue.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
C_SetAttributeValue = make_late_binding_function("C_SetAttributeValue")
C_SetAttributeValue.restype = CK_RV
C_SetAttributeValue.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
C_FindObjectsInit = make_late_binding_function("C_FindObjectsInit")
C_FindObjectsInit.restype = CK_RV
C_FindObjectsInit.argtypes = [CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
C_FindObjects = make_late_binding_function("C_FindObjects")
C_FindObjects.restype = CK_RV
C_FindObjects.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR]
C_FindObjectsFinal = make_late_binding_function("C_FindObjectsFinal")
C_FindObjectsFinal.restype = CK_RV
C_FindObjectsFinal.argtypes = [CK_SESSION_HANDLE]
C_EncryptInit = make_late_binding_function("C_EncryptInit")
C_EncryptInit.restype = CK_RV
C_EncryptInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_Encrypt = make_late_binding_function("C_Encrypt")
C_Encrypt.restype = CK_RV
C_Encrypt.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_EncryptUpdate = make_late_binding_function("C_EncryptUpdate")
C_EncryptUpdate.restype = CK_RV
C_EncryptUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_EncryptFinal = make_late_binding_function("C_EncryptFinal")
C_EncryptFinal.restype = CK_RV
C_EncryptFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_DecryptInit = make_late_binding_function("C_DecryptInit")
C_DecryptInit.restype = CK_RV
C_DecryptInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_Decrypt = make_late_binding_function("C_Decrypt")
C_Decrypt.restype = CK_RV
C_Decrypt.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DecryptUpdate = make_late_binding_function("C_DecryptUpdate")
C_DecryptUpdate.restype = CK_RV
C_DecryptUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DecryptFinal = make_late_binding_function("C_DecryptFinal")
C_DecryptFinal.restype = CK_RV
C_DecryptFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_DigestInit = make_late_binding_function("C_DigestInit")
C_DigestInit.restype = CK_RV
C_DigestInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR]
C_Digest = make_late_binding_function("C_Digest")
C_Digest.restype = CK_RV
C_Digest.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DigestUpdate = make_late_binding_function("C_DigestUpdate")
C_DigestUpdate.restype = CK_RV
C_DigestUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_DigestKey = make_late_binding_function("C_DigestKey")
C_DigestKey.restype = CK_RV
C_DigestKey.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
C_DigestFinal = make_late_binding_function("C_DigestFinal")
C_DigestFinal.restype = CK_RV
C_DigestFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_SignInit = make_late_binding_function("C_SignInit")
C_SignInit.restype = CK_RV
C_SignInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_Sign = make_late_binding_function("C_Sign")
C_Sign.restype = CK_RV
C_Sign.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_SignUpdate = make_late_binding_function("C_SignUpdate")
C_SignUpdate.restype = CK_RV
C_SignUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_SignFinal = make_late_binding_function("C_SignFinal")
C_SignFinal.restype = CK_RV
C_SignFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_SignRecoverInit = make_late_binding_function("C_SignRecoverInit")
C_SignRecoverInit.restype = CK_RV
C_SignRecoverInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_SignRecover = make_late_binding_function("C_SignRecover")
C_SignRecover.restype = CK_RV
C_SignRecover.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_VerifyInit = make_late_binding_function("C_VerifyInit")
C_VerifyInit.restype = CK_RV
C_VerifyInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_Verify = make_late_binding_function("C_Verify")
C_Verify.restype = CK_RV
C_Verify.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG]
C_VerifyUpdate = make_late_binding_function("C_VerifyUpdate")
C_VerifyUpdate.restype = CK_RV
C_VerifyUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_VerifyFinal = make_late_binding_function("C_VerifyFinal")
C_VerifyFinal.restype = CK_RV
C_VerifyFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_VerifyRecoverInit = make_late_binding_function("C_VerifyRecoverInit")
C_VerifyRecoverInit.restype = CK_RV
C_VerifyRecoverInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_VerifyRecover = make_late_binding_function("C_VerifyRecover")
C_VerifyRecover.restype = CK_RV
C_VerifyRecover.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DigestEncryptUpdate = make_late_binding_function("C_DigestEncryptUpdate")
C_DigestEncryptUpdate.restype = CK_RV
C_DigestEncryptUpdate.argtypes = [
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
]
C_DecryptDigestUpdate = make_late_binding_function("C_DecryptDigestUpdate")
C_DecryptDigestUpdate.restype = CK_RV
C_DecryptDigestUpdate.argtypes = [
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
]
C_SignEncryptUpdate = make_late_binding_function("C_SignEncryptUpdate")
C_SignEncryptUpdate.restype = CK_RV
C_SignEncryptUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DecryptVerifyUpdate = make_late_binding_function("C_DecryptVerifyUpdate")
C_DecryptVerifyUpdate.restype = CK_RV
C_DecryptVerifyUpdate.argtypes = [
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
]
C_GenerateKey = make_late_binding_function("C_GenerateKey")
C_GenerateKey.restype = CK_RV
C_GenerateKey.argtypes = [
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
]
C_GenerateKeyPair = make_late_binding_function("C_GenerateKeyPair")
C_GenerateKeyPair.restype = CK_RV
C_GenerateKeyPair.argtypes = [
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
    CK_OBJECT_HANDLE_PTR,
]
C_WrapKey = make_late_binding_function("C_WrapKey")
C_WrapKey.restype = CK_RV
C_WrapKey.argtypes = [
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
]
C_UnwrapKey = make_late_binding_function("C_UnwrapKey")
C_UnwrapKey.restype = CK_RV
C_UnwrapKey.argtypes = [
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
]
C_DeriveKey = make_late_binding_function("C_DeriveKey")
C_DeriveKey.restype = CK_RV
C_DeriveKey.argtypes = [
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
]
C_SeedRandom = make_late_binding_function("C_SeedRandom")
C_SeedRandom.restype = CK_RV
C_SeedRandom.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_GenerateRandom = make_late_binding_function("C_GenerateRandom")
C_GenerateRandom.restype = CK_RV
C_GenerateRandom.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_GetFunctionStatus = make_late_binding_function("C_GetFunctionStatus")
C_GetFunctionStatus.restype = CK_RV
C_GetFunctionStatus.argtypes = [CK_SESSION_HANDLE]
C_CancelFunction = make_late_binding_function("C_CancelFunction")
C_CancelFunction.restype = CK_RV
C_CancelFunction.argtypes = [CK_SESSION_HANDLE]
C_WaitForSlotEvent = make_late_binding_function("C_WaitForSlotEvent")
C_WaitForSlotEvent.restype = CK_RV
C_WaitForSlotEvent.argtypes = [CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR]

CA_GetApplicationID = make_late_binding_function("CA_GetApplicationID")
CA_GetApplicationID.restype = CK_RV
CA_GetApplicationID.argtypes = [POINTER(CK_APPLICATION_ID)]

CA_OpenApplicationIDV2 = make_late_binding_function("CA_OpenApplicationIDV2")
CA_OpenApplicationIDV2.restype = CK_RV
CA_OpenApplicationIDV2.argtypes = [CK_SLOT_ID, POINTER(CK_APPLICATION_ID)]

CA_CloseApplicationIDV2 = make_late_binding_function("CA_CloseApplicationIDV2")
CA_CloseApplicationIDV2.restype = CK_RV
CA_CloseApplicationIDV2.argtypes = [CK_SLOT_ID, POINTER(CK_APPLICATION_ID)]

CA_SetApplicationIDV2 = make_late_binding_function("CA_SetApplicationIDV2")
CA_SetApplicationIDV2.restype = CK_RV
CA_SetApplicationIDV2.argypes = [POINTER(CK_APPLICATION_ID)]
