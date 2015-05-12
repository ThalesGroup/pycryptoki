'''
THIS FILE WAS CREATED AUTOMATICALLY AND CONTAINS AUTOMATICALLY GENERATED CODE
This file should NOT be checked into MKS or modified in any way, this file was
created by setup/initialize.py. Any changes to this file will be wiped out when
it is regenerated.

This file contains all of the ctypes definitions for the cryptoki library.
The ctypes definitions outline the structures for the cryptoki C API.
'''


from pycryptoki.cryptoki_helpers import make_late_binding_function
from ctypes import *

class CK_FUNCTION_LIST(Structure):
    pass
class CK_VERSION(Structure):
    pass
CK_BYTE = c_ubyte
CK_VERSION._fields_ = [
    ('major', CK_BYTE),
    ('minor', CK_BYTE),
]
CK_ULONG = c_ulong
CK_RV = CK_ULONG
CK_VOID_PTR = c_void_p
CK_C_Initialize = CFUNCTYPE(CK_RV, CK_VOID_PTR)
CK_C_Finalize = CFUNCTYPE(CK_RV, CK_VOID_PTR)
class CK_INFO(Structure):
    pass
CK_INFO_PTR = POINTER(CK_INFO)
CK_C_GetInfo = CFUNCTYPE(CK_RV, CK_INFO_PTR)
CK_FUNCTION_LIST_PTR = POINTER(CK_FUNCTION_LIST)
CK_FUNCTION_LIST_PTR_PTR = POINTER(CK_FUNCTION_LIST_PTR)
CK_C_GetFunctionList = CFUNCTYPE(CK_RV, CK_FUNCTION_LIST_PTR_PTR)
CK_BBOOL = CK_BYTE
CK_SLOT_ID = CK_ULONG
CK_SLOT_ID_PTR = POINTER(CK_SLOT_ID)
CK_ULONG_PTR = POINTER(CK_ULONG)
CK_C_GetSlotList = CFUNCTYPE(CK_RV, CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR)
class CK_SLOT_INFO(Structure):
    pass
CK_SLOT_INFO_PTR = POINTER(CK_SLOT_INFO)
CK_C_GetSlotInfo = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_SLOT_INFO_PTR)
class CK_TOKEN_INFO(Structure):
    pass
CK_TOKEN_INFO_PTR = POINTER(CK_TOKEN_INFO)
CK_C_GetTokenInfo = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_TOKEN_INFO_PTR)
CK_MECHANISM_TYPE = CK_ULONG
CK_MECHANISM_TYPE_PTR = POINTER(CK_MECHANISM_TYPE)
CK_C_GetMechanismList = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR)
class CK_MECHANISM_INFO(Structure):
    pass
CK_MECHANISM_INFO_PTR = POINTER(CK_MECHANISM_INFO)
CK_C_GetMechanismInfo = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR)
CK_UTF8CHAR = CK_BYTE
CK_UTF8CHAR_PTR = POINTER(CK_UTF8CHAR)
CK_C_InitToken = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR)
CK_SESSION_HANDLE = CK_ULONG
CK_C_InitPIN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG)
CK_C_SetPIN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG)
CK_FLAGS = CK_ULONG
CK_NOTIFICATION = CK_ULONG
CK_NOTIFY = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR)
CK_SESSION_HANDLE_PTR = POINTER(CK_SESSION_HANDLE)
CK_C_OpenSession = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR)
CK_C_CloseSession = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_C_CloseAllSessions = CFUNCTYPE(CK_RV, CK_SLOT_ID)
class CK_SESSION_INFO(Structure):
    pass
CK_SESSION_INFO_PTR = POINTER(CK_SESSION_INFO)
CK_C_GetSessionInfo = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_SESSION_INFO_PTR)
CK_BYTE_PTR = POINTER(CK_BYTE)
CK_C_GetOperationState = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_OBJECT_HANDLE = CK_ULONG
CK_C_SetOperationState = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)
CK_USER_TYPE = CK_ULONG
CK_C_Login = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG)
CK_C_Logout = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
class CK_ATTRIBUTE(Structure):
    pass
CK_ATTRIBUTE_PTR = POINTER(CK_ATTRIBUTE)
CK_OBJECT_HANDLE_PTR = POINTER(CK_OBJECT_HANDLE)
CK_C_CreateObject = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
CK_C_CopyObject = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
CK_C_DestroyObject = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE)
CK_C_GetObjectSize = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR)
CK_C_GetAttributeValue = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG)
CK_C_SetAttributeValue = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG)
CK_C_FindObjectsInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG)
CK_C_FindObjects = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR)
CK_C_FindObjectsFinal = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
class CK_MECHANISM(Structure):
    pass
CK_MECHANISM_PTR = POINTER(CK_MECHANISM)
CK_C_EncryptInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
CK_C_Encrypt = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_EncryptUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_EncryptFinal = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_DecryptInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
CK_C_Decrypt = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_DecryptUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_DecryptFinal = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_DigestInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR)
CK_C_Digest = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_DigestUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_C_DigestKey = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE)
CK_C_DigestFinal = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_SignInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
CK_C_Sign = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_SignUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_C_SignFinal = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_SignRecoverInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
CK_C_SignRecover = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_VerifyInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
CK_C_Verify = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)
CK_C_VerifyUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_C_VerifyFinal = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_C_VerifyRecoverInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
CK_C_VerifyRecover = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_DigestEncryptUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_DecryptDigestUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_SignEncryptUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_DecryptVerifyUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_GenerateKey = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
CK_C_GenerateKeyPair = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR)
CK_C_WrapKey = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_UnwrapKey = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
CK_C_DeriveKey = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
CK_C_SeedRandom = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_C_GenerateRandom = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_C_GetFunctionStatus = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_C_CancelFunction = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_C_WaitForSlotEvent = CFUNCTYPE(CK_RV, CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR)
CK_FUNCTION_LIST._fields_ = [
    ('version', CK_VERSION),
    ('C_Initialize', CK_C_Initialize),
    ('C_Finalize', CK_C_Finalize),
    ('C_GetInfo', CK_C_GetInfo),
    ('C_GetFunctionList', CK_C_GetFunctionList),
    ('C_GetSlotList', CK_C_GetSlotList),
    ('C_GetSlotInfo', CK_C_GetSlotInfo),
    ('C_GetTokenInfo', CK_C_GetTokenInfo),
    ('C_GetMechanismList', CK_C_GetMechanismList),
    ('C_GetMechanismInfo', CK_C_GetMechanismInfo),
    ('C_InitToken', CK_C_InitToken),
    ('C_InitPIN', CK_C_InitPIN),
    ('C_SetPIN', CK_C_SetPIN),
    ('C_OpenSession', CK_C_OpenSession),
    ('C_CloseSession', CK_C_CloseSession),
    ('C_CloseAllSessions', CK_C_CloseAllSessions),
    ('C_GetSessionInfo', CK_C_GetSessionInfo),
    ('C_GetOperationState', CK_C_GetOperationState),
    ('C_SetOperationState', CK_C_SetOperationState),
    ('C_Login', CK_C_Login),
    ('C_Logout', CK_C_Logout),
    ('C_CreateObject', CK_C_CreateObject),
    ('C_CopyObject', CK_C_CopyObject),
    ('C_DestroyObject', CK_C_DestroyObject),
    ('C_GetObjectSize', CK_C_GetObjectSize),
    ('C_GetAttributeValue', CK_C_GetAttributeValue),
    ('C_SetAttributeValue', CK_C_SetAttributeValue),
    ('C_FindObjectsInit', CK_C_FindObjectsInit),
    ('C_FindObjects', CK_C_FindObjects),
    ('C_FindObjectsFinal', CK_C_FindObjectsFinal),
    ('C_EncryptInit', CK_C_EncryptInit),
    ('C_Encrypt', CK_C_Encrypt),
    ('C_EncryptUpdate', CK_C_EncryptUpdate),
    ('C_EncryptFinal', CK_C_EncryptFinal),
    ('C_DecryptInit', CK_C_DecryptInit),
    ('C_Decrypt', CK_C_Decrypt),
    ('C_DecryptUpdate', CK_C_DecryptUpdate),
    ('C_DecryptFinal', CK_C_DecryptFinal),
    ('C_DigestInit', CK_C_DigestInit),
    ('C_Digest', CK_C_Digest),
    ('C_DigestUpdate', CK_C_DigestUpdate),
    ('C_DigestKey', CK_C_DigestKey),
    ('C_DigestFinal', CK_C_DigestFinal),
    ('C_SignInit', CK_C_SignInit),
    ('C_Sign', CK_C_Sign),
    ('C_SignUpdate', CK_C_SignUpdate),
    ('C_SignFinal', CK_C_SignFinal),
    ('C_SignRecoverInit', CK_C_SignRecoverInit),
    ('C_SignRecover', CK_C_SignRecover),
    ('C_VerifyInit', CK_C_VerifyInit),
    ('C_Verify', CK_C_Verify),
    ('C_VerifyUpdate', CK_C_VerifyUpdate),
    ('C_VerifyFinal', CK_C_VerifyFinal),
    ('C_VerifyRecoverInit', CK_C_VerifyRecoverInit),
    ('C_VerifyRecover', CK_C_VerifyRecover),
    ('C_DigestEncryptUpdate', CK_C_DigestEncryptUpdate),
    ('C_DecryptDigestUpdate', CK_C_DecryptDigestUpdate),
    ('C_SignEncryptUpdate', CK_C_SignEncryptUpdate),
    ('C_DecryptVerifyUpdate', CK_C_DecryptVerifyUpdate),
    ('C_GenerateKey', CK_C_GenerateKey),
    ('C_GenerateKeyPair', CK_C_GenerateKeyPair),
    ('C_WrapKey', CK_C_WrapKey),
    ('C_UnwrapKey', CK_C_UnwrapKey),
    ('C_DeriveKey', CK_C_DeriveKey),
    ('C_SeedRandom', CK_C_SeedRandom),
    ('C_GenerateRandom', CK_C_GenerateRandom),
    ('C_GetFunctionStatus', CK_C_GetFunctionStatus),
    ('C_CancelFunction', CK_C_CancelFunction),
    ('C_WaitForSlotEvent', CK_C_WaitForSlotEvent),
]
C_Initialize = make_late_binding_function('C_Initialize')
C_Initialize.restype = CK_RV
C_Initialize.argtypes = [CK_VOID_PTR]
C_Finalize = make_late_binding_function('C_Finalize')
C_Finalize.restype = CK_RV
C_Finalize.argtypes = [CK_VOID_PTR]
C_GetInfo = make_late_binding_function('C_GetInfo')
C_GetInfo.restype = CK_RV
C_GetInfo.argtypes = [CK_INFO_PTR]
C_GetFunctionList = make_late_binding_function('C_GetFunctionList')
C_GetFunctionList.restype = CK_RV
C_GetFunctionList.argtypes = [CK_FUNCTION_LIST_PTR_PTR]
C_GetSlotList = make_late_binding_function('C_GetSlotList')
C_GetSlotList.restype = CK_RV
C_GetSlotList.argtypes = [CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR]
C_GetSlotInfo = make_late_binding_function('C_GetSlotInfo')
C_GetSlotInfo.restype = CK_RV
C_GetSlotInfo.argtypes = [CK_SLOT_ID, CK_SLOT_INFO_PTR]
C_GetTokenInfo = make_late_binding_function('C_GetTokenInfo')
C_GetTokenInfo.restype = CK_RV
C_GetTokenInfo.argtypes = [CK_SLOT_ID, CK_TOKEN_INFO_PTR]
C_GetMechanismList = make_late_binding_function('C_GetMechanismList')
C_GetMechanismList.restype = CK_RV
C_GetMechanismList.argtypes = [CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR]
C_GetMechanismInfo = make_late_binding_function('C_GetMechanismInfo')
C_GetMechanismInfo.restype = CK_RV
C_GetMechanismInfo.argtypes = [CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR]
C_InitToken = make_late_binding_function('C_InitToken')
C_InitToken.restype = CK_RV
C_InitToken.argtypes = [CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR]
C_InitPIN = make_late_binding_function('C_InitPIN')
C_InitPIN.restype = CK_RV
C_InitPIN.argtypes = [CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG]
C_SetPIN = make_late_binding_function('C_SetPIN')
C_SetPIN.restype = CK_RV
C_SetPIN.argtypes = [CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG]
C_OpenSession = make_late_binding_function('C_OpenSession')
C_OpenSession.restype = CK_RV
C_OpenSession.argtypes = [CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR]
C_CloseSession = make_late_binding_function('C_CloseSession')
C_CloseSession.restype = CK_RV
C_CloseSession.argtypes = [CK_SESSION_HANDLE]
C_CloseAllSessions = make_late_binding_function('C_CloseAllSessions')
C_CloseAllSessions.restype = CK_RV
C_CloseAllSessions.argtypes = [CK_SLOT_ID]
C_GetSessionInfo = make_late_binding_function('C_GetSessionInfo')
C_GetSessionInfo.restype = CK_RV
C_GetSessionInfo.argtypes = [CK_SESSION_HANDLE, CK_SESSION_INFO_PTR]
C_GetOperationState = make_late_binding_function('C_GetOperationState')
C_GetOperationState.restype = CK_RV
C_GetOperationState.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_SetOperationState = make_late_binding_function('C_SetOperationState')
C_SetOperationState.restype = CK_RV
C_SetOperationState.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE]
C_Login = make_late_binding_function('C_Login')
C_Login.restype = CK_RV
C_Login.argtypes = [CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG]
C_Logout = make_late_binding_function('C_Logout')
C_Logout.restype = CK_RV
C_Logout.argtypes = [CK_SESSION_HANDLE]
C_CreateObject = make_late_binding_function('C_CreateObject')
C_CreateObject.restype = CK_RV
C_CreateObject.argtypes = [CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR]
C_CopyObject = make_late_binding_function('C_CopyObject')
C_CopyObject.restype = CK_RV
C_CopyObject.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR]
C_DestroyObject = make_late_binding_function('C_DestroyObject')
C_DestroyObject.restype = CK_RV
C_DestroyObject.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
C_GetObjectSize = make_late_binding_function('C_GetObjectSize')
C_GetObjectSize.restype = CK_RV
C_GetObjectSize.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR]
C_GetAttributeValue = make_late_binding_function('C_GetAttributeValue')
C_GetAttributeValue.restype = CK_RV
C_GetAttributeValue.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
C_SetAttributeValue = make_late_binding_function('C_SetAttributeValue')
C_SetAttributeValue.restype = CK_RV
C_SetAttributeValue.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
C_FindObjectsInit = make_late_binding_function('C_FindObjectsInit')
C_FindObjectsInit.restype = CK_RV
C_FindObjectsInit.argtypes = [CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
C_FindObjects = make_late_binding_function('C_FindObjects')
C_FindObjects.restype = CK_RV
C_FindObjects.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR]
C_FindObjectsFinal = make_late_binding_function('C_FindObjectsFinal')
C_FindObjectsFinal.restype = CK_RV
C_FindObjectsFinal.argtypes = [CK_SESSION_HANDLE]
C_EncryptInit = make_late_binding_function('C_EncryptInit')
C_EncryptInit.restype = CK_RV
C_EncryptInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_Encrypt = make_late_binding_function('C_Encrypt')
C_Encrypt.restype = CK_RV
C_Encrypt.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_EncryptUpdate = make_late_binding_function('C_EncryptUpdate')
C_EncryptUpdate.restype = CK_RV
C_EncryptUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_EncryptFinal = make_late_binding_function('C_EncryptFinal')
C_EncryptFinal.restype = CK_RV
C_EncryptFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_DecryptInit = make_late_binding_function('C_DecryptInit')
C_DecryptInit.restype = CK_RV
C_DecryptInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_Decrypt = make_late_binding_function('C_Decrypt')
C_Decrypt.restype = CK_RV
C_Decrypt.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DecryptUpdate = make_late_binding_function('C_DecryptUpdate')
C_DecryptUpdate.restype = CK_RV
C_DecryptUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DecryptFinal = make_late_binding_function('C_DecryptFinal')
C_DecryptFinal.restype = CK_RV
C_DecryptFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_DigestInit = make_late_binding_function('C_DigestInit')
C_DigestInit.restype = CK_RV
C_DigestInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR]
C_Digest = make_late_binding_function('C_Digest')
C_Digest.restype = CK_RV
C_Digest.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DigestUpdate = make_late_binding_function('C_DigestUpdate')
C_DigestUpdate.restype = CK_RV
C_DigestUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_DigestKey = make_late_binding_function('C_DigestKey')
C_DigestKey.restype = CK_RV
C_DigestKey.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
C_DigestFinal = make_late_binding_function('C_DigestFinal')
C_DigestFinal.restype = CK_RV
C_DigestFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_SignInit = make_late_binding_function('C_SignInit')
C_SignInit.restype = CK_RV
C_SignInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_Sign = make_late_binding_function('C_Sign')
C_Sign.restype = CK_RV
C_Sign.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_SignUpdate = make_late_binding_function('C_SignUpdate')
C_SignUpdate.restype = CK_RV
C_SignUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_SignFinal = make_late_binding_function('C_SignFinal')
C_SignFinal.restype = CK_RV
C_SignFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_SignRecoverInit = make_late_binding_function('C_SignRecoverInit')
C_SignRecoverInit.restype = CK_RV
C_SignRecoverInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_SignRecover = make_late_binding_function('C_SignRecover')
C_SignRecover.restype = CK_RV
C_SignRecover.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_VerifyInit = make_late_binding_function('C_VerifyInit')
C_VerifyInit.restype = CK_RV
C_VerifyInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_Verify = make_late_binding_function('C_Verify')
C_Verify.restype = CK_RV
C_Verify.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG]
C_VerifyUpdate = make_late_binding_function('C_VerifyUpdate')
C_VerifyUpdate.restype = CK_RV
C_VerifyUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_VerifyFinal = make_late_binding_function('C_VerifyFinal')
C_VerifyFinal.restype = CK_RV
C_VerifyFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_VerifyRecoverInit = make_late_binding_function('C_VerifyRecoverInit')
C_VerifyRecoverInit.restype = CK_RV
C_VerifyRecoverInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_VerifyRecover = make_late_binding_function('C_VerifyRecover')
C_VerifyRecover.restype = CK_RV
C_VerifyRecover.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DigestEncryptUpdate = make_late_binding_function('C_DigestEncryptUpdate')
C_DigestEncryptUpdate.restype = CK_RV
C_DigestEncryptUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DecryptDigestUpdate = make_late_binding_function('C_DecryptDigestUpdate')
C_DecryptDigestUpdate.restype = CK_RV
C_DecryptDigestUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_SignEncryptUpdate = make_late_binding_function('C_SignEncryptUpdate')
C_SignEncryptUpdate.restype = CK_RV
C_SignEncryptUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DecryptVerifyUpdate = make_late_binding_function('C_DecryptVerifyUpdate')
C_DecryptVerifyUpdate.restype = CK_RV
C_DecryptVerifyUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_GenerateKey = make_late_binding_function('C_GenerateKey')
C_GenerateKey.restype = CK_RV
C_GenerateKey.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR]
C_GenerateKeyPair = make_late_binding_function('C_GenerateKeyPair')
C_GenerateKeyPair.restype = CK_RV
C_GenerateKeyPair.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR]
C_WrapKey = make_late_binding_function('C_WrapKey')
C_WrapKey.restype = CK_RV
C_WrapKey.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_UnwrapKey = make_late_binding_function('C_UnwrapKey')
C_UnwrapKey.restype = CK_RV
C_UnwrapKey.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR]
C_DeriveKey = make_late_binding_function('C_DeriveKey')
C_DeriveKey.restype = CK_RV
C_DeriveKey.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR]
C_SeedRandom = make_late_binding_function('C_SeedRandom')
C_SeedRandom.restype = CK_RV
C_SeedRandom.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_GenerateRandom = make_late_binding_function('C_GenerateRandom')
C_GenerateRandom.restype = CK_RV
C_GenerateRandom.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_GetFunctionStatus = make_late_binding_function('C_GetFunctionStatus')
C_GetFunctionStatus.restype = CK_RV
C_GetFunctionStatus.argtypes = [CK_SESSION_HANDLE]
C_CancelFunction = make_late_binding_function('C_CancelFunction')
C_CancelFunction.restype = CK_RV
C_CancelFunction.argtypes = [CK_SESSION_HANDLE]
C_WaitForSlotEvent = make_late_binding_function('C_WaitForSlotEvent')
C_WaitForSlotEvent.restype = CK_RV
C_WaitForSlotEvent.argtypes = [CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR]
CK_CHAR = CK_BYTE
CK_LONG = c_long
CK_CHAR_PTR = POINTER(CK_CHAR)
CK_VOID_PTR_PTR = POINTER(CK_VOID_PTR)
CK_VERSION_PTR = POINTER(CK_VERSION)
CK_INFO._fields_ = [
    ('cryptokiVersion', CK_VERSION),
    ('manufacturerID', CK_UTF8CHAR * 32),
    ('flags', CK_FLAGS),
    ('libraryDescription', CK_UTF8CHAR * 32),
    ('libraryVersion', CK_VERSION),
]
CK_SLOT_INFO._fields_ = [
    ('slotDescription', CK_UTF8CHAR * 64),
    ('manufacturerID', CK_UTF8CHAR * 32),
    ('flags', CK_FLAGS),
    ('hardwareVersion', CK_VERSION),
    ('firmwareVersion', CK_VERSION),
]
CK_TOKEN_INFO._fields_ = [
    ('label', CK_UTF8CHAR * 32),
    ('manufacturerID', CK_UTF8CHAR * 32),
    ('model', CK_UTF8CHAR * 16),
    ('serialNumber', CK_CHAR * 16),
    ('flags', CK_FLAGS),
    ('usMaxSessionCount', CK_ULONG),
    ('usSessionCount', CK_ULONG),
    ('usMaxRwSessionCount', CK_ULONG),
    ('usRwSessionCount', CK_ULONG),
    ('usMaxPinLen', CK_ULONG),
    ('usMinPinLen', CK_ULONG),
    ('ulTotalPublicMemory', CK_ULONG),
    ('ulFreePublicMemory', CK_ULONG),
    ('ulTotalPrivateMemory', CK_ULONG),
    ('ulFreePrivateMemory', CK_ULONG),
    ('hardwareVersion', CK_VERSION),
    ('firmwareVersion', CK_VERSION),
    ('utcTime', CK_CHAR * 16),
]
CK_STATE = CK_ULONG
CK_SESSION_INFO._fields_ = [
    ('slotID', CK_SLOT_ID),
    ('state', CK_STATE),
    ('flags', CK_FLAGS),
    ('usDeviceError', CK_ULONG),
]
CK_OBJECT_CLASS = CK_ULONG
CK_OBJECT_CLASS_PTR = POINTER(CK_OBJECT_CLASS)
CK_HW_FEATURE_TYPE = CK_ULONG
CK_KEY_TYPE = CK_ULONG
CK_CERTIFICATE_TYPE = CK_ULONG
CK_ATTRIBUTE_TYPE = CK_ULONG
CK_ATTRIBUTE._fields_ = [
    ('type', CK_ATTRIBUTE_TYPE),
    ('pValue', CK_VOID_PTR),
    ('usValueLen', CK_ULONG),
]
class CK_DATE(Structure):
    pass
CK_DATE._fields_ = [
    ('year', CK_CHAR * 4),
    ('month', CK_CHAR * 2),
    ('day', CK_CHAR * 2),
]
CK_MECHANISM._fields_ = [
    ('mechanism', CK_MECHANISM_TYPE),
    ('pParameter', CK_VOID_PTR),
    ('usParameterLen', CK_ULONG),
]
CK_MECHANISM_INFO._fields_ = [
    ('ulMinKeySize', CK_ULONG),
    ('ulMaxKeySize', CK_ULONG),
    ('flags', CK_FLAGS),
]
CK_CREATEMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR_PTR)
CK_DESTROYMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR)
CK_LOCKMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR)
CK_UNLOCKMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR)
class CK_C_INITIALIZE_ARGS(Structure):
    pass
CK_C_INITIALIZE_ARGS._fields_ = [
    ('CreateMutex', CK_CREATEMUTEX),
    ('DestroyMutex', CK_DESTROYMUTEX),
    ('LockMutex', CK_LOCKMUTEX),
    ('UnlockMutex', CK_UNLOCKMUTEX),
    ('flags', CK_FLAGS),
    ('pReserved', CK_VOID_PTR),
]
CK_C_INITIALIZE_ARGS_PTR = POINTER(CK_C_INITIALIZE_ARGS)
CK_RSA_PKCS_MGF_TYPE = CK_ULONG
CK_RSA_PKCS_MGF_TYPE_PTR = POINTER(CK_RSA_PKCS_MGF_TYPE)
CK_RSA_PKCS_OAEP_SOURCE_TYPE = CK_ULONG
CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR = POINTER(CK_RSA_PKCS_OAEP_SOURCE_TYPE)
class CK_RSA_PKCS_OAEP_PARAMS(Structure):
    pass
CK_RSA_PKCS_OAEP_PARAMS._fields_ = [
    ('hashAlg', CK_MECHANISM_TYPE),
    ('mgf', CK_RSA_PKCS_MGF_TYPE),
    ('source', CK_RSA_PKCS_OAEP_SOURCE_TYPE),
    ('pSourceData', CK_VOID_PTR),
    ('ulSourceDataLen', CK_ULONG),
]
CK_RSA_PKCS_OAEP_PARAMS_PTR = POINTER(CK_RSA_PKCS_OAEP_PARAMS)
class CK_RSA_PKCS_PSS_PARAMS(Structure):
    pass
CK_RSA_PKCS_PSS_PARAMS._fields_ = [
    ('hashAlg', CK_MECHANISM_TYPE),
    ('mgf', CK_RSA_PKCS_MGF_TYPE),
    ('usSaltLen', CK_ULONG),
]
CK_RSA_PKCS_PSS_PARAMS_PTR = POINTER(CK_RSA_PKCS_PSS_PARAMS)
CK_EC_KDF_TYPE = CK_ULONG
class CK_ECDH1_DERIVE_PARAMS(Structure):
    pass
CK_ECDH1_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_EC_KDF_TYPE),
    ('ulSharedDataLen', CK_ULONG),
    ('pSharedData', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
]
CK_ECDH1_DERIVE_PARAMS_PTR = POINTER(CK_ECDH1_DERIVE_PARAMS)
class CK_ECDH2_DERIVE_PARAMS(Structure):
    pass
CK_ECDH2_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_EC_KDF_TYPE),
    ('ulSharedDataLen', CK_ULONG),
    ('pSharedData', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPrivateDataLen', CK_ULONG),
    ('hPrivateData', CK_OBJECT_HANDLE),
    ('ulPublicDataLen2', CK_ULONG),
    ('pPublicData2', CK_BYTE_PTR),
]
CK_ECDH2_DERIVE_PARAMS_PTR = POINTER(CK_ECDH2_DERIVE_PARAMS)
class CK_ECMQV_DERIVE_PARAMS(Structure):
    pass
CK_ECMQV_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_EC_KDF_TYPE),
    ('ulSharedDataLen', CK_ULONG),
    ('pSharedData', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPrivateDataLen', CK_ULONG),
    ('hPrivateData', CK_OBJECT_HANDLE),
    ('ulPublicDataLen2', CK_ULONG),
    ('pPublicData2', CK_BYTE_PTR),
    ('publicKey', CK_OBJECT_HANDLE),
]
CK_ECMQV_DERIVE_PARAMS_PTR = POINTER(CK_ECMQV_DERIVE_PARAMS)
CK_X9_42_DH_KDF_TYPE = CK_ULONG
CK_X9_42_DH_KDF_TYPE_PTR = POINTER(CK_X9_42_DH_KDF_TYPE)
class CK_X9_42_DH1_DERIVE_PARAMS(Structure):
    pass
CK_X9_42_DH1_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_X9_42_DH_KDF_TYPE),
    ('ulOtherInfoLen', CK_ULONG),
    ('pOtherInfo', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
]
CK_X9_42_DH1_DERIVE_PARAMS_PTR = POINTER(CK_X9_42_DH1_DERIVE_PARAMS)
class CK_X9_42_DH2_DERIVE_PARAMS(Structure):
    pass
CK_X9_42_DH2_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_X9_42_DH_KDF_TYPE),
    ('ulOtherInfoLen', CK_ULONG),
    ('pOtherInfo', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPrivateDataLen', CK_ULONG),
    ('hPrivateData', CK_OBJECT_HANDLE),
    ('ulPublicDataLen2', CK_ULONG),
    ('pPublicData2', CK_BYTE_PTR),
]
CK_X9_42_DH2_DERIVE_PARAMS_PTR = POINTER(CK_X9_42_DH2_DERIVE_PARAMS)
class CK_X9_42_MQV_DERIVE_PARAMS(Structure):
    pass
CK_X9_42_MQV_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_X9_42_DH_KDF_TYPE),
    ('ulOtherInfoLen', CK_ULONG),
    ('pOtherInfo', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPrivateDataLen', CK_ULONG),
    ('hPrivateData', CK_OBJECT_HANDLE),
    ('ulPublicDataLen2', CK_ULONG),
    ('pPublicData2', CK_BYTE_PTR),
    ('publicKey', CK_OBJECT_HANDLE),
]
CK_X9_42_MQV_DERIVE_PARAMS_PTR = POINTER(CK_X9_42_MQV_DERIVE_PARAMS)
class CK_KEA_DERIVE_PARAMS(Structure):
    pass
CK_KEA_DERIVE_PARAMS._fields_ = [
    ('isSender', CK_BBOOL),
    ('ulRandomLen', CK_ULONG),
    ('pRandomA', CK_BYTE_PTR),
    ('pRandomB', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
]
CK_KEA_DERIVE_PARAMS_PTR = POINTER(CK_KEA_DERIVE_PARAMS)
CK_RC2_PARAMS = CK_ULONG
CK_RC2_PARAMS_PTR = POINTER(CK_RC2_PARAMS)
class CK_RC2_CBC_PARAMS(Structure):
    pass
CK_RC2_CBC_PARAMS._fields_ = [
    ('usEffectiveBits', CK_ULONG),
    ('iv', CK_BYTE * 8),
]
CK_RC2_CBC_PARAMS_PTR = POINTER(CK_RC2_CBC_PARAMS)
class CK_RC2_MAC_GENERAL_PARAMS(Structure):
    pass
CK_RC2_MAC_GENERAL_PARAMS._fields_ = [
    ('usEffectiveBits', CK_ULONG),
    ('ulMacLength', CK_ULONG),
]
CK_RC2_MAC_GENERAL_PARAMS_PTR = POINTER(CK_RC2_MAC_GENERAL_PARAMS)
class CK_RC5_PARAMS(Structure):
    pass
CK_RC5_PARAMS._fields_ = [
    ('ulWordsize', CK_ULONG),
    ('ulRounds', CK_ULONG),
]
CK_RC5_PARAMS_PTR = POINTER(CK_RC5_PARAMS)
class CK_RC5_CBC_PARAMS(Structure):
    pass
CK_RC5_CBC_PARAMS._fields_ = [
    ('ulWordsize', CK_ULONG),
    ('ulRounds', CK_ULONG),
    ('pIv', CK_BYTE_PTR),
    ('ulIvLen', CK_ULONG),
]
CK_RC5_CBC_PARAMS_PTR = POINTER(CK_RC5_CBC_PARAMS)
class CK_RC5_MAC_GENERAL_PARAMS(Structure):
    pass
CK_RC5_MAC_GENERAL_PARAMS._fields_ = [
    ('ulWordsize', CK_ULONG),
    ('ulRounds', CK_ULONG),
    ('ulMacLength', CK_ULONG),
]
CK_RC5_MAC_GENERAL_PARAMS_PTR = POINTER(CK_RC5_MAC_GENERAL_PARAMS)
CK_MAC_GENERAL_PARAMS = CK_ULONG
CK_MAC_GENERAL_PARAMS_PTR = POINTER(CK_MAC_GENERAL_PARAMS)
class CK_DES_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass
CK_DES_CBC_ENCRYPT_DATA_PARAMS._fields_ = [
    ('iv', CK_BYTE * 8),
    ('pData', CK_BYTE_PTR),
    ('length', CK_ULONG),
]
CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_DES_CBC_ENCRYPT_DATA_PARAMS)
class CK_AES_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass
CK_AES_CBC_ENCRYPT_DATA_PARAMS._fields_ = [
    ('iv', CK_BYTE * 16),
    ('pData', CK_BYTE_PTR),
    ('length', CK_ULONG),
]
CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_AES_CBC_ENCRYPT_DATA_PARAMS)
class CK_SKIPJACK_PRIVATE_WRAP_PARAMS(Structure):
    pass
CK_SKIPJACK_PRIVATE_WRAP_PARAMS._fields_ = [
    ('usPasswordLen', CK_ULONG),
    ('pPassword', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPAndGLen', CK_ULONG),
    ('ulQLen', CK_ULONG),
    ('ulRandomLen', CK_ULONG),
    ('pRandomA', CK_BYTE_PTR),
    ('pPrimeP', CK_BYTE_PTR),
    ('pBaseG', CK_BYTE_PTR),
    ('pSubprimeQ', CK_BYTE_PTR),
]
CK_SKIPJACK_PRIVATE_WRAP_PTR = POINTER(CK_SKIPJACK_PRIVATE_WRAP_PARAMS)
class CK_SKIPJACK_RELAYX_PARAMS(Structure):
    pass
CK_SKIPJACK_RELAYX_PARAMS._fields_ = [
    ('ulOldWrappedXLen', CK_ULONG),
    ('pOldWrappedX', CK_BYTE_PTR),
    ('ulOldPasswordLen', CK_ULONG),
    ('pOldPassword', CK_BYTE_PTR),
    ('ulOldPublicDataLen', CK_ULONG),
    ('pOldPublicData', CK_BYTE_PTR),
    ('ulOldRandomLen', CK_ULONG),
    ('pOldRandomA', CK_BYTE_PTR),
    ('ulNewPasswordLen', CK_ULONG),
    ('pNewPassword', CK_BYTE_PTR),
    ('ulNewPublicDataLen', CK_ULONG),
    ('pNewPublicData', CK_BYTE_PTR),
    ('ulNewRandomLen', CK_ULONG),
    ('pNewRandomA', CK_BYTE_PTR),
]
CK_SKIPJACK_RELAYX_PARAMS_PTR = POINTER(CK_SKIPJACK_RELAYX_PARAMS)
class CK_PBE_PARAMS(Structure):
    pass
CK_PBE_PARAMS._fields_ = [
    ('pInitVector', CK_BYTE_PTR),
    ('pPassword', CK_UTF8CHAR_PTR),
    ('usPasswordLen', CK_ULONG),
    ('pSalt', CK_BYTE_PTR),
    ('usSaltLen', CK_ULONG),
    ('usIteration', CK_ULONG),
]
CK_PBE_PARAMS_PTR = POINTER(CK_PBE_PARAMS)
class CK_KEY_WRAP_SET_OAEP_PARAMS(Structure):
    pass
CK_KEY_WRAP_SET_OAEP_PARAMS._fields_ = [
    ('bBC', CK_BYTE),
    ('pX', CK_BYTE_PTR),
    ('ulXLen', CK_ULONG),
]
CK_KEY_WRAP_SET_OAEP_PARAMS_PTR = POINTER(CK_KEY_WRAP_SET_OAEP_PARAMS)
class CK_SSL3_RANDOM_DATA(Structure):
    pass
CK_SSL3_RANDOM_DATA._fields_ = [
    ('pClientRandom', CK_BYTE_PTR),
    ('ulClientRandomLen', CK_ULONG),
    ('pServerRandom', CK_BYTE_PTR),
    ('ulServerRandomLen', CK_ULONG),
]
class CK_SSL3_MASTER_KEY_DERIVE_PARAMS(Structure):
    pass
CK_SSL3_MASTER_KEY_DERIVE_PARAMS._fields_ = [
    ('RandomInfo', CK_SSL3_RANDOM_DATA),
    ('pVersion', CK_VERSION_PTR),
]
CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR = POINTER(CK_SSL3_MASTER_KEY_DERIVE_PARAMS)
class CK_SSL3_KEY_MAT_OUT(Structure):
    pass
CK_SSL3_KEY_MAT_OUT._fields_ = [
    ('hClientMacSecret', CK_OBJECT_HANDLE),
    ('hServerMacSecret', CK_OBJECT_HANDLE),
    ('hClientKey', CK_OBJECT_HANDLE),
    ('hServerKey', CK_OBJECT_HANDLE),
    ('pIVClient', CK_BYTE_PTR),
    ('pIVServer', CK_BYTE_PTR),
]
CK_SSL3_KEY_MAT_OUT_PTR = POINTER(CK_SSL3_KEY_MAT_OUT)
class CK_SSL3_KEY_MAT_PARAMS(Structure):
    pass
CK_SSL3_KEY_MAT_PARAMS._fields_ = [
    ('ulMacSizeInBits', CK_ULONG),
    ('ulKeySizeInBits', CK_ULONG),
    ('ulIVSizeInBits', CK_ULONG),
    ('bIsExport', CK_BBOOL),
    ('RandomInfo', CK_SSL3_RANDOM_DATA),
    ('pReturnedKeyMaterial', CK_SSL3_KEY_MAT_OUT_PTR),
]
CK_SSL3_KEY_MAT_PARAMS_PTR = POINTER(CK_SSL3_KEY_MAT_PARAMS)
class CK_TLS_PRF_PARAMS(Structure):
    pass
CK_TLS_PRF_PARAMS._fields_ = [
    ('pSeed', CK_BYTE_PTR),
    ('ulSeedLen', CK_ULONG),
    ('pLabel', CK_BYTE_PTR),
    ('ulLabelLen', CK_ULONG),
    ('pOutput', CK_BYTE_PTR),
    ('pulOutputLen', CK_ULONG_PTR),
]
CK_TLS_PRF_PARAMS_PTR = POINTER(CK_TLS_PRF_PARAMS)
class CK_WTLS_RANDOM_DATA(Structure):
    pass
CK_WTLS_RANDOM_DATA._fields_ = [
    ('pClientRandom', CK_BYTE_PTR),
    ('ulClientRandomLen', CK_ULONG),
    ('pServerRandom', CK_BYTE_PTR),
    ('ulServerRandomLen', CK_ULONG),
]
CK_WTLS_RANDOM_DATA_PTR = POINTER(CK_WTLS_RANDOM_DATA)
class CK_WTLS_MASTER_KEY_DERIVE_PARAMS(Structure):
    pass
CK_WTLS_MASTER_KEY_DERIVE_PARAMS._fields_ = [
    ('DigestMechanism', CK_MECHANISM_TYPE),
    ('RandomInfo', CK_WTLS_RANDOM_DATA),
    ('pVersion', CK_BYTE_PTR),
]
CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR = POINTER(CK_WTLS_MASTER_KEY_DERIVE_PARAMS)
class CK_WTLS_PRF_PARAMS(Structure):
    pass
CK_WTLS_PRF_PARAMS._fields_ = [
    ('DigestMechanism', CK_MECHANISM_TYPE),
    ('pSeed', CK_BYTE_PTR),
    ('ulSeedLen', CK_ULONG),
    ('pLabel', CK_BYTE_PTR),
    ('ulLabelLen', CK_ULONG),
    ('pOutput', CK_BYTE_PTR),
    ('pulOutputLen', CK_ULONG_PTR),
]
CK_WTLS_PRF_PARAMS_PTR = POINTER(CK_WTLS_PRF_PARAMS)
class CK_WTLS_KEY_MAT_OUT(Structure):
    pass
CK_WTLS_KEY_MAT_OUT._fields_ = [
    ('hMacSecret', CK_OBJECT_HANDLE),
    ('hKey', CK_OBJECT_HANDLE),
    ('pIV', CK_BYTE_PTR),
]
CK_WTLS_KEY_MAT_OUT_PTR = POINTER(CK_WTLS_KEY_MAT_OUT)
class CK_WTLS_KEY_MAT_PARAMS(Structure):
    pass
CK_WTLS_KEY_MAT_PARAMS._fields_ = [
    ('DigestMechanism', CK_MECHANISM_TYPE),
    ('ulMacSizeInBits', CK_ULONG),
    ('ulKeySizeInBits', CK_ULONG),
    ('ulIVSizeInBits', CK_ULONG),
    ('ulSequenceNumber', CK_ULONG),
    ('bIsExport', CK_BBOOL),
    ('RandomInfo', CK_WTLS_RANDOM_DATA),
    ('pReturnedKeyMaterial', CK_WTLS_KEY_MAT_OUT_PTR),
]
CK_WTLS_KEY_MAT_PARAMS_PTR = POINTER(CK_WTLS_KEY_MAT_PARAMS)
class CK_CMS_SIG_PARAMS(Structure):
    pass
CK_CMS_SIG_PARAMS._fields_ = [
    ('certificateHandle', CK_OBJECT_HANDLE),
    ('pSigningMechanism', CK_MECHANISM_PTR),
    ('pDigestMechanism', CK_MECHANISM_PTR),
    ('pContentType', CK_UTF8CHAR_PTR),
    ('pRequestedAttributes', CK_BYTE_PTR),
    ('ulRequestedAttributesLen', CK_ULONG),
    ('pRequiredAttributes', CK_BYTE_PTR),
    ('ulRequiredAttributesLen', CK_ULONG),
]
CK_CMS_SIG_PARAMS_PTR = POINTER(CK_CMS_SIG_PARAMS)
class CK_KEY_DERIVATION_STRING_DATA(Structure):
    pass
CK_KEY_DERIVATION_STRING_DATA._fields_ = [
    ('pData', CK_BYTE_PTR),
    ('ulLen', CK_ULONG),
]
CK_KEY_DERIVATION_STRING_DATA_PTR = POINTER(CK_KEY_DERIVATION_STRING_DATA)
CK_EXTRACT_PARAMS = CK_ULONG
CK_EXTRACT_PARAMS_PTR = POINTER(CK_EXTRACT_PARAMS)
CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = CK_ULONG
CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR = POINTER(CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE)
CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE = CK_ULONG
CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR = POINTER(CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE)
class CK_PKCS5_PBKD2_PARAMS(Structure):
    pass
CK_PKCS5_PBKD2_PARAMS._fields_ = [
    ('saltSource', CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE),
    ('pSaltSourceData', CK_VOID_PTR),
    ('ulSaltSourceDataLen', CK_ULONG),
    ('iterations', CK_ULONG),
    ('prf', CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE),
    ('pPrfData', CK_VOID_PTR),
    ('ulPrfDataLen', CK_ULONG),
    ('pPassword', CK_UTF8CHAR_PTR),
    ('usPasswordLen', CK_ULONG),
]
CK_PKCS5_PBKD2_PARAMS_PTR = POINTER(CK_PKCS5_PBKD2_PARAMS)
CK_OTP_PARAM_TYPE = CK_ULONG
CK_PARAM_TYPE = CK_OTP_PARAM_TYPE
class CK_OTP_PARAM(Structure):
    pass
CK_OTP_PARAM._fields_ = [
    ('type', CK_OTP_PARAM_TYPE),
    ('pValue', CK_VOID_PTR),
    ('usValueLen', CK_ULONG),
]
CK_OTP_PARAM_PTR = POINTER(CK_OTP_PARAM)
class CK_OTP_PARAMS(Structure):
    pass
CK_OTP_PARAMS._fields_ = [
    ('pParams', CK_OTP_PARAM_PTR),
    ('ulCount', CK_ULONG),
]
CK_OTP_PARAMS_PTR = POINTER(CK_OTP_PARAMS)
class CK_OTP_SIGNATURE_INFO(Structure):
    pass
CK_OTP_SIGNATURE_INFO._fields_ = [
    ('pParams', CK_OTP_PARAM_PTR),
    ('ulCount', CK_ULONG),
]
CK_OTP_SIGNATURE_INFO_PTR = POINTER(CK_OTP_SIGNATURE_INFO)
class CK_KIP_PARAMS(Structure):
    pass
CK_KIP_PARAMS._fields_ = [
    ('pMechanism', CK_MECHANISM_PTR),
    ('hKey', CK_OBJECT_HANDLE),
    ('pSeed', CK_BYTE_PTR),
    ('ulSeedLen', CK_ULONG),
]
CK_KIP_PARAMS_PTR = POINTER(CK_KIP_PARAMS)
class CK_AES_CTR_PARAMS(Structure):
    pass
CK_AES_CTR_PARAMS._fields_ = [
    ('ulCounterBits', CK_ULONG),
    ('cb', CK_BYTE * 16),
]
CK_AES_CTR_PARAMS_PTR = POINTER(CK_AES_CTR_PARAMS)
class CK_CAMELLIA_CTR_PARAMS(Structure):
    pass
CK_CAMELLIA_CTR_PARAMS._fields_ = [
    ('ulCounterBits', CK_ULONG),
    ('cb', CK_BYTE * 16),
]
CK_CAMELLIA_CTR_PARAMS_PTR = POINTER(CK_CAMELLIA_CTR_PARAMS)
class CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass
CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS._fields_ = [
    ('iv', CK_BYTE * 16),
    ('pData', CK_BYTE_PTR),
    ('length', CK_ULONG),
]
CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS)
class CK_ARIA_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass
CK_ARIA_CBC_ENCRYPT_DATA_PARAMS._fields_ = [
    ('iv', CK_BYTE * 16),
    ('pData', CK_BYTE_PTR),
    ('length', CK_ULONG),
]
CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS)
CK_USHORT = c_ulong
CK_USHORT_PTR = POINTER(CK_USHORT)
class CK_AES_GCM_PARAMS(Structure):
    pass
CK_AES_GCM_PARAMS._fields_ = [
    ('pIv', CK_BYTE_PTR),
    ('ulIvLen', CK_ULONG),
    ('ulIvBits', CK_ULONG),
    ('pAAD', CK_BYTE_PTR),
    ('ulAADLen', CK_ULONG),
    ('ulTagBits', CK_ULONG),
]
CK_AES_GCM_PARAMS_PTR = CK_AES_GCM_PARAMS
class CK_XOR_BASE_DATA_KDF_PARAMS(Structure):
    pass
CK_XOR_BASE_DATA_KDF_PARAMS._fields_ = [
    ('kdf', CK_EC_KDF_TYPE),
    ('ulSharedDataLen', CK_ULONG),
    ('pSharedData', CK_BYTE_PTR),
]
CK_XOR_BASE_DATA_KDF_PARAMS_PTR = POINTER(CK_XOR_BASE_DATA_KDF_PARAMS)
CK_EC_DH_PRIMITIVE = CK_ULONG
CK_EC_ENC_SCHEME = CK_ULONG
CK_EC_MAC_SCHEME = CK_ULONG
class CK_ECIES_PARAMS(Structure):
    pass
CK_ECIES_PARAMS._fields_ = [
    ('dhPrimitive', CK_EC_DH_PRIMITIVE),
    ('kdf', CK_EC_KDF_TYPE),
    ('ulSharedDataLen1', CK_ULONG),
    ('pSharedData1', CK_BYTE_PTR),
    ('encScheme', CK_EC_ENC_SCHEME),
    ('ulEncKeyLenInBits', CK_ULONG),
    ('macScheme', CK_EC_MAC_SCHEME),
    ('ulMacKeyLenInBits', CK_ULONG),
    ('ulMacLenInBits', CK_ULONG),
    ('ulSharedDataLen2', CK_ULONG),
    ('pSharedData2', CK_BYTE_PTR),
]
CK_ECIES_PARAMS_PTR = POINTER(CK_ECIES_PARAMS)
CK_KDF_PRF_TYPE = CK_ULONG
CK_KDF_PRF_ENCODING_SCHEME = CK_ULONG
class CK_KDF_PRF_PARAMS(Structure):
    pass
CK_KDF_PRF_PARAMS._fields_ = [
    ('prfType', CK_KDF_PRF_TYPE),
    ('pLabel', CK_BYTE_PTR),
    ('ulLabelLen', CK_ULONG),
    ('pContext', CK_BYTE_PTR),
    ('ulContextLen', CK_ULONG),
    ('ulCounter', CK_ULONG),
    ('ulEncodingScheme', CK_KDF_PRF_ENCODING_SCHEME),
]
CK_PRF_KDF_PARAMS = CK_KDF_PRF_PARAMS
CK_KDF_PRF_PARAMS_PTR = POINTER(CK_PRF_KDF_PARAMS)
CK_SEED_CTR_PARAMS = CK_AES_CTR_PARAMS
CK_SEED_CTR_PARAMS_PTR = POINTER(CK_SEED_CTR_PARAMS)
CK_ARIA_CTR_PARAMS = CK_AES_CTR_PARAMS
CK_ARIA_CTR_PARAMS_PTR = POINTER(CK_ARIA_CTR_PARAMS)
class CK_DES_CTR_PARAMS(Structure):
    pass
CK_DES_CTR_PARAMS._fields_ = [
    ('ulCounterBits', CK_ULONG),
    ('cb', CK_BYTE * 8),
]
CK_DES_CTR_PARAMS_PTR = POINTER(CK_DES_CTR_PARAMS)
CK_AES_GMAC_PARAMS = CK_AES_GCM_PARAMS
CK_AES_GMAC_PARAMS_PTR = POINTER(CK_AES_GMAC_PARAMS)
class CA_MOFN_GENERATION(Structure):
    pass
CA_MOFN_GENERATION._fields_ = [
    ('ulWeight', CK_ULONG),
    ('pVector', CK_BYTE_PTR),
    ('ulVectorLen', CK_ULONG),
]
CA_MOFN_GENERATION_PTR = POINTER(CA_MOFN_GENERATION)
class CA_MOFN_ACTIVATION(Structure):
    pass
CA_MOFN_ACTIVATION._fields_ = [
    ('pVector', CK_BYTE_PTR),
    ('ulVectorLen', CK_ULONG),
]
CA_MOFN_ACTIVATION_PTR = POINTER(CA_MOFN_ACTIVATION)
class CA_M_OF_N_STATUS(Structure):
    pass
CA_M_OF_N_STATUS._fields_ = [
    ('ulID', CK_ULONG),
    ('ulM', CK_ULONG),
    ('ulN', CK_ULONG),
    ('ulSecretSize', CK_ULONG),
    ('ulFlag', CK_ULONG),
]
CA_MOFN_STATUS = CA_M_OF_N_STATUS
CA_MOFN_STATUS_PTR = POINTER(CA_MOFN_STATUS)
CKCA_MODULE_ID = CK_ULONG
CKCA_MODULE_ID_PTR = POINTER(CKCA_MODULE_ID)
class CKCA_MODULE_INFO(Structure):
    pass
CKCA_MODULE_INFO._fields_ = [
    ('ulModuleSize', CK_ULONG),
    ('developerName', CK_CHAR * 32),
    ('moduleDescription', CK_CHAR * 32),
    ('moduleVersion', CK_VERSION),
]
CKCA_MODULE_INFO_PTR = POINTER(CKCA_MODULE_INFO)
class CK_HA_MEMBER(Structure):
    pass
CK_HA_MEMBER._fields_ = [
    ('memberSerial', CK_ULONG),
    ('memberStatus', CK_RV),
]
class CK_HA_STATUS(Structure):
    pass
CK_HA_STATUS._fields_ = [
    ('groupSerial', CK_ULONG),
    ('memberList', CK_HA_MEMBER * 32),
    ('listSize', CK_ULONG),
]
CK_HA_MEMBER_PTR = POINTER(CK_HA_MEMBER)
CK_HA_STATE_PTR = POINTER(CK_HA_STATUS)
CKA_SIM_AUTH_FORM = CK_ULONG
class CK_AES_CBC_PAD_EXTRACT_PARAMS(Structure):
    pass
CK_AES_CBC_PAD_EXTRACT_PARAMS._fields_ = [
    ('ulType', CK_ULONG),
    ('ulHandle', CK_ULONG),
    ('ulDeleteAfterExtract', CK_ULONG),
    ('pBuffer', CK_BYTE_PTR),
    ('pulBufferLen', CK_ULONG_PTR),
    ('ulStorage', CK_ULONG),
    ('pedId', CK_ULONG),
    ('pbFileName', CK_BYTE_PTR),
]
CK_AES_CBC_PAD_EXTRACT_PARAMS_PTR = POINTER(CK_AES_CBC_PAD_EXTRACT_PARAMS)
class CK_AES_CBC_PAD_INSERT_PARAMS(Structure):
    pass
CK_AES_CBC_PAD_INSERT_PARAMS._fields_ = [
    ('ulStorageType', CK_ULONG),
    ('ulContainerState', CK_ULONG),
    ('pBuffer', CK_BYTE_PTR),
    ('ulBufferLen', CK_ULONG),
    ('pulType', CK_ULONG_PTR),
    ('pulHandle', CK_ULONG_PTR),
    ('ulStorage', CK_ULONG),
    ('pedId', CK_ULONG),
    ('pbFileName', CK_BYTE_PTR),
]
CK_AES_CBC_PAD_INSERT_PARAMS_PTR = POINTER(CK_AES_CBC_PAD_INSERT_PARAMS)
class CK_CLUSTER_STATE(Structure):
    pass
CK_CLUSTER_STATE._fields_ = [
    ('bMembers', CK_BYTE * 32 * 8),
    ('ulMemberStatus', CK_ULONG * 8),
]
CK_CLUSTER_STATE_PTR = POINTER(CK_CLUSTER_STATE)
class CK_LKM_TOKEN_ID_S(Structure):
    pass
CK_LKM_TOKEN_ID_S._fields_ = [
    ('id', CK_BYTE * 20),
]
CK_LKM_TOKEN_ID = CK_LKM_TOKEN_ID_S
CK_LKM_TOKEN_ID_PTR = POINTER(CK_LKM_TOKEN_ID)
class CK_SFNT_CA_FUNCTION_LIST(Structure):
    pass
CK_SFNT_CA_FUNCTION_LIST_PTR = POINTER(CK_SFNT_CA_FUNCTION_LIST)
CK_SFNT_CA_FUNCTION_LIST_PTR_PTR = POINTER(CK_SFNT_CA_FUNCTION_LIST_PTR)
CK_CA_GetFunctionList = CFUNCTYPE(CK_RV, CK_SFNT_CA_FUNCTION_LIST_PTR_PTR)
CK_CA_WaitForSlotEvent = CFUNCTYPE(CK_RV, CK_FLAGS, POINTER(CK_ULONG), CK_SLOT_ID_PTR, CK_VOID_PTR)
CK_CA_InitIndirectToken = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR, CK_SESSION_HANDLE)
CK_CA_InitIndirectPIN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG, CK_SESSION_HANDLE)
CK_CA_ResetPIN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG)
CK_CA_CreateLoginChallenge = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_USER_TYPE, CK_ULONG, CK_CHAR_PTR, CK_ULONG_PTR, CK_CHAR_PTR)
CK_CA_Deactivate = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_USER_TYPE)
CK_CA_OpenSession = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR)
CK_CA_IndirectLogin = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_USER_TYPE, CK_SESSION_HANDLE)
CK_CA_InitializeRemotePEDVector = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_CA_DeleteRemotePEDVector = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_CA_GetRemotePEDVectorStatus = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR)
CK_CA_ConfigureRemotePED = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_ULONG_PTR)
CK_CA_DismantleRemotePED = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG)
CK_CA_Restart = CFUNCTYPE(CK_RV, CK_SLOT_ID)
CK_CA_RestartForContainer = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG)
CK_CA_CloseApplicationID = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG)
CK_CA_CloseApplicationIDForContainer = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG)
CK_CA_OpenApplicationID = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG)
CK_CA_OpenApplicationIDForContainer = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG)
CK_CA_SetApplicationID = CFUNCTYPE(CK_RV, CK_ULONG, CK_ULONG)
CK_CA_ManualKCV = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_CA_SetLKCV = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_CA_SetKCV = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_CA_SetCloningDomain = CFUNCTYPE(CK_RV, CK_BYTE_PTR, CK_ULONG)
CK_CA_ClonePrivateKey = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR)
CK_CA_CloneObject = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR)
CK_CA_GenerateCloningKEV = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_CloneAsTargetInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BBOOL, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_CloneAsSource = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BBOOL, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_CloneAsTarget = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_ULONG, CK_ULONG, CK_BBOOL, CK_OBJECT_HANDLE_PTR)
CK_CA_SetMofN = CFUNCTYPE(CK_RV, CK_BBOOL)
CK_CA_GenerateMofN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CA_MOFN_GENERATION_PTR, CK_ULONG, CK_ULONG, CK_VOID_PTR)
CK_CA_GenerateCloneableMofN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CA_MOFN_GENERATION_PTR, CK_ULONG, CK_ULONG, CK_VOID_PTR)
CK_CA_ModifyMofN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CA_MOFN_GENERATION_PTR, CK_ULONG, CK_ULONG, CK_VOID_PTR)
CK_CA_CloneMofN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_VOID_PTR)
CK_CA_CloneModifyMofN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_VOID_PTR)
CK_CA_ActivateMofN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CA_MOFN_ACTIVATION_PTR, CK_ULONG)
CK_CA_DeactivateMofN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_CA_GetMofNStatus = CFUNCTYPE(CK_RV, CK_SLOT_ID, CA_MOFN_STATUS_PTR)
CK_CA_DuplicateMofN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_CA_IsMofNEnabled = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR)
CK_CA_IsMofNRequired = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR)
CK_CA_GenerateTokenKeys = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG)
CK_CA_GetTokenCertificateInfo = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_SetTokenCertificateSignature = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)
CK_CA_GetModuleList = CFUNCTYPE(CK_RV, CK_SLOT_ID, CKCA_MODULE_ID_PTR, CK_ULONG, CK_ULONG_PTR)
CK_CA_GetModuleInfo = CFUNCTYPE(CK_RV, CK_SLOT_ID, CKCA_MODULE_ID, CKCA_MODULE_INFO_PTR)
CK_CA_LoadModule = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CKCA_MODULE_ID_PTR)
CK_CA_LoadEncryptedModule = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CKCA_MODULE_ID_PTR)
CK_CA_UnloadModule = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CKCA_MODULE_ID)
CK_CA_PerformModuleCall = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CKCA_MODULE_ID, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_ULONG_PTR)
CK_C_PerformSelfTest = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_FirmwareUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR)
CK_CA_FirmwareRollback = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_CA_CapabilityUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR)
CK_CA_GetUserContainerNumber = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR)
CK_CA_GetUserContainerName = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_SetUserContainerName = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG)
CK_CA_GetTokenInsertionCount = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR)
CK_CA_GetRollbackFirmwareVersion = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR)
CK_CA_GetFPV = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR)
CK_CA_GetTPV = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR)
CK_CA_GetExtendedTPV = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_GetConfigurationElementDescription = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_CHAR_PTR)
CK_CA_GetHSMCapabilitySet = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_GetHSMCapabilitySetting = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR)
CK_CA_GetHSMPolicySet = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_GetHSMPolicySetting = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR)
CK_CA_GetContainerCapabilitySet = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_GetContainerCapabilitySetting = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR)
CK_CA_GetContainerPolicySet = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_GetContainerPolicySetting = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR)
CK_CA_SetTPV = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG)
CK_CA_SetExtendedTPV = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG)
CK_CA_SetHSMPolicy = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG)
CK_CA_SetHSMPolicies = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_SetDestructiveHSMPolicy = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG)
CK_CA_SetDestructiveHSMPolicies = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_SetContainerPolicy = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG)
CK_CA_SetContainerPolicies = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_RetrieveLicenseList = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_QueryLicense = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_BYTE_PTR)
CK_CA_GetContainerStatus = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_GetSessionInfo = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_ReadCommonStore = CFUNCTYPE(CK_RV, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_WriteCommonStore = CFUNCTYPE(CK_RV, CK_ULONG, CK_BYTE_PTR, CK_ULONG)
CK_CA_GetPrimarySlot = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID_PTR)
CK_CA_GetSecondarySlot = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID_PTR)
CK_CA_SwitchSecondarySlot = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG)
CK_CA_CloseSecondarySession = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG)
CK_CA_CloseAllSecondarySessions = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_CA_ChoosePrimarySlot = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_CA_ChooseSecondarySlot = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_CA_CloneObjectToAllSessions = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE)
CK_CA_CloneAllObjectsToSession = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID)
CK_CA_ResetDevice = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_FLAGS)
CK_CA_FactoryReset = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_FLAGS)
CK_CA_SetPedId = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG)
CK_CA_GetPedId = CFUNCTYPE(CK_RV, CK_SLOT_ID, POINTER(CK_ULONG))
CK_CA_SpRawRead = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR)
CK_CA_SpRawWrite = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR)
CK_CA_CheckOperationState = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, POINTER(CK_BBOOL))
CK_CA_DestroyMultipleObjects = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_ULONG_PTR)
CK_CA_HAInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE)
CK_CA_HAGetMasterPublic = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_HAGetLoginChallenge = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_USER_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_HAAnswerLoginChallenge = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_HALogin = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_HAAnswerMofNChallenge = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_HAActivateMofN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_CA_GetHAState = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_HA_STATE_PTR)
CK_CA_GetTokenCertificates = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_ExtractMaskedObject = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_InsertMaskedObject = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG_PTR, CK_BYTE_PTR, CK_ULONG)
CK_CA_MultisignValue = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_ULONG_PTR, POINTER(CK_BYTE_PTR), CK_ULONG_PTR, POINTER(CK_BYTE_PTR))
CK_CA_SIMExtract = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG, CKA_SIM_AUTH_FORM, CK_ULONG_PTR, POINTER(CK_BYTE_PTR), CK_BBOOL, CK_ULONG_PTR, CK_BYTE_PTR)
CK_CA_SIMInsert = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CKA_SIM_AUTH_FORM, CK_ULONG_PTR, POINTER(CK_BYTE_PTR), CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR)
CK_CA_SIMMultiSign = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ULONG, CKA_SIM_AUTH_FORM, CK_ULONG_PTR, POINTER(CK_BYTE_PTR), CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_ULONG_PTR, POINTER(CK_BYTE_PTR), CK_ULONG_PTR, POINTER(CK_BYTE_PTR))
CK_CA_Extract = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR)
CK_CA_Insert = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR)
CK_CA_GetObjectUID = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG, POINTER(CK_BYTE))
CK_CA_GetObjectHandle = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, POINTER(CK_BYTE), CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_DeleteContainer = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_CA_MTKSetStorage = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG)
CK_CA_MTKRestore = CFUNCTYPE(CK_RV, CK_SLOT_ID)
CK_CA_MTKResplit = CFUNCTYPE(CK_RV, CK_SLOT_ID)
CK_CA_MTKZeroize = CFUNCTYPE(CK_RV, CK_SLOT_ID)
CK_CA_MTKGetState = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR)
CK_CA_GetTSV = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR)
CK_CA_InvokeServiceInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG)
CK_CA_InvokeService = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ULONG_PTR)
CK_CA_InvokeServiceFinal = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_InvokeServiceAsynch = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG)
CK_CA_InvokeServiceSinglePart = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_EncodeECPrimeParams = CFUNCTYPE(CK_RV, CK_BYTE_PTR, CK_ULONG_PTR, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)
CK_CA_EncodeECChar2Params = CFUNCTYPE(CK_RV, CK_BYTE_PTR, CK_ULONG_PTR, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)
CK_CA_EncodeECParamsFromFile = CFUNCTYPE(CK_RV, CK_BYTE_PTR, CK_ULONG_PTR, CK_BYTE_PTR)
CK_CA_GetHSMStorageInformation = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_GetContainerStorageInformation = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_SetContainerSize = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG)
CK_CA_CreateContainer = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG_PTR)
CK_CA_DeleteContainerWithHandle = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG)
CK_CA_GetContainerList = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR)
CK_CA_GetContainerName = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_GetNumberOfAllowedContainers = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_ULONG_PTR)
CK_CA_GetTunnelSlotNumber = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_SLOT_ID_PTR)
CK_CA_GetClusterState = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_CLUSTER_STATE_PTR)
CK_CA_LockClusteredSlot = CFUNCTYPE(CK_RV, CK_SLOT_ID)
CK_CA_UnlockClusteredSlot = CFUNCTYPE(CK_RV, CK_SLOT_ID)
CK_CA_LKMInitiatorChallenge = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_ULONG, CK_LKM_TOKEN_ID_PTR, CK_LKM_TOKEN_ID_PTR, CK_CHAR_PTR, CK_ULONG_PTR)
CK_CA_LKMReceiverResponse = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_ULONG, CK_LKM_TOKEN_ID_PTR, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR, CK_ULONG_PTR)
CK_CA_LKMInitiatorComplete = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_CHAR_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR)
CK_CA_LKMReceiverComplete = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR)
CK_CA_ModifyUsageCount = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG, CK_ULONG)
CK_CA_LogVerify = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ULONG, CK_ULONG_PTR)
CK_CA_LogVerifyFile = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG_PTR)
CK_CA_LogExternal = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG)
CK_CA_LogImportSecret = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR)
CK_CA_LogExportSecret = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR)
CK_CA_LogSetConfig = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_BYTE_PTR)
CK_CA_LogGetConfig = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, POINTER(CK_ULONG), POINTER(CK_ULONG), POINTER(CK_ULONG), POINTER(CK_ULONG), CK_BYTE_PTR)
CK_CA_LogEraseAll = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_CA_LogGetStatus = CFUNCTYPE(CK_RV, CK_SLOT_ID, POINTER(CK_ULONG), POINTER(CK_ULONG), POINTER(CK_ULONG), POINTER(CK_ULONG), POINTER(CK_ULONG))
CK_CA_InitAudit = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR)
CK_CA_GetTime = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG_PTR)
CK_CA_TimeSync = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ULONG)
CK_SFNT_CA_FUNCTION_LIST._fields_ = [
    ('version', CK_VERSION),
    ('CA_GetFunctionList', CK_CA_GetFunctionList),
    ('CA_WaitForSlotEvent', CK_CA_WaitForSlotEvent),
    ('CA_InitIndirectToken', CK_CA_InitIndirectToken),
    ('CA_InitIndirectPIN', CK_CA_InitIndirectPIN),
    ('CA_ResetPIN', CK_CA_ResetPIN),
    ('CA_CreateLoginChallenge', CK_CA_CreateLoginChallenge),
    ('CA_Deactivate', CK_CA_Deactivate),
    ('CA_OpenSession', CK_CA_OpenSession),
    ('CA_IndirectLogin', CK_CA_IndirectLogin),
    ('CA_InitializeRemotePEDVector', CK_CA_InitializeRemotePEDVector),
    ('CA_DeleteRemotePEDVector', CK_CA_DeleteRemotePEDVector),
    ('CA_GetRemotePEDVectorStatus', CK_CA_GetRemotePEDVectorStatus),
    ('CA_ConfigureRemotePED', CK_CA_ConfigureRemotePED),
    ('CA_DismantleRemotePED', CK_CA_DismantleRemotePED),
    ('CA_Restart', CK_CA_Restart),
    ('CA_RestartForContainer', CK_CA_RestartForContainer),
    ('CA_CloseApplicationID', CK_CA_CloseApplicationID),
    ('CA_CloseApplicationIDForContainer', CK_CA_CloseApplicationIDForContainer),
    ('CA_OpenApplicationID', CK_CA_OpenApplicationID),
    ('CA_OpenApplicationIDForContainer', CK_CA_OpenApplicationIDForContainer),
    ('CA_SetApplicationID', CK_CA_SetApplicationID),
    ('CA_ManualKCV', CK_CA_ManualKCV),
    ('CA_SetLKCV', CK_CA_SetLKCV),
    ('CA_SetKCV', CK_CA_SetKCV),
    ('CA_SetCloningDomain', CK_CA_SetCloningDomain),
    ('CA_ClonePrivateKey', CK_CA_ClonePrivateKey),
    ('CA_CloneObject', CK_CA_CloneObject),
    ('CA_GenerateCloningKEV', CK_CA_GenerateCloningKEV),
    ('CA_CloneAsTargetInit', CK_CA_CloneAsTargetInit),
    ('CA_CloneAsSource', CK_CA_CloneAsSource),
    ('CA_CloneAsTarget', CK_CA_CloneAsTarget),
    ('CA_SetMofN', CK_CA_SetMofN),
    ('CA_GenerateMofN', CK_CA_GenerateMofN),
    ('CA_GenerateCloneableMofN', CK_CA_GenerateCloneableMofN),
    ('CA_ModifyMofN', CK_CA_ModifyMofN),
    ('CA_CloneMofN', CK_CA_CloneMofN),
    ('CA_CloneModifyMofN', CK_CA_CloneModifyMofN),
    ('CA_ActivateMofN', CK_CA_ActivateMofN),
    ('CA_DeactivateMofN', CK_CA_DeactivateMofN),
    ('CA_GetMofNStatus', CK_CA_GetMofNStatus),
    ('CA_DuplicateMofN', CK_CA_DuplicateMofN),
    ('CA_IsMofNEnabled', CK_CA_IsMofNEnabled),
    ('CA_IsMofNRequired', CK_CA_IsMofNRequired),
    ('CA_GenerateTokenKeys', CK_CA_GenerateTokenKeys),
    ('CA_GetTokenCertificateInfo', CK_CA_GetTokenCertificateInfo),
    ('CA_SetTokenCertificateSignature', CK_CA_SetTokenCertificateSignature),
    ('CA_GetModuleList', CK_CA_GetModuleList),
    ('CA_GetModuleInfo', CK_CA_GetModuleInfo),
    ('CA_LoadModule', CK_CA_LoadModule),
    ('CA_LoadEncryptedModule', CK_CA_LoadEncryptedModule),
    ('CA_UnloadModule', CK_CA_UnloadModule),
    ('CA_PerformModuleCall', CK_CA_PerformModuleCall),
    ('C_PerformSelfTest', CK_C_PerformSelfTest),
    ('CA_FirmwareUpdate', CK_CA_FirmwareUpdate),
    ('CA_FirmwareRollback', CK_CA_FirmwareRollback),
    ('CA_CapabilityUpdate', CK_CA_CapabilityUpdate),
    ('CA_GetUserContainerNumber', CK_CA_GetUserContainerNumber),
    ('CA_GetUserContainerName', CK_CA_GetUserContainerName),
    ('CA_SetUserContainerName', CK_CA_SetUserContainerName),
    ('CA_GetTokenInsertionCount', CK_CA_GetTokenInsertionCount),
    ('CA_GetRollbackFirmwareVersion', CK_CA_GetRollbackFirmwareVersion),
    ('CA_GetFPV', CK_CA_GetFPV),
    ('CA_GetTPV', CK_CA_GetTPV),
    ('CA_GetExtendedTPV', CK_CA_GetExtendedTPV),
    ('CA_GetConfigurationElementDescription', CK_CA_GetConfigurationElementDescription),
    ('CA_GetHSMCapabilitySet', CK_CA_GetHSMCapabilitySet),
    ('CA_GetHSMCapabilitySetting', CK_CA_GetHSMCapabilitySetting),
    ('CA_GetHSMPolicySet', CK_CA_GetHSMPolicySet),
    ('CA_GetHSMPolicySetting', CK_CA_GetHSMPolicySetting),
    ('CA_GetContainerCapabilitySet', CK_CA_GetContainerCapabilitySet),
    ('CA_GetContainerCapabilitySetting', CK_CA_GetContainerCapabilitySetting),
    ('CA_GetContainerPolicySet', CK_CA_GetContainerPolicySet),
    ('CA_GetContainerPolicySetting', CK_CA_GetContainerPolicySetting),
    ('CA_SetTPV', CK_CA_SetTPV),
    ('CA_SetExtendedTPV', CK_CA_SetExtendedTPV),
    ('CA_SetHSMPolicy', CK_CA_SetHSMPolicy),
    ('CA_SetHSMPolicies', CK_CA_SetHSMPolicies),
    ('CA_SetDestructiveHSMPolicy', CK_CA_SetDestructiveHSMPolicy),
    ('CA_SetDestructiveHSMPolicies', CK_CA_SetDestructiveHSMPolicies),
    ('CA_SetContainerPolicy', CK_CA_SetContainerPolicy),
    ('CA_SetContainerPolicies', CK_CA_SetContainerPolicies),
    ('CA_RetrieveLicenseList', CK_CA_RetrieveLicenseList),
    ('CA_QueryLicense', CK_CA_QueryLicense),
    ('CA_GetContainerStatus', CK_CA_GetContainerStatus),
    ('CA_GetSessionInfo', CK_CA_GetSessionInfo),
    ('CA_ReadCommonStore', CK_CA_ReadCommonStore),
    ('CA_WriteCommonStore', CK_CA_WriteCommonStore),
    ('CA_GetPrimarySlot', CK_CA_GetPrimarySlot),
    ('CA_GetSecondarySlot', CK_CA_GetSecondarySlot),
    ('CA_SwitchSecondarySlot', CK_CA_SwitchSecondarySlot),
    ('CA_CloseSecondarySession', CK_CA_CloseSecondarySession),
    ('CA_CloseAllSecondarySessions', CK_CA_CloseAllSecondarySessions),
    ('CA_ChoosePrimarySlot', CK_CA_ChoosePrimarySlot),
    ('CA_ChooseSecondarySlot', CK_CA_ChooseSecondarySlot),
    ('CA_CloneObjectToAllSessions', CK_CA_CloneObjectToAllSessions),
    ('CA_CloneAllObjectsToSession', CK_CA_CloneAllObjectsToSession),
    ('CA_ResetDevice', CK_CA_ResetDevice),
    ('CA_FactoryReset', CK_CA_FactoryReset),
    ('CA_SetPedId', CK_CA_SetPedId),
    ('CA_GetPedId', CK_CA_GetPedId),
    ('CA_SpRawRead', CK_CA_SpRawRead),
    ('CA_SpRawWrite', CK_CA_SpRawWrite),
    ('CA_CheckOperationState', CK_CA_CheckOperationState),
    ('CA_DestroyMultipleObjects', CK_CA_DestroyMultipleObjects),
    ('CA_HAInit', CK_CA_HAInit),
    ('CA_HAGetMasterPublic', CK_CA_HAGetMasterPublic),
    ('CA_HAGetLoginChallenge', CK_CA_HAGetLoginChallenge),
    ('CA_HAAnswerLoginChallenge', CK_CA_HAAnswerLoginChallenge),
    ('CA_HALogin', CK_CA_HALogin),
    ('CA_HAAnswerMofNChallenge', CK_CA_HAAnswerMofNChallenge),
    ('CA_HAActivateMofN', CK_CA_HAActivateMofN),
    ('CA_GetHAState', CK_CA_GetHAState),
    ('CA_GetTokenCertificates', CK_CA_GetTokenCertificates),
    ('CA_ExtractMaskedObject', CK_CA_ExtractMaskedObject),
    ('CA_InsertMaskedObject', CK_CA_InsertMaskedObject),
    ('CA_MultisignValue', CK_CA_MultisignValue),
    ('CA_SIMExtract', CK_CA_SIMExtract),
    ('CA_SIMInsert', CK_CA_SIMInsert),
    ('CA_SIMMultiSign', CK_CA_SIMMultiSign),
    ('CA_Extract', CK_CA_Extract),
    ('CA_Insert', CK_CA_Insert),
    ('CA_GetObjectUID', CK_CA_GetObjectUID),
    ('CA_GetObjectHandle', CK_CA_GetObjectHandle),
    ('CA_DeleteContainer', CK_CA_DeleteContainer),
    ('CA_MTKSetStorage', CK_CA_MTKSetStorage),
    ('CA_MTKRestore', CK_CA_MTKRestore),
    ('CA_MTKResplit', CK_CA_MTKResplit),
    ('CA_MTKZeroize', CK_CA_MTKZeroize),
    ('CA_MTKGetState', CK_CA_MTKGetState),
    ('CA_GetTSV', CK_CA_GetTSV),
    ('CA_InvokeServiceInit', CK_CA_InvokeServiceInit),
    ('CA_InvokeService', CK_CA_InvokeService),
    ('CA_InvokeServiceFinal', CK_CA_InvokeServiceFinal),
    ('CA_InvokeServiceAsynch', CK_CA_InvokeServiceAsynch),
    ('CA_InvokeServiceSinglePart', CK_CA_InvokeServiceSinglePart),
    ('CA_EncodeECPrimeParams', CK_CA_EncodeECPrimeParams),
    ('CA_EncodeECChar2Params', CK_CA_EncodeECChar2Params),
    ('CA_EncodeECParamsFromFile', CK_CA_EncodeECParamsFromFile),
    ('CA_GetHSMStorageInformation', CK_CA_GetHSMStorageInformation),
    ('CA_GetContainerStorageInformation', CK_CA_GetContainerStorageInformation),
    ('CA_SetContainerSize', CK_CA_SetContainerSize),
    ('CA_CreateContainer', CK_CA_CreateContainer),
    ('CA_DeleteContainerWithHandle', CK_CA_DeleteContainerWithHandle),
    ('CA_GetContainerList', CK_CA_GetContainerList),
    ('CA_GetContainerName', CK_CA_GetContainerName),
    ('CA_GetNumberOfAllowedContainers', CK_CA_GetNumberOfAllowedContainers),
    ('CA_GetTunnelSlotNumber', CK_CA_GetTunnelSlotNumber),
    ('CA_GetClusterState', CK_CA_GetClusterState),
    ('CA_LockClusteredSlot', CK_CA_LockClusteredSlot),
    ('CA_UnlockClusteredSlot', CK_CA_UnlockClusteredSlot),
    ('CA_LKMInitiatorChallenge', CK_CA_LKMInitiatorChallenge),
    ('CA_LKMReceiverResponse', CK_CA_LKMReceiverResponse),
    ('CA_LKMInitiatorComplete', CK_CA_LKMInitiatorComplete),
    ('CA_LKMReceiverComplete', CK_CA_LKMReceiverComplete),
    ('CA_ModifyUsageCount', CK_CA_ModifyUsageCount),
    ('CA_LogVerify', CK_CA_LogVerify),
    ('CA_LogVerifyFile', CK_CA_LogVerifyFile),
    ('CA_LogExternal', CK_CA_LogExternal),
    ('CA_LogImportSecret', CK_CA_LogImportSecret),
    ('CA_LogExportSecret', CK_CA_LogExportSecret),
    ('CA_LogSetConfig', CK_CA_LogSetConfig),
    ('CA_LogGetConfig', CK_CA_LogGetConfig),
    ('CA_LogEraseAll', CK_CA_LogEraseAll),
    ('CA_LogGetStatus', CK_CA_LogGetStatus),
    ('CA_InitAudit', CK_CA_InitAudit),
    ('CA_GetTime', CK_CA_GetTime),
    ('CA_TimeSync', CK_CA_TimeSync),
]
CA_GetFunctionList = make_late_binding_function('CA_GetFunctionList')
CA_GetFunctionList.restype = CK_RV
CA_GetFunctionList.argtypes = [CK_SFNT_CA_FUNCTION_LIST_PTR_PTR]
CA_WaitForSlotEvent = make_late_binding_function('CA_WaitForSlotEvent')
CA_WaitForSlotEvent.restype = CK_RV
CA_WaitForSlotEvent.argtypes = [CK_FLAGS, POINTER(CK_ULONG), CK_SLOT_ID_PTR, CK_VOID_PTR]
CA_InitIndirectToken = make_late_binding_function('CA_InitIndirectToken')
CA_InitIndirectToken.restype = CK_RV
CA_InitIndirectToken.argtypes = [CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR, CK_SESSION_HANDLE]
CA_InitIndirectPIN = make_late_binding_function('CA_InitIndirectPIN')
CA_InitIndirectPIN.restype = CK_RV
CA_InitIndirectPIN.argtypes = [CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG, CK_SESSION_HANDLE]
CA_ResetPIN = make_late_binding_function('CA_ResetPIN')
CA_ResetPIN.restype = CK_RV
CA_ResetPIN.argtypes = [CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG]
CA_CreateLoginChallenge = make_late_binding_function('CA_CreateLoginChallenge')
CA_CreateLoginChallenge.restype = CK_RV
CA_CreateLoginChallenge.argtypes = [CK_SESSION_HANDLE, CK_USER_TYPE, CK_ULONG, CK_CHAR_PTR, CK_ULONG_PTR, CK_CHAR_PTR]
CA_Deactivate = make_late_binding_function('CA_Deactivate')
CA_Deactivate.restype = CK_RV
CA_Deactivate.argtypes = [CK_SLOT_ID, CK_USER_TYPE]
CA_OpenSession = make_late_binding_function('CA_OpenSession')
CA_OpenSession.restype = CK_RV
CA_OpenSession.argtypes = [CK_SLOT_ID, CK_ULONG, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR]
CA_IndirectLogin = make_late_binding_function('CA_IndirectLogin')
CA_IndirectLogin.restype = CK_RV
CA_IndirectLogin.argtypes = [CK_SESSION_HANDLE, CK_USER_TYPE, CK_SESSION_HANDLE]
CA_InitializeRemotePEDVector = make_late_binding_function('CA_InitializeRemotePEDVector')
CA_InitializeRemotePEDVector.restype = CK_RV
CA_InitializeRemotePEDVector.argtypes = [CK_SESSION_HANDLE]
CA_DeleteRemotePEDVector = make_late_binding_function('CA_DeleteRemotePEDVector')
CA_DeleteRemotePEDVector.restype = CK_RV
CA_DeleteRemotePEDVector.argtypes = [CK_SESSION_HANDLE]
CA_GetRemotePEDVectorStatus = make_late_binding_function('CA_GetRemotePEDVectorStatus')
CA_GetRemotePEDVectorStatus.restype = CK_RV
CA_GetRemotePEDVectorStatus.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_ConfigureRemotePED = make_late_binding_function('CA_ConfigureRemotePED')
CA_ConfigureRemotePED.restype = CK_RV
CA_ConfigureRemotePED.argtypes = [CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_ULONG_PTR]
CA_DismantleRemotePED = make_late_binding_function('CA_DismantleRemotePED')
CA_DismantleRemotePED.restype = CK_RV
CA_DismantleRemotePED.argtypes = [CK_SLOT_ID, CK_ULONG]
CA_Restart = make_late_binding_function('CA_Restart')
CA_Restart.restype = CK_RV
CA_Restart.argtypes = [CK_SLOT_ID]
CA_RestartForContainer = make_late_binding_function('CA_RestartForContainer')
CA_RestartForContainer.restype = CK_RV
CA_RestartForContainer.argtypes = [CK_SLOT_ID, CK_ULONG]
CA_CloseApplicationID = make_late_binding_function('CA_CloseApplicationID')
CA_CloseApplicationID.restype = CK_RV
CA_CloseApplicationID.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG]
CA_CloseApplicationIDForContainer = make_late_binding_function('CA_CloseApplicationIDForContainer')
CA_CloseApplicationIDForContainer.restype = CK_RV
CA_CloseApplicationIDForContainer.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG]
CA_OpenApplicationID = make_late_binding_function('CA_OpenApplicationID')
CA_OpenApplicationID.restype = CK_RV
CA_OpenApplicationID.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG]
CA_OpenApplicationIDForContainer = make_late_binding_function('CA_OpenApplicationIDForContainer')
CA_OpenApplicationIDForContainer.restype = CK_RV
CA_OpenApplicationIDForContainer.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG]
CA_SetApplicationID = make_late_binding_function('CA_SetApplicationID')
CA_SetApplicationID.restype = CK_RV
CA_SetApplicationID.argtypes = [CK_ULONG, CK_ULONG]
CA_ManualKCV = make_late_binding_function('CA_ManualKCV')
CA_ManualKCV.restype = CK_RV
CA_ManualKCV.argtypes = [CK_SESSION_HANDLE]
CA_SetLKCV = make_late_binding_function('CA_SetLKCV')
CA_SetLKCV.restype = CK_RV
CA_SetLKCV.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
CA_SetKCV = make_late_binding_function('CA_SetKCV')
CA_SetKCV.restype = CK_RV
CA_SetKCV.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
CA_SetCloningDomain = make_late_binding_function('CA_SetCloningDomain')
CA_SetCloningDomain.restype = CK_RV
CA_SetCloningDomain.argtypes = [CK_BYTE_PTR, CK_ULONG]
CA_ClonePrivateKey = make_late_binding_function('CA_ClonePrivateKey')
CA_ClonePrivateKey.restype = CK_RV
CA_ClonePrivateKey.argtypes = [CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR]
CA_CloneObject = make_late_binding_function('CA_CloneObject')
CA_CloneObject.restype = CK_RV
CA_CloneObject.argtypes = [CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR]
CA_GenerateCloningKEV = make_late_binding_function('CA_GenerateCloningKEV')
CA_GenerateCloningKEV.restype = CK_RV
CA_GenerateCloningKEV.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
CA_CloneAsTargetInit = make_late_binding_function('CA_CloneAsTargetInit')
CA_CloneAsTargetInit.restype = CK_RV
CA_CloneAsTargetInit.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BBOOL, CK_BYTE_PTR, CK_ULONG_PTR]
CA_CloneAsSource = make_late_binding_function('CA_CloneAsSource')
CA_CloneAsSource.restype = CK_RV
CA_CloneAsSource.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BBOOL, CK_BYTE_PTR, CK_ULONG_PTR]
CA_CloneAsTarget = make_late_binding_function('CA_CloneAsTarget')
CA_CloneAsTarget.restype = CK_RV
CA_CloneAsTarget.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_ULONG, CK_ULONG, CK_BBOOL, CK_OBJECT_HANDLE_PTR]
CA_SetMofN = make_late_binding_function('CA_SetMofN')
CA_SetMofN.restype = CK_RV
CA_SetMofN.argtypes = [CK_BBOOL]
CA_GenerateMofN = make_late_binding_function('CA_GenerateMofN')
CA_GenerateMofN.restype = CK_RV
CA_GenerateMofN.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CA_MOFN_GENERATION_PTR, CK_ULONG, CK_ULONG, CK_VOID_PTR]
CA_GenerateCloneableMofN = make_late_binding_function('CA_GenerateCloneableMofN')
CA_GenerateCloneableMofN.restype = CK_RV
CA_GenerateCloneableMofN.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CA_MOFN_GENERATION_PTR, CK_ULONG, CK_ULONG, CK_VOID_PTR]
CA_ModifyMofN = make_late_binding_function('CA_ModifyMofN')
CA_ModifyMofN.restype = CK_RV
CA_ModifyMofN.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CA_MOFN_GENERATION_PTR, CK_ULONG, CK_ULONG, CK_VOID_PTR]
CA_CloneMofN = make_late_binding_function('CA_CloneMofN')
CA_CloneMofN.restype = CK_RV
CA_CloneMofN.argtypes = [CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_VOID_PTR]
CA_CloneModifyMofN = make_late_binding_function('CA_CloneModifyMofN')
CA_CloneModifyMofN.restype = CK_RV
CA_CloneModifyMofN.argtypes = [CK_SESSION_HANDLE, CK_SESSION_HANDLE, CK_VOID_PTR]
CA_ActivateMofN = make_late_binding_function('CA_ActivateMofN')
CA_ActivateMofN.restype = CK_RV
CA_ActivateMofN.argtypes = [CK_SESSION_HANDLE, CA_MOFN_ACTIVATION_PTR, CK_ULONG]
CA_DeactivateMofN = make_late_binding_function('CA_DeactivateMofN')
CA_DeactivateMofN.restype = CK_RV
CA_DeactivateMofN.argtypes = [CK_SESSION_HANDLE]
CA_GetMofNStatus = make_late_binding_function('CA_GetMofNStatus')
CA_GetMofNStatus.restype = CK_RV
CA_GetMofNStatus.argtypes = [CK_SLOT_ID, CA_MOFN_STATUS_PTR]
CA_DuplicateMofN = make_late_binding_function('CA_DuplicateMofN')
CA_DuplicateMofN.restype = CK_RV
CA_DuplicateMofN.argtypes = [CK_SESSION_HANDLE]
CA_IsMofNEnabled = make_late_binding_function('CA_IsMofNEnabled')
CA_IsMofNEnabled.restype = CK_RV
CA_IsMofNEnabled.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_IsMofNRequired = make_late_binding_function('CA_IsMofNRequired')
CA_IsMofNRequired.restype = CK_RV
CA_IsMofNRequired.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GenerateTokenKeys = make_late_binding_function('CA_GenerateTokenKeys')
CA_GenerateTokenKeys.restype = CK_RV
CA_GenerateTokenKeys.argtypes = [CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
CA_GetTokenCertificateInfo = make_late_binding_function('CA_GetTokenCertificateInfo')
CA_GetTokenCertificateInfo.restype = CK_RV
CA_GetTokenCertificateInfo.argtypes = [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_SetTokenCertificateSignature = make_late_binding_function('CA_SetTokenCertificateSignature')
CA_SetTokenCertificateSignature.restype = CK_RV
CA_SetTokenCertificateSignature.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG]
CA_GetModuleList = make_late_binding_function('CA_GetModuleList')
CA_GetModuleList.restype = CK_RV
CA_GetModuleList.argtypes = [CK_SLOT_ID, CKCA_MODULE_ID_PTR, CK_ULONG, CK_ULONG_PTR]
CA_GetModuleInfo = make_late_binding_function('CA_GetModuleInfo')
CA_GetModuleInfo.restype = CK_RV
CA_GetModuleInfo.argtypes = [CK_SLOT_ID, CKCA_MODULE_ID, CKCA_MODULE_INFO_PTR]
CA_LoadModule = make_late_binding_function('CA_LoadModule')
CA_LoadModule.restype = CK_RV
CA_LoadModule.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CKCA_MODULE_ID_PTR]
CA_LoadEncryptedModule = make_late_binding_function('CA_LoadEncryptedModule')
CA_LoadEncryptedModule.restype = CK_RV
CA_LoadEncryptedModule.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CKCA_MODULE_ID_PTR]
CA_UnloadModule = make_late_binding_function('CA_UnloadModule')
CA_UnloadModule.restype = CK_RV
CA_UnloadModule.argtypes = [CK_SESSION_HANDLE, CKCA_MODULE_ID]
CA_PerformModuleCall = make_late_binding_function('CA_PerformModuleCall')
CA_PerformModuleCall.restype = CK_RV
CA_PerformModuleCall.argtypes = [CK_SESSION_HANDLE, CKCA_MODULE_ID, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_ULONG_PTR]
C_PerformSelfTest = make_late_binding_function('C_PerformSelfTest')
C_PerformSelfTest.restype = CK_RV
C_PerformSelfTest.argtypes = [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_FirmwareUpdate = make_late_binding_function('CA_FirmwareUpdate')
CA_FirmwareUpdate.restype = CK_RV
CA_FirmwareUpdate.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR]
CA_FirmwareRollback = make_late_binding_function('CA_FirmwareRollback')
CA_FirmwareRollback.restype = CK_RV
CA_FirmwareRollback.argtypes = [CK_SESSION_HANDLE]
CA_CapabilityUpdate = make_late_binding_function('CA_CapabilityUpdate')
CA_CapabilityUpdate.restype = CK_RV
CA_CapabilityUpdate.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR]
CA_GetUserContainerNumber = make_late_binding_function('CA_GetUserContainerNumber')
CA_GetUserContainerNumber.restype = CK_RV
CA_GetUserContainerNumber.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetUserContainerName = make_late_binding_function('CA_GetUserContainerName')
CA_GetUserContainerName.restype = CK_RV
CA_GetUserContainerName.argtypes = [CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG_PTR]
CA_SetUserContainerName = make_late_binding_function('CA_SetUserContainerName')
CA_SetUserContainerName.restype = CK_RV
CA_SetUserContainerName.argtypes = [CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG]
CA_GetTokenInsertionCount = make_late_binding_function('CA_GetTokenInsertionCount')
CA_GetTokenInsertionCount.restype = CK_RV
CA_GetTokenInsertionCount.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetRollbackFirmwareVersion = make_late_binding_function('CA_GetRollbackFirmwareVersion')
CA_GetRollbackFirmwareVersion.restype = CK_RV
CA_GetRollbackFirmwareVersion.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetFPV = make_late_binding_function('CA_GetFPV')
CA_GetFPV.restype = CK_RV
CA_GetFPV.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetTPV = make_late_binding_function('CA_GetTPV')
CA_GetTPV.restype = CK_RV
CA_GetTPV.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetExtendedTPV = make_late_binding_function('CA_GetExtendedTPV')
CA_GetExtendedTPV.restype = CK_RV
CA_GetExtendedTPV.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetConfigurationElementDescription = make_late_binding_function('CA_GetConfigurationElementDescription')
CA_GetConfigurationElementDescription.restype = CK_RV
CA_GetConfigurationElementDescription.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_CHAR_PTR]
CA_GetHSMCapabilitySet = make_late_binding_function('CA_GetHSMCapabilitySet')
CA_GetHSMCapabilitySet.restype = CK_RV
CA_GetHSMCapabilitySet.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetHSMCapabilitySetting = make_late_binding_function('CA_GetHSMCapabilitySetting')
CA_GetHSMCapabilitySetting.restype = CK_RV
CA_GetHSMCapabilitySetting.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR]
CA_GetHSMPolicySet = make_late_binding_function('CA_GetHSMPolicySet')
CA_GetHSMPolicySet.restype = CK_RV
CA_GetHSMPolicySet.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetHSMPolicySetting = make_late_binding_function('CA_GetHSMPolicySetting')
CA_GetHSMPolicySetting.restype = CK_RV
CA_GetHSMPolicySetting.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR]
CA_GetContainerCapabilitySet = make_late_binding_function('CA_GetContainerCapabilitySet')
CA_GetContainerCapabilitySet.restype = CK_RV
CA_GetContainerCapabilitySet.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetContainerCapabilitySetting = make_late_binding_function('CA_GetContainerCapabilitySetting')
CA_GetContainerCapabilitySetting.restype = CK_RV
CA_GetContainerCapabilitySetting.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR]
CA_GetContainerPolicySet = make_late_binding_function('CA_GetContainerPolicySet')
CA_GetContainerPolicySet.restype = CK_RV
CA_GetContainerPolicySet.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetContainerPolicySetting = make_late_binding_function('CA_GetContainerPolicySetting')
CA_GetContainerPolicySetting.restype = CK_RV
CA_GetContainerPolicySetting.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR]
CA_SetTPV = make_late_binding_function('CA_SetTPV')
CA_SetTPV.restype = CK_RV
CA_SetTPV.argtypes = [CK_SESSION_HANDLE, CK_ULONG]
CA_SetExtendedTPV = make_late_binding_function('CA_SetExtendedTPV')
CA_SetExtendedTPV.restype = CK_RV
CA_SetExtendedTPV.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_SetHSMPolicy = make_late_binding_function('CA_SetHSMPolicy')
CA_SetHSMPolicy.restype = CK_RV
CA_SetHSMPolicy.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_SetHSMPolicies = make_late_binding_function('CA_SetHSMPolicies')
CA_SetHSMPolicies.restype = CK_RV
CA_SetHSMPolicies.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR]
CA_SetDestructiveHSMPolicy = make_late_binding_function('CA_SetDestructiveHSMPolicy')
CA_SetDestructiveHSMPolicy.restype = CK_RV
CA_SetDestructiveHSMPolicy.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_SetDestructiveHSMPolicies = make_late_binding_function('CA_SetDestructiveHSMPolicies')
CA_SetDestructiveHSMPolicies.restype = CK_RV
CA_SetDestructiveHSMPolicies.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR]
CA_SetContainerPolicy = make_late_binding_function('CA_SetContainerPolicy')
CA_SetContainerPolicy.restype = CK_RV
CA_SetContainerPolicy.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG]
CA_SetContainerPolicies = make_late_binding_function('CA_SetContainerPolicies')
CA_SetContainerPolicies.restype = CK_RV
CA_SetContainerPolicies.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR]
CA_RetrieveLicenseList = make_late_binding_function('CA_RetrieveLicenseList')
CA_RetrieveLicenseList.restype = CK_RV
CA_RetrieveLicenseList.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR]
CA_QueryLicense = make_late_binding_function('CA_QueryLicense')
CA_QueryLicense.restype = CK_RV
CA_QueryLicense.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_BYTE_PTR]
CA_GetContainerStatus = make_late_binding_function('CA_GetContainerStatus')
CA_GetContainerStatus.restype = CK_RV
CA_GetContainerStatus.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetSessionInfo = make_late_binding_function('CA_GetSessionInfo')
CA_GetSessionInfo.restype = CK_RV
CA_GetSessionInfo.argtypes = [CK_SESSION_HANDLE, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
CA_ReadCommonStore = make_late_binding_function('CA_ReadCommonStore')
CA_ReadCommonStore.restype = CK_RV
CA_ReadCommonStore.argtypes = [CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_WriteCommonStore = make_late_binding_function('CA_WriteCommonStore')
CA_WriteCommonStore.restype = CK_RV
CA_WriteCommonStore.argtypes = [CK_ULONG, CK_BYTE_PTR, CK_ULONG]
CA_GetPrimarySlot = make_late_binding_function('CA_GetPrimarySlot')
CA_GetPrimarySlot.restype = CK_RV
CA_GetPrimarySlot.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID_PTR]
CA_GetSecondarySlot = make_late_binding_function('CA_GetSecondarySlot')
CA_GetSecondarySlot.restype = CK_RV
CA_GetSecondarySlot.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID_PTR]
CA_SwitchSecondarySlot = make_late_binding_function('CA_SwitchSecondarySlot')
CA_SwitchSecondarySlot.restype = CK_RV
CA_SwitchSecondarySlot.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG]
CA_CloseSecondarySession = make_late_binding_function('CA_CloseSecondarySession')
CA_CloseSecondarySession.restype = CK_RV
CA_CloseSecondarySession.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG]
CA_CloseAllSecondarySessions = make_late_binding_function('CA_CloseAllSecondarySessions')
CA_CloseAllSecondarySessions.restype = CK_RV
CA_CloseAllSecondarySessions.argtypes = [CK_SESSION_HANDLE]
CA_ChoosePrimarySlot = make_late_binding_function('CA_ChoosePrimarySlot')
CA_ChoosePrimarySlot.restype = CK_RV
CA_ChoosePrimarySlot.argtypes = [CK_SESSION_HANDLE]
CA_ChooseSecondarySlot = make_late_binding_function('CA_ChooseSecondarySlot')
CA_ChooseSecondarySlot.restype = CK_RV
CA_ChooseSecondarySlot.argtypes = [CK_SESSION_HANDLE]
CA_CloneObjectToAllSessions = make_late_binding_function('CA_CloneObjectToAllSessions')
CA_CloneObjectToAllSessions.restype = CK_RV
CA_CloneObjectToAllSessions.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
CA_CloneAllObjectsToSession = make_late_binding_function('CA_CloneAllObjectsToSession')
CA_CloneAllObjectsToSession.restype = CK_RV
CA_CloneAllObjectsToSession.argtypes = [CK_SESSION_HANDLE, CK_SLOT_ID]
CA_ResetDevice = make_late_binding_function('CA_ResetDevice')
CA_ResetDevice.restype = CK_RV
CA_ResetDevice.argtypes = [CK_SLOT_ID, CK_FLAGS]
CA_FactoryReset = make_late_binding_function('CA_FactoryReset')
CA_FactoryReset.restype = CK_RV
CA_FactoryReset.argtypes = [CK_SLOT_ID, CK_FLAGS]
CA_SetPedId = make_late_binding_function('CA_SetPedId')
CA_SetPedId.restype = CK_RV
CA_SetPedId.argtypes = [CK_SLOT_ID, CK_ULONG]
CA_GetPedId = make_late_binding_function('CA_GetPedId')
CA_GetPedId.restype = CK_RV
CA_GetPedId.argtypes = [CK_SLOT_ID, POINTER(CK_ULONG)]
CA_SpRawRead = make_late_binding_function('CA_SpRawRead')
CA_SpRawRead.restype = CK_RV
CA_SpRawRead.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_SpRawWrite = make_late_binding_function('CA_SpRawWrite')
CA_SpRawWrite.restype = CK_RV
CA_SpRawWrite.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_CheckOperationState = make_late_binding_function('CA_CheckOperationState')
CA_CheckOperationState.restype = CK_RV
CA_CheckOperationState.argtypes = [CK_SESSION_HANDLE, CK_ULONG, POINTER(CK_BBOOL)]
CA_DestroyMultipleObjects = make_late_binding_function('CA_DestroyMultipleObjects')
CA_DestroyMultipleObjects.restype = CK_RV
CA_DestroyMultipleObjects.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_ULONG_PTR]
CA_HAInit = make_late_binding_function('CA_HAInit')
CA_HAInit.restype = CK_RV
CA_HAInit.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
CA_HAGetMasterPublic = make_late_binding_function('CA_HAGetMasterPublic')
CA_HAGetMasterPublic.restype = CK_RV
CA_HAGetMasterPublic.argtypes = [CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG_PTR]
CA_HAGetLoginChallenge = make_late_binding_function('CA_HAGetLoginChallenge')
CA_HAGetLoginChallenge.restype = CK_RV
CA_HAGetLoginChallenge.argtypes = [CK_SESSION_HANDLE, CK_USER_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_HAAnswerLoginChallenge = make_late_binding_function('CA_HAAnswerLoginChallenge')
CA_HAAnswerLoginChallenge.restype = CK_RV
CA_HAAnswerLoginChallenge.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_HALogin = make_late_binding_function('CA_HALogin')
CA_HALogin.restype = CK_RV
CA_HALogin.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_HAAnswerMofNChallenge = make_late_binding_function('CA_HAAnswerMofNChallenge')
CA_HAAnswerMofNChallenge.restype = CK_RV
CA_HAAnswerMofNChallenge.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_HAActivateMofN = make_late_binding_function('CA_HAActivateMofN')
CA_HAActivateMofN.restype = CK_RV
CA_HAActivateMofN.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
CA_GetHAState = make_late_binding_function('CA_GetHAState')
CA_GetHAState.restype = CK_RV
CA_GetHAState.argtypes = [CK_SLOT_ID, CK_HA_STATE_PTR]
CA_GetTokenCertificates = make_late_binding_function('CA_GetTokenCertificates')
CA_GetTokenCertificates.restype = CK_RV
CA_GetTokenCertificates.argtypes = [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_ExtractMaskedObject = make_late_binding_function('CA_ExtractMaskedObject')
CA_ExtractMaskedObject.restype = CK_RV
CA_ExtractMaskedObject.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_InsertMaskedObject = make_late_binding_function('CA_InsertMaskedObject')
CA_InsertMaskedObject.restype = CK_RV
CA_InsertMaskedObject.argtypes = [CK_SESSION_HANDLE, CK_ULONG_PTR, CK_BYTE_PTR, CK_ULONG]
CA_MultisignValue = make_late_binding_function('CA_MultisignValue')
CA_MultisignValue.restype = CK_RV
CA_MultisignValue.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_ULONG_PTR, POINTER(CK_BYTE_PTR), CK_ULONG_PTR, POINTER(CK_BYTE_PTR)]
CA_SIMExtract = make_late_binding_function('CA_SIMExtract')
CA_SIMExtract.restype = CK_RV
CA_SIMExtract.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG, CKA_SIM_AUTH_FORM, CK_ULONG_PTR, POINTER(CK_BYTE_PTR), CK_BBOOL, CK_ULONG_PTR, CK_BYTE_PTR]
CA_SIMInsert = make_late_binding_function('CA_SIMInsert')
CA_SIMInsert.restype = CK_RV
CA_SIMInsert.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CKA_SIM_AUTH_FORM, CK_ULONG_PTR, POINTER(CK_BYTE_PTR), CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR]
CA_SIMMultiSign = make_late_binding_function('CA_SIMMultiSign')
CA_SIMMultiSign.restype = CK_RV
CA_SIMMultiSign.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ULONG, CKA_SIM_AUTH_FORM, CK_ULONG_PTR, POINTER(CK_BYTE_PTR), CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_ULONG_PTR, POINTER(CK_BYTE_PTR), CK_ULONG_PTR, POINTER(CK_BYTE_PTR)]
CA_Extract = make_late_binding_function('CA_Extract')
CA_Extract.restype = CK_RV
CA_Extract.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR]
CA_Insert = make_late_binding_function('CA_Insert')
CA_Insert.restype = CK_RV
CA_Insert.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR]
CA_GetObjectUID = make_late_binding_function('CA_GetObjectUID')
CA_GetObjectUID.restype = CK_RV
CA_GetObjectUID.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG, POINTER(CK_BYTE)]
CA_GetObjectHandle = make_late_binding_function('CA_GetObjectHandle')
CA_GetObjectHandle.restype = CK_RV
CA_GetObjectHandle.argtypes = [CK_SLOT_ID, CK_ULONG, POINTER(CK_BYTE), CK_ULONG_PTR, CK_ULONG_PTR]
CA_DeleteContainer = make_late_binding_function('CA_DeleteContainer')
CA_DeleteContainer.restype = CK_RV
CA_DeleteContainer.argtypes = [CK_SESSION_HANDLE]
CA_MTKSetStorage = make_late_binding_function('CA_MTKSetStorage')
CA_MTKSetStorage.restype = CK_RV
CA_MTKSetStorage.argtypes = [CK_SESSION_HANDLE, CK_ULONG]
CA_MTKRestore = make_late_binding_function('CA_MTKRestore')
CA_MTKRestore.restype = CK_RV
CA_MTKRestore.argtypes = [CK_SLOT_ID]
CA_MTKResplit = make_late_binding_function('CA_MTKResplit')
CA_MTKResplit.restype = CK_RV
CA_MTKResplit.argtypes = [CK_SLOT_ID]
CA_MTKZeroize = make_late_binding_function('CA_MTKZeroize')
CA_MTKZeroize.restype = CK_RV
CA_MTKZeroize.argtypes = [CK_SLOT_ID]
CA_MTKGetState = make_late_binding_function('CA_MTKGetState')
CA_MTKGetState.restype = CK_RV
CA_MTKGetState.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetTSV = make_late_binding_function('CA_GetTSV')
CA_GetTSV.restype = CK_RV
CA_GetTSV.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_InvokeServiceInit = make_late_binding_function('CA_InvokeServiceInit')
CA_InvokeServiceInit.restype = CK_RV
CA_InvokeServiceInit.argtypes = [CK_SESSION_HANDLE, CK_ULONG]
CA_InvokeService = make_late_binding_function('CA_InvokeService')
CA_InvokeService.restype = CK_RV
CA_InvokeService.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ULONG_PTR]
CA_InvokeServiceFinal = make_late_binding_function('CA_InvokeServiceFinal')
CA_InvokeServiceFinal.restype = CK_RV
CA_InvokeServiceFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
CA_InvokeServiceAsynch = make_late_binding_function('CA_InvokeServiceAsynch')
CA_InvokeServiceAsynch.restype = CK_RV
CA_InvokeServiceAsynch.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG]
CA_InvokeServiceSinglePart = make_late_binding_function('CA_InvokeServiceSinglePart')
CA_InvokeServiceSinglePart.restype = CK_RV
CA_InvokeServiceSinglePart.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_EncodeECPrimeParams = make_late_binding_function('CA_EncodeECPrimeParams')
CA_EncodeECPrimeParams.restype = CK_RV
CA_EncodeECPrimeParams.argtypes = [CK_BYTE_PTR, CK_ULONG_PTR, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG]
CA_EncodeECChar2Params = make_late_binding_function('CA_EncodeECChar2Params')
CA_EncodeECChar2Params.restype = CK_RV
CA_EncodeECChar2Params.argtypes = [CK_BYTE_PTR, CK_ULONG_PTR, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG]
CA_EncodeECParamsFromFile = make_late_binding_function('CA_EncodeECParamsFromFile')
CA_EncodeECParamsFromFile.restype = CK_RV
CA_EncodeECParamsFromFile.argtypes = [CK_BYTE_PTR, CK_ULONG_PTR, CK_BYTE_PTR]
CA_GetHSMStorageInformation = make_late_binding_function('CA_GetHSMStorageInformation')
CA_GetHSMStorageInformation.restype = CK_RV
CA_GetHSMStorageInformation.argtypes = [CK_SLOT_ID, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetContainerStorageInformation = make_late_binding_function('CA_GetContainerStorageInformation')
CA_GetContainerStorageInformation.restype = CK_RV
CA_GetContainerStorageInformation.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR, CK_ULONG_PTR]
CA_SetContainerSize = make_late_binding_function('CA_SetContainerSize')
CA_SetContainerSize.restype = CK_RV
CA_SetContainerSize.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG]
CA_CreateContainer = make_late_binding_function('CA_CreateContainer')
CA_CreateContainer.restype = CK_RV
CA_CreateContainer.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG_PTR]
CA_InitAudit = make_late_binding_function('CA_InitAudit')
CA_InitAudit.restype = CK_RV
CA_InitAudit.argtypes = [CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR]
CA_LogVerify = make_late_binding_function('CA_LogVerify')
CA_LogVerify.restype = CK_RV
CA_LogVerify.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ULONG, CK_ULONG_PTR]
CA_LogVerifyFile = make_late_binding_function('CA_LogVerifyFile')
CA_LogVerifyFile.restype = CK_RV
CA_LogVerifyFile.argtypes = [CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG_PTR]
CA_LogExternal = make_late_binding_function('CA_LogExternal')
CA_LogExternal.restype = CK_RV
CA_LogExternal.argtypes = [CK_SLOT_ID, CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG]
CA_LogImportSecret = make_late_binding_function('CA_LogImportSecret')
CA_LogImportSecret.restype = CK_RV
CA_LogImportSecret.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR]
CA_LogExportSecret = make_late_binding_function('CA_LogExportSecret')
CA_LogExportSecret.restype = CK_RV
CA_LogExportSecret.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR]
CA_TimeSync = make_late_binding_function('CA_TimeSync')
CA_TimeSync.restype = CK_RV
CA_TimeSync.argtypes = [CK_SESSION_HANDLE, CK_ULONG]
CA_GetTime = make_late_binding_function('CA_GetTime')
CA_GetTime.restype = CK_RV
CA_GetTime.argtypes = [CK_SESSION_HANDLE, CK_ULONG_PTR]
CA_LogSetConfig = make_late_binding_function('CA_LogSetConfig')
CA_LogSetConfig.restype = CK_RV
CA_LogSetConfig.argtypes = [CK_SESSION_HANDLE, CK_ULONG, CK_ULONG, CK_ULONG, CK_ULONG, CK_BYTE_PTR]
CA_LogGetConfig = make_late_binding_function('CA_LogGetConfig')
CA_LogGetConfig.restype = CK_RV
CA_LogGetConfig.argtypes = [CK_SESSION_HANDLE, POINTER(CK_ULONG), POINTER(CK_ULONG), POINTER(CK_ULONG), POINTER(CK_ULONG), CK_BYTE_PTR]
CA_LogEraseAll = make_late_binding_function('CA_LogEraseAll')
CA_LogEraseAll.restype = CK_RV
CA_LogEraseAll.argtypes = [CK_SESSION_HANDLE]
CA_LogGetStatus = make_late_binding_function('CA_LogGetStatus')
CA_LogGetStatus.restype = CK_RV
CA_LogGetStatus.argtypes = [CK_SLOT_ID, POINTER(CK_ULONG), POINTER(CK_ULONG), POINTER(CK_ULONG), POINTER(CK_ULONG), POINTER(CK_ULONG)]
CA_DeleteContainerWithHandle = make_late_binding_function('CA_DeleteContainerWithHandle')
CA_DeleteContainerWithHandle.restype = CK_RV
CA_DeleteContainerWithHandle.argtypes = [CK_SESSION_HANDLE, CK_ULONG]
CA_GetContainerList = make_late_binding_function('CA_GetContainerList')
CA_GetContainerList.restype = CK_RV
CA_GetContainerList.argtypes = [CK_SLOT_ID, CK_ULONG, CK_ULONG, CK_ULONG_PTR, CK_ULONG_PTR]
CA_GetContainerName = make_late_binding_function('CA_GetContainerName')
CA_GetContainerName.restype = CK_RV
CA_GetContainerName.argtypes = [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
CA_GetNumberOfAllowedContainers = make_late_binding_function('CA_GetNumberOfAllowedContainers')
CA_GetNumberOfAllowedContainers.restype = CK_RV
CA_GetNumberOfAllowedContainers.argtypes = [CK_SLOT_ID, CK_ULONG_PTR]
CA_GetTunnelSlotNumber = make_late_binding_function('CA_GetTunnelSlotNumber')
CA_GetTunnelSlotNumber.restype = CK_RV
CA_GetTunnelSlotNumber.argtypes = [CK_SLOT_ID, CK_SLOT_ID_PTR]
CA_GetClusterState = make_late_binding_function('CA_GetClusterState')
CA_GetClusterState.restype = CK_RV
CA_GetClusterState.argtypes = [CK_SLOT_ID, CK_CLUSTER_STATE_PTR]
CA_LockClusteredSlot = make_late_binding_function('CA_LockClusteredSlot')
CA_LockClusteredSlot.restype = CK_RV
CA_LockClusteredSlot.argtypes = [CK_SLOT_ID]
CA_UnlockClusteredSlot = make_late_binding_function('CA_UnlockClusteredSlot')
CA_UnlockClusteredSlot.restype = CK_RV
CA_UnlockClusteredSlot.argtypes = [CK_SLOT_ID]
CA_LKMInitiatorChallenge = make_late_binding_function('CA_LKMInitiatorChallenge')
CA_LKMInitiatorChallenge.restype = CK_RV
CA_LKMInitiatorChallenge.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_ULONG, CK_LKM_TOKEN_ID_PTR, CK_LKM_TOKEN_ID_PTR, CK_CHAR_PTR, CK_ULONG_PTR]
CA_LKMReceiverResponse = make_late_binding_function('CA_LKMReceiverResponse')
CA_LKMReceiverResponse.restype = CK_RV
CA_LKMReceiverResponse.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_ULONG, CK_LKM_TOKEN_ID_PTR, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR, CK_ULONG_PTR]
CA_LKMInitiatorComplete = make_late_binding_function('CA_LKMInitiatorComplete')
CA_LKMInitiatorComplete.restype = CK_RV
CA_LKMInitiatorComplete.argtypes = [CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_CHAR_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR]
CA_LKMReceiverComplete = make_late_binding_function('CA_LKMReceiverComplete')
CA_LKMReceiverComplete.restype = CK_RV
CA_LKMReceiverComplete.argtypes = [CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR]
CA_ModifyUsageCount = make_late_binding_function('CA_ModifyUsageCount')
CA_ModifyUsageCount.restype = CK_RV
CA_ModifyUsageCount.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG, CK_ULONG]
CK_GetTotalOperations = CFUNCTYPE(CK_RV, CK_SLOT_ID, POINTER(c_int))
CK_ResetTotalOperations = CFUNCTYPE(CK_RV, CK_SLOT_ID)
CK_CA_SinglePartSign = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_CA_SinglePartDecrypt = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
__all__ = ['CA_InvokeService', 'CA_GetSecondarySlot',
           'CK_OTP_SIGNATURE_INFO', 'C_FindObjectsFinal',
           'CK_C_EncryptFinal',
           'CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE',
           'CK_CA_HAAnswerMofNChallenge', 'CK_CA_InvokeServiceInit',
           'CK_ECDH1_DERIVE_PARAMS', 'C_UnwrapKey',
           'CA_DismantleRemotePED', 'CA_PerformModuleCall',
           'CA_SetApplicationID', 'CK_OTP_PARAM',
           'CA_LoadEncryptedModule', 'CA_MTKZeroize',
           'CK_C_VerifyInit', 'CK_LKM_TOKEN_ID_PTR',
           'CK_RC2_PARAMS_PTR', 'CK_WTLS_PRF_PARAMS_PTR',
           'CK_C_CancelFunction', 'CK_CA_GetContainerStatus',
           'CK_CA_FactoryReset', 'CK_CA_Restart',
           'CK_C_VerifyRecover', 'CK_CA_SetDestructiveHSMPolicy',
           'CK_CA_SpRawRead', 'C_SetAttributeValue',
           'CK_RC2_CBC_PARAMS_PTR', 'CA_CloseAllSecondarySessions',
           'CK_C_GetOperationState', 'CK_C_SetOperationState',
           'CK_CA_CloseApplicationIDForContainer', 'C_VerifyFinal',
           'CK_CA_LogVerifyFile', 'CK_TOKEN_INFO',
           'CK_RSA_PKCS_OAEP_PARAMS',
           'CK_CA_CloseAllSecondarySessions', 'CK_DATE',
           'CA_ReadCommonStore',
           'CA_GetConfigurationElementDescription',
           'CK_WTLS_PRF_PARAMS', 'CK_RC2_MAC_GENERAL_PARAMS',
           'CK_CA_CapabilityUpdate', 'CK_SESSION_HANDLE',
           'CK_RC5_PARAMS', 'CK_SLOT_INFO', 'C_GetInfo',
           'CK_CA_SpRawWrite', 'CK_C_EncryptInit', 'C_Login',
           'CK_CA_CloneAllObjectsToSession', 'C_GetMechanismInfo',
           'CK_CA_GetConfigurationElementDescription', 'CK_C_SetPIN',
           'CA_QueryLicense', 'C_Logout', 'C_Finalize',
           'C_CreateObject', 'CK_ATTRIBUTE_PTR', 'CK_VERSION',
           'CK_CA_GetFPV', 'CK_SESSION_HANDLE_PTR',
           'CK_CA_FirmwareUpdate', 'CK_CA_OpenSession',
           'CK_RC2_MAC_GENERAL_PARAMS_PTR', 'CA_CloseApplicationID',
           'C_WaitForSlotEvent', 'CA_Restart', 'CK_HW_FEATURE_TYPE',
           'CA_CloneAsTargetInit', 'C_FindObjects', 'CK_C_Logout',
           'CK_VOID_PTR', 'CK_C_Sign', 'CK_CA_GetTunnelSlotNumber',
           'CA_HAGetLoginChallenge', 'CA_CreateContainer',
           'CA_EncodeECParamsFromFile', 'CK_CA_ReadCommonStore',
           'CA_LogSetConfig', 'CK_MECHANISM_INFO', 'CK_C_GetInfo',
           'CKCA_MODULE_ID_PTR', 'CK_C_INITIALIZE_ARGS', 'CK_LONG',
           'CA_MOFN_GENERATION', 'CKCA_MODULE_ID',
           'CA_GetTokenCertificateInfo', 'C_Decrypt', 'CA_InitAudit',
           'CK_C_SignEncryptUpdate', 'CA_GetExtendedTPV',
           'CK_SFNT_CA_FUNCTION_LIST_PTR',
           'CK_SKIPJACK_PRIVATE_WRAP_PTR', 'CA_GetContainerPolicySet',
           'CK_EXTRACT_PARAMS_PTR', 'CA_LoadModule',
           'CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_PTR',
           'CA_FirmwareRollback',
           'CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR', 'CK_CA_SetKCV',
           'CK_CA_GetObjectUID', 'CK_OBJECT_HANDLE_PTR',
           'CA_LogExportSecret', 'CA_Deactivate',
           'C_DecryptDigestUpdate',
           'CA_OpenApplicationIDForContainer', 'C_SetOperationState',
           'CK_X9_42_DH_KDF_TYPE', 'CK_AES_GCM_PARAMS',
           'CK_CA_ConfigureRemotePED', 'CK_HA_STATE_PTR',
           'CA_HAActivateMofN', 'CK_CA_MultisignValue',
           'CA_SetHSMPolicies', 'CA_GetHSMCapabilitySet',
           'CA_UnloadModule', 'CK_KIP_PARAMS', 'CK_CA_HAInit',
           'CA_LKMReceiverResponse', 'CK_CERTIFICATE_TYPE',
           'CK_XOR_BASE_DATA_KDF_PARAMS', 'CK_OTP_PARAM_PTR',
           'CK_C_InitPIN', 'CK_AES_CBC_PAD_EXTRACT_PARAMS',
           'CK_X9_42_MQV_DERIVE_PARAMS', 'CK_CA_GetHAState',
           'CA_SetContainerPolicy', 'C_CloseAllSessions',
           'CA_Extract', 'CK_OBJECT_CLASS',
           'CK_SKIPJACK_RELAYX_PARAMS_PTR', 'C_VerifyRecover',
           'CA_GetModuleInfo', 'CK_FLAGS', 'CK_TLS_PRF_PARAMS',
           'CK_CA_FirmwareRollback', 'CK_WTLS_KEY_MAT_OUT',
           'CK_CMS_SIG_PARAMS', 'CK_CA_GetExtendedTPV',
           'CA_GetObjectHandle', 'CK_CA_GetContainerName',
           'CA_GetRemotePEDVectorStatus', 'CK_C_GetFunctionList',
           'CK_CA_SetHSMPolicy', 'CK_SLOT_ID', 'CK_CA_LogGetStatus',
           'CA_CapabilityUpdate', 'CK_CA_SIMMultiSign',
           'CK_C_DigestEncryptUpdate', 'C_GetSlotInfo',
           'CK_HA_MEMBER', 'C_VerifyRecoverInit',
           'CA_GetTokenInsertionCount', 'C_DigestKey',
           'CK_C_OpenSession', 'CK_CA_ResetDevice',
           'CK_CA_LogExternal', 'CA_IndirectLogin',
           'C_FindObjectsInit', 'CA_SIMExtract',
           'CK_C_FindObjectsInit', 'CK_RSA_PKCS_OAEP_SOURCE_TYPE',
           'CK_UNLOCKMUTEX', 'CK_CA_GetNumberOfAllowedContainers',
           'CK_CA_SIMExtract', 'CK_ULONG_PTR', 'CK_CA_MTKResplit',
           'CK_CA_GetFunctionList', 'CKCA_MODULE_INFO',
           'CK_CA_HAGetMasterPublic', 'C_PerformSelfTest',
           'CK_CA_CloneAsTarget', 'CK_CA_RetrieveLicenseList',
           'CK_UTF8CHAR_PTR', 'CA_LogEraseAll', 'CA_CloneAsSource',
           'CK_ECMQV_DERIVE_PARAMS', 'CK_CA_LKMReceiverComplete',
           'CA_InvokeServiceSinglePart', 'CK_KDF_PRF_ENCODING_SCHEME',
           'CK_C_Finalize', 'CA_MOFN_ACTIVATION_PTR', 'CK_KEY_TYPE',
           'CK_RSA_PKCS_PSS_PARAMS', 'CA_GetFunctionList',
           'CK_FUNCTION_LIST', 'CK_C_DecryptInit',
           'CK_CA_UnloadModule', 'CA_GetTPV', 'CA_OpenSession',
           'CA_InvokeServiceFinal', 'CK_CA_EncodeECParamsFromFile',
           'CA_LockClusteredSlot', 'CK_CA_RestartForContainer',
           'CK_INFO_PTR', 'CA_FactoryReset',
           'CA_SetUserContainerName', 'CK_TLS_PRF_PARAMS_PTR',
           'CA_DestroyMultipleObjects', 'CK_PBE_PARAMS',
           'CK_CA_InsertMaskedObject', 'CA_GetHSMStorageInformation',
           'CA_EncodeECPrimeParams', 'C_OpenSession',
           'CK_CA_SetUserContainerName',
           'CA_DeleteContainerWithHandle', 'CA_CloneObject',
           'CA_MOFN_ACTIVATION', 'CA_GetNumberOfAllowedContainers',
           'CA_WaitForSlotEvent', 'CA_ChoosePrimarySlot',
           'CK_CA_GetContainerCapabilitySet',
           'CK_WTLS_RANDOM_DATA_PTR', 'C_VerifyInit',
           'CK_C_CloseAllSessions', 'CK_RSA_PKCS_PSS_PARAMS_PTR',
           'CK_USER_TYPE', 'C_GetMechanismList', 'C_GetObjectSize',
           'C_GenerateRandom', 'CK_CA_DeleteContainerWithHandle',
           'CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR', 'CK_LOCKMUTEX',
           'CK_CA_SetHSMPolicies', 'CK_CA_GetRemotePEDVectorStatus',
           'CK_ARIA_CTR_PARAMS', 'C_GetAttributeValue',
           'CK_CA_GetTime', 'CA_OpenApplicationID',
           'CK_CA_GenerateCloningKEV', 'CK_C_DecryptUpdate',
           'CK_CAMELLIA_CTR_PARAMS', 'CA_LogVerifyFile',
           'CA_M_OF_N_STATUS', 'CK_C_CloseSession',
           'CK_EC_ENC_SCHEME', 'CK_C_INITIALIZE_ARGS_PTR',
           'CK_CA_SetLKCV', 'CK_MECHANISM_INFO_PTR',
           'CA_DuplicateMofN', 'CK_CA_GetModuleList',
           'CK_DES_CTR_PARAMS', 'CK_AES_CBC_PAD_INSERT_PARAMS_PTR',
           'C_GetFunctionStatus', 'CK_CA_PerformModuleCall',
           'CA_GetClusterState', 'CK_OTP_PARAMS_PTR',
           'CK_C_SignRecoverInit', 'CK_CA_SetExtendedTPV',
           'CK_CA_SinglePartSign', 'CK_CA_CloseSecondarySession',
           'CK_C_SignFinal', 'CA_SetDestructiveHSMPolicy',
           'CA_ResetPIN', 'CK_CA_GetHSMPolicySet', 'CK_CA_MTKRestore',
           'CK_SSL3_MASTER_KEY_DERIVE_PARAMS', 'CK_C_Digest',
           'CK_WTLS_KEY_MAT_OUT_PTR', 'CK_AES_GMAC_PARAMS',
           'CK_OBJECT_HANDLE', 'CK_ARIA_CBC_ENCRYPT_DATA_PARAMS',
           'C_SeedRandom', 'C_WrapKey', 'CA_RestartForContainer',
           'CK_PKCS5_PBKD2_PARAMS', 'CK_MAC_GENERAL_PARAMS',
           'CK_C_VerifyUpdate', 'CK_C_Verify', 'CA_CloneMofN',
           'CK_CA_SwitchSecondarySlot', 'CK_ATTRIBUTE_TYPE',
           'CK_CA_GetTokenCertificates',
           'CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR',
           'CK_CA_GetMofNStatus', 'CK_CA_GetRollbackFirmwareVersion',
           'CK_CA_WriteCommonStore', 'CA_GetPedId',
           'CA_InitIndirectToken',
           'CK_CA_GetContainerCapabilitySetting',
           'CK_CA_GenerateMofN', 'CK_C_GetMechanismInfo',
           'CK_CA_GetPrimarySlot', 'CK_C_DigestFinal',
           'CK_X9_42_DH2_DERIVE_PARAMS', 'CA_LogExternal',
           'CA_ClonePrivateKey', 'CA_ManualKCV', 'CK_EC_MAC_SCHEME',
           'CK_CA_GetTokenCertificateInfo', 'CK_CA_DeleteContainer',
           'CK_CA_GetContainerPolicySet', 'C_CancelFunction',
           'CK_HA_STATUS', 'CK_CA_OpenApplicationIDForContainer',
           'CK_C_DigestKey', 'CA_ConfigureRemotePED', 'C_Initialize',
           'C_DestroyObject', 'CK_RSA_PKCS_OAEP_PARAMS_PTR',
           'CA_DeleteContainer', 'CK_ECDH1_DERIVE_PARAMS_PTR',
           'C_InitToken', 'CK_C_WrapKey', 'CA_EncodeECChar2Params',
           'CK_CA_ActivateMofN',
           'CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR',
           'CA_SpRawWrite', 'C_GetSessionInfo',
           'CK_CA_InitIndirectPIN', 'CA_DeleteRemotePEDVector',
           'CK_CA_UnlockClusteredSlot', 'CK_CA_CloneModifyMofN',
           'CK_KDF_PRF_PARAMS', 'CK_CA_DestroyMultipleObjects',
           'C_GetSlotList', 'CK_ULONG', 'CK_SSL3_KEY_MAT_OUT_PTR',
           'CK_CA_GetHSMPolicySetting', 'CK_C_GenerateRandom',
           'CK_CA_ModifyUsageCount', 'CA_MTKResplit', 'CK_CHAR',
           'CK_STATE', 'CK_CA_GetHSMCapabilitySetting',
           'CK_KEY_WRAP_SET_OAEP_PARAMS', 'CA_GetPrimarySlot',
           'CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR',
           'CK_X9_42_DH1_DERIVE_PARAMS', 'CA_GetMofNStatus',
           'CK_C_EncryptUpdate', 'CK_DESTROYMUTEX',
           'CK_CMS_SIG_PARAMS_PTR', 'CK_CA_CheckOperationState',
           'CK_C_UnwrapKey', 'CK_CA_GetContainerList',
           'CK_WTLS_KEY_MAT_PARAMS_PTR', 'CA_MultisignValue',
           'CK_ECMQV_DERIVE_PARAMS_PTR', 'CK_CA_InitIndirectToken',
           'CA_GetTSV', 'CA_InitIndirectPIN', 'CK_CA_SetPedId',
           'CA_GenerateMofN', 'CK_CA_DeactivateMofN', 'C_DeriveKey',
           'C_Verify', 'CK_CA_Extract', 'C_DigestUpdate',
           'CK_CA_GetHSMStorageInformation', 'CA_SpRawRead',
           'CK_C_SetAttributeValue', 'CK_CA_GetHSMCapabilitySet',
           'C_SignFinal', 'CA_SIMMultiSign', 'CK_C_GenerateKey',
           'C_DecryptFinal', 'CA_UnlockClusteredSlot',
           'CK_CA_CloneAsSource', 'CK_C_GetSlotList',
           'CK_FUNCTION_LIST_PTR', 'CK_AES_CTR_PARAMS_PTR',
           'CA_FirmwareUpdate', 'CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE',
           'CK_USHORT_PTR', 'CA_CloseSecondarySession',
           'CK_PKCS5_PBKD2_PARAMS_PTR', 'CK_DES_CTR_PARAMS_PTR',
           'CA_ActivateMofN', 'CK_RSA_PKCS_MGF_TYPE',
           'CK_EXTRACT_PARAMS', 'CK_C_DeriveKey', 'CA_SIMInsert',
           'CK_SFNT_CA_FUNCTION_LIST', 'CK_RC5_CBC_PARAMS_PTR',
           'CK_CA_OpenApplicationID', 'CK_AES_GMAC_PARAMS_PTR',
           'CK_RC5_MAC_GENERAL_PARAMS', 'CK_CA_InvokeService',
           'CK_CAMELLIA_CTR_PARAMS_PTR',
           'CK_AES_CBC_PAD_EXTRACT_PARAMS_PTR',
           'CA_RetrieveLicenseList', 'CA_GetHSMPolicySetting',
           'CK_SEED_CTR_PARAMS', 'CK_ResetTotalOperations',
           'CA_HALogin', 'CA_MOFN_GENERATION_PTR',
           'CK_AES_GCM_PARAMS_PTR', 'CK_C_VerifyRecoverInit',
           'CK_CA_SetContainerSize', 'CK_LKM_TOKEN_ID',
           'CK_CA_HALogin', 'CA_CloneObjectToAllSessions',
           'CA_Insert', 'CK_ECDH2_DERIVE_PARAMS_PTR',
           'CK_CA_ChoosePrimarySlot', 'CA_LogGetConfig',
           'CK_C_DecryptDigestUpdate', 'CK_SSL3_KEY_MAT_PARAMS',
           'CK_CA_LogSetConfig', 'CK_CA_IndirectLogin',
           'CK_CA_InvokeServiceAsynch', 'CA_MTKSetStorage',
           'CK_CA_WaitForSlotEvent', 'CK_OTP_SIGNATURE_INFO_PTR',
           'CA_HAAnswerMofNChallenge', 'CK_CA_InitAudit',
           'CK_SSL3_RANDOM_DATA', 'CK_WTLS_RANDOM_DATA',
           'CK_DES_CBC_ENCRYPT_DATA_PARAMS', 'CK_RC5_CBC_PARAMS',
           'CK_C_SeedRandom', 'CK_USHORT',
           'CK_CA_SetContainerPolicies', 'CK_CLUSTER_STATE',
           'CA_MTKRestore', 'CK_C_CreateObject', 'CK_TOKEN_INFO_PTR',
           'CA_SetMofN', 'CA_CloneModifyMofN',
           'CK_CA_LoadEncryptedModule', 'CK_C_DecryptFinal',
           'CK_AES_CBC_PAD_INSERT_PARAMS', 'CK_CA_SetContainerPolicy',
           'CK_ECIES_PARAMS', 'CK_CA_CloneObject', 'CA_SetTPV',
           'C_GenerateKeyPair', 'CK_SFNT_CA_FUNCTION_LIST_PTR_PTR',
           'CK_CA_MTKSetStorage', 'CKA_SIM_AUTH_FORM',
           'CK_CA_LKMInitiatorChallenge', 'CK_CA_HAActivateMofN',
           'CK_KEY_DERIVATION_STRING_DATA', 'CK_MECHANISM_PTR',
           'CK_C_SignRecover', 'CA_LKMInitiatorComplete',
           'CA_SetTokenCertificateSignature',
           'CA_GetUserContainerName', 'CK_HA_MEMBER_PTR',
           'CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS',
           'CK_CA_ExtractMaskedObject', 'CK_C_GetFunctionStatus',
           'CK_CA_GetContainerPolicySetting', 'CK_PRF_KDF_PARAMS',
           'CK_CA_Deactivate', 'CK_SLOT_INFO_PTR',
           'CK_X9_42_DH1_DERIVE_PARAMS_PTR', 'CK_CLUSTER_STATE_PTR',
           'CK_C_GetTokenInfo', 'CK_C_VerifyFinal',
           'CA_CheckOperationState', 'C_GetTokenInfo', 'C_Digest',
           'CA_CloneAsTarget', 'CA_SetCloningDomain',
           'CK_OTP_PARAM_TYPE', 'CA_GetUserContainerNumber',
           'CK_KEY_WRAP_SET_OAEP_PARAMS_PTR', 'CA_GetObjectUID',
           'CK_VERSION_PTR', 'CA_HAAnswerLoginChallenge',
           'CK_CA_GetSessionInfo', 'CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR',
           'C_SignEncryptUpdate', 'CA_GetHSMCapabilitySetting',
           'CK_CA_GetSecondarySlot', 'CK_CA_DuplicateMofN',
           'C_DecryptInit', 'CK_RC5_PARAMS_PTR',
           'CK_KEA_DERIVE_PARAMS', 'CK_C_DigestInit', 'CA_ModifyMofN',
           'CK_MECHANISM_TYPE_PTR', 'CA_MTKGetState',
           'CK_CA_LogExportSecret',
           'CK_WTLS_MASTER_KEY_DERIVE_PARAMS', 'CA_InvokeServiceInit',
           'CK_XOR_BASE_DATA_KDF_PARAMS_PTR', 'CK_SESSION_INFO',
           'C_SignUpdate', 'CK_CA_CloneObjectToAllSessions',
           'C_SignInit', 'CK_MECHANISM_TYPE',
           'CK_WTLS_KEY_MAT_PARAMS', 'CA_SetKCV',
           'CK_CA_CreateContainer', 'CA_ExtractMaskedObject',
           'C_EncryptInit', 'C_DigestEncryptUpdate', 'CK_OTP_PARAMS',
           'CK_SEED_CTR_PARAMS_PTR', 'CK_KDF_PRF_PARAMS_PTR',
           'CA_GetContainerCapabilitySet', 'CK_CA_LogGetConfig',
           'C_DigestFinal', 'CK_CA_HAAnswerLoginChallenge',
           'CK_CA_LockClusteredSlot',
           'CK_CA_GetContainerStorageInformation', 'CK_ATTRIBUTE',
           'CK_CA_SetDestructiveHSMPolicies',
           'CK_RSA_PKCS_MGF_TYPE_PTR', 'CK_SKIPJACK_RELAYX_PARAMS',
           'CK_PBE_PARAMS_PTR', 'CK_MECHANISM',
           'CA_GetContainerCapabilitySetting',
           'CA_GetContainerStatus', 'CA_InvokeServiceAsynch',
           'CK_CA_CloneAsTargetInit', 'C_Encrypt',
           'CK_LKM_TOKEN_ID_S', 'CK_C_WaitForSlotEvent',
           'CK_C_SignUpdate', 'CK_CA_LogVerify',
           'CK_CA_SetApplicationID', 'CK_CA_GetTSV',
           'CK_AES_CBC_ENCRYPT_DATA_PARAMS', 'CK_ARIA_CTR_PARAMS_PTR',
           'C_EncryptFinal', 'CA_LKMReceiverComplete',
           'CK_C_DecryptVerifyUpdate', 'CK_CA_GetUserContainerNumber',
           'CK_EC_KDF_TYPE', 'CK_KEY_DERIVATION_STRING_DATA_PTR',
           'CA_InitializeRemotePEDVector', 'CA_LogVerify',
           'CA_GetFPV', 'CA_HAInit', 'C_CloseSession',
           'CA_GetHAState', 'CA_SetDestructiveHSMPolicies',
           'C_SignRecoverInit', 'CK_EC_DH_PRIMITIVE',
           'CK_CA_ManualKCV', 'CK_C_Login', 'CA_IsMofNEnabled',
           'CK_CA_InvokeServiceSinglePart', 'CA_LogGetStatus',
           'CK_CA_QueryLicense', 'CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR',
           'CK_C_FindObjectsFinal', 'CK_CREATEMUTEX',
           'CK_SLOT_ID_PTR', 'CA_IsMofNRequired',
           'CK_FUNCTION_LIST_PTR_PTR', 'CA_HAGetMasterPublic',
           'CK_CA_LKMInitiatorComplete', 'CK_CA_LogEraseAll',
           'CA_CloseApplicationIDForContainer',
           'CK_CA_GenerateTokenKeys', 'CK_BYTE',
           'CK_SSL3_KEY_MAT_OUT', 'CA_SetContainerPolicies',
           'C_DecryptVerifyUpdate', 'CA_GenerateCloningKEV',
           'CA_SetHSMPolicy', 'CK_CA_GetTPV',
           'CK_CA_SinglePartDecrypt', 'CK_GetTotalOperations',
           'CK_UTF8CHAR', 'CK_CA_GetObjectHandle', 'CK_CA_Insert',
           'CK_CA_SetTokenCertificateSignature', 'CK_RV', 'CK_NOTIFY',
           'CK_CA_InitializeRemotePEDVector', 'CKCA_MODULE_INFO_PTR',
           'CK_C_FindObjects', 'C_DigestInit',
           'CA_GetContainerStorageInformation', 'CK_BYTE_PTR',
           'CA_ModifyUsageCount', 'CK_CA_TimeSync', 'CA_SetPedId',
           'CA_GetHSMPolicySet', 'CK_CA_ModifyMofN', 'C_CopyObject',
           'CK_CA_CloseApplicationID', 'CA_GetContainerPolicySetting',
           'CK_SSL3_KEY_MAT_PARAMS_PTR', 'C_VerifyUpdate',
           'CK_NOTIFICATION', 'CK_CA_LogImportSecret',
           'CA_GenerateTokenKeys', 'CK_X9_42_MQV_DERIVE_PARAMS_PTR',
           'CK_CA_SetMofN', 'CK_C_GetAttributeValue',
           'CK_CA_InvokeServiceFinal', 'CA_TimeSync',
           'CA_LKMInitiatorChallenge', 'CK_CA_ResetPIN',
           'CA_GetContainerList', 'CK_C_GetMechanismList',
           'CA_CreateLoginChallenge', 'C_EncryptUpdate',
           'CK_X9_42_DH_KDF_TYPE_PTR',
           'CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_PTR',
           'CK_CA_EncodeECPrimeParams', 'CK_CA_HAGetLoginChallenge',
           'CK_VOID_PTR_PTR', 'CA_MOFN_STATUS', 'CK_C_SignInit',
           'CK_C_Decrypt', 'CK_CA_CloneMofN', 'CK_SESSION_INFO_PTR',
           'CK_CA_IsMofNRequired', 'CK_CA_SIMInsert',
           'CK_C_CopyObject', 'CK_CA_CreateLoginChallenge',
           'CK_KDF_PRF_TYPE', 'CA_GenerateCloneableMofN',
           'CK_CHAR_PTR', 'C_Sign', 'C_SetPIN', 'CK_C_GetObjectSize',
           'CA_ResetDevice', 'CK_CA_GetTokenInsertionCount',
           'CK_C_DigestUpdate', 'CA_GetSessionInfo',
           'C_GetFunctionList', 'CK_CA_SetCloningDomain',
           'CA_DeactivateMofN', 'CK_C_Initialize',
           'C_GetOperationState', 'CK_C_GetSessionInfo',
           'CA_GetModuleList', 'CK_C_Encrypt', 'CK_BBOOL',
           'CK_CA_EncodeECChar2Params', 'CK_CA_GetModuleInfo',
           'C_GenerateKey', 'CK_CA_SetTPV', 'CA_GetTokenCertificates',
           'C_InitPIN', 'C_DecryptUpdate',
           'CK_SKIPJACK_PRIVATE_WRAP_PARAMS', 'CK_KIP_PARAMS_PTR',
           'CK_RC2_CBC_PARAMS', 'CK_C_GetSlotInfo',
           'CA_GetRollbackFirmwareVersion', 'CK_C_DestroyObject',
           'CK_C_GenerateKeyPair', 'CK_C_InitToken',
           'CK_CA_LKMReceiverResponse', 'CA_GetTime',
           'CA_ChooseSecondarySlot', 'CK_CA_GetUserContainerName',
           'CK_CA_MTKZeroize', 'CK_CA_GetClusterState',
           'CK_AES_CTR_PARAMS', 'CA_SetContainerSize',
           'C_SignRecover', 'CA_SetExtendedTPV',
           'CK_ECDH2_DERIVE_PARAMS', 'CA_InsertMaskedObject',
           'CA_CloneAllObjectsToSession', 'CK_ECIES_PARAMS_PTR',
           'CK_X9_42_DH2_DERIVE_PARAMS_PTR', 'CK_CA_GetPedId',
           'CA_WriteCommonStore', 'CK_CA_MTKGetState',
           'CK_CA_DeleteRemotePEDVector', 'CK_KEA_DERIVE_PARAMS_PTR',
           'CA_LogImportSecret', 'CA_SwitchSecondarySlot',
           'CK_MAC_GENERAL_PARAMS_PTR', 'CK_CA_DismantleRemotePED',
           'CK_CA_GenerateCloneableMofN',
           'CK_RC5_MAC_GENERAL_PARAMS_PTR', 'CK_PARAM_TYPE',
           'CK_C_PerformSelfTest', 'CK_CA_ClonePrivateKey', 'CK_INFO',
           'CA_GetTunnelSlotNumber', 'CA_GetContainerName',
           'CK_CA_LoadModule', 'CK_OBJECT_CLASS_PTR',
           'CK_CA_ChooseSecondarySlot', 'CK_CA_IsMofNEnabled',
           'CA_MOFN_STATUS_PTR', 'CK_RC2_PARAMS', 'CA_SetLKCV']
