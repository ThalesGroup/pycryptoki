"""
This file should contain the 'redefinitions' of ctypes to common PKCS11 CK types.

These types are the most basic types used in PKCS11.
"""
from ctypes import (
    c_ulong,
    c_ubyte,
    POINTER,
    c_ulonglong,
    c_void_p,
    c_long,
    Structure,
    string_at,
    sizeof,
)

CK_BYTE = c_ubyte
CK_BYTE_PTR = POINTER(CK_BYTE)

CK_LONG = c_long

CK_ULONG = c_ulong
CK_ULONG_PTR = POINTER(CK_ULONG)

CK_UTF8CHAR = CK_BYTE
CK_UTF8CHAR_PTR = POINTER(CK_UTF8CHAR)
CK_RV = CK_ULONG

CK_ULONGLONG = c_ulonglong

CK_VOID_PTR = c_void_p
CK_VOID_PTR_PTR = POINTER(CK_VOID_PTR)


CK_FLAGS = CK_ULONG
CK_SLOT_ID = CK_ULONG
CK_SLOT_ID_PTR = POINTER(CK_SLOT_ID)

CK_USHORT = c_ulong
CK_USHORT_PTR = POINTER(CK_USHORT)


CK_CHAR = CK_BYTE
CK_CHAR_PTR = POINTER(CK_CHAR)

CK_BBOOL = CK_BYTE
