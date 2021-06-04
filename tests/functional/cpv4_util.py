"""Some utility functions for CPV4"""
from ctypes import c_ubyte, c_void_p, c_ulong, cast, pointer, sizeof, POINTER

from pycryptoki.conversions import from_bytestring
from pycryptoki.attributes import to_byte_array

from pycryptoki.defines import CKM_CPV4_EXTRACT, CKM_CPV4_INSERT, CKF_CPV4_CONTINUE_ON_ERR, CKR_OK
from pycryptoki.cryptoki import (
    CK_MECHANISM,
    CK_MECHANISM_TYPE,
    CK_CPV4_EXTRACT_PARAMS,
    CK_CPV4_INSERT_PARAMS,
    CK_BYTE_PTR,
)

PCPROT_MAX_BUFFER_SIZE = 64000


def initialize_cpv4_extract_params(
    obj_handles, obj_type, input_param, session_ouid, extraction_flags
):
    """

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

    """
    input_param, input_len = to_byte_array(from_bytestring(input_param))
    input_param = cast(input_param, POINTER(c_ubyte))

    session_ouid, session_ouid_len = to_byte_array(from_bytestring(session_ouid))
    session_ouid = cast(session_ouid, POINTER(c_ubyte))

    cpv4_extract_params = CK_CPV4_EXTRACT_PARAMS()

    cpv4_extract_params.input = input_param
    cpv4_extract_params.inputLength = input_len
    cpv4_extract_params.sessionOuidLen = session_ouid_len
    cpv4_extract_params.sessionOuid = session_ouid
    cpv4_extract_params.extractionFlags = extraction_flags
    cpv4_extract_params.objectType = (c_ulong * len(obj_type))(*obj_type)
    cpv4_extract_params.objectHandle = (c_ulong * len(obj_handles))(*obj_handles)
    cpv4_extract_params.numberOfObjects = c_ulong(len(obj_handles))
    cpv4_extract_params.result = (c_ulong * len(obj_handles))()
    cpv4_extract_params.keyBlobLen = (c_ulong * len(obj_handles))()
    cpv4_extract_params.keyBlob = keyBlob = (len(obj_handles) * POINTER(c_ubyte))()

    for i in range(len(obj_handles)):
        cpv4_extract_params.keyBlob[i] = (c_ubyte * PCPROT_MAX_BUFFER_SIZE)()
        cpv4_extract_params.keyBlobLen[i] = PCPROT_MAX_BUFFER_SIZE

    return cpv4_extract_params


def initialize_cpv4_insert_params(
    input_param,
    session_ouid,
    number_of_objects,
    obj_type,
    storage_type,
    key_blob_len,
    key_blob,
    insertion_flags,
):
    """
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

    """
    input_param, input_len = to_byte_array(from_bytestring(input_param))
    input_param = cast(input_param, POINTER(c_ubyte))

    session_ouid, session_ouid_len = to_byte_array(from_bytestring(session_ouid))
    session_ouid = cast(session_ouid, POINTER(c_ubyte))

    cpv4_insert_params = CK_CPV4_INSERT_PARAMS()

    cpv4_insert_params.inputLength = input_len
    cpv4_insert_params.input = input_param
    cpv4_insert_params.sessionOuidLen = session_ouid_len
    cpv4_insert_params.sessionOuid = session_ouid
    cpv4_insert_params.insertionFlags = insertion_flags
    cpv4_insert_params.numberOfObjects = number_of_objects
    cpv4_insert_params.objectType = (c_ulong * len(obj_type))(*obj_type)
    cpv4_insert_params.storageType = (c_ulong * len(storage_type))(*storage_type)
    cpv4_insert_params.keyBlobLen = key_blob_len
    cpv4_insert_params.keyBlob = key_blob
    cpv4_insert_params.objectHandle = (c_ulong * number_of_objects)()
    cpv4_insert_params.result = (c_ulong * number_of_objects)()

    return cpv4_insert_params


def create_cpv4_extract_mech(cpv4_extract_params):
    mech = CK_MECHANISM()
    mech.mechanism = CK_MECHANISM_TYPE(CKM_CPV4_EXTRACT)
    mech.pParameter = cast(pointer(cpv4_extract_params), c_void_p)
    mech.usParameterLen = sizeof(cpv4_extract_params)
    return mech


def create_cpv4_insert_mech(cpv4_insert_params):
    mech = CK_MECHANISM()
    mech.mechanism = CK_MECHANISM_TYPE(CKM_CPV4_INSERT)
    mech.pParameter = cast(pointer(cpv4_insert_params), c_void_p)
    mech.usParameterLen = sizeof(cpv4_insert_params)
    return mech


def generate_cpv4_extract_mech_params(
    obj_handles, obj_type, input_param, session_ouid, extraction_flags=CKF_CPV4_CONTINUE_ON_ERR
):
    cpv4_extract_params = initialize_cpv4_extract_params(
        obj_handles, obj_type, input_param, session_ouid, extraction_flags
    )

    return create_cpv4_extract_mech(cpv4_extract_params)


def generate_cpv4_insert_mech(
    input_param,
    session_ouid,
    number_of_objects,
    obj_type,
    storage_type,
    key_blob_len,
    key_blob,
    insertion_flags=CKF_CPV4_CONTINUE_ON_ERR,
):
    cpv4_insert_params = initialize_cpv4_insert_params(
        input_param,
        session_ouid,
        number_of_objects,
        obj_type,
        storage_type,
        key_blob_len,
        key_blob,
        insertion_flags,
    )

    # Create Put Mechanism object
    return create_cpv4_insert_mech(cpv4_insert_params)


def verify_extracted_objects(cpv4_extracted_params, expected_retcode):
    """
    verifies extracted objects

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
    """
    cpv4_params = cast(cpv4_extracted_params, POINTER(CK_CPV4_EXTRACT_PARAMS)).contents

    number_of_objects = cpv4_params.numberOfObjects
    results = cpv4_params.result
    key_blobs = cpv4_params.keyBlob
    key_blobs_len = cpv4_params.keyBlobLen

    # assert len(results) == numberOfObjs
    # assert len(keyBlobs) == numberOfObjs
    # assert len(keyBlobsLen) == numberOfObjs

    for i in range(number_of_objects):
        assert expected_retcode[i] == results[i]
        if results[i] != CKR_OK:
            del key_blobs[i]
            del key_blobs_len[i]

    return key_blobs, key_blobs_len
