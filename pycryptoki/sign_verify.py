from cryptoki import CK_MECHANISM, CK_MECHANISM_TYPE, CK_VOID_PTR, CK_ULONG, \
    CK_BYTE_PTR, C_SignInit, C_Sign
from ctypes import create_string_buffer, cast, byref, sizeof, pointer, c_void_p
from defines import CKR_OK, CKM_RSA_PKCS_PSS, CKM_SHA1_RSA_PKCS_PSS, \
    CKM_SHA224_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, \
    CKM_SHA512_RSA_PKCS_PSS, CKM_SHA_1, CKM_SHA224, CKM_SHA256, CKM_SHA384, \
    CKM_SHA512, CKG_MGF1_SHA1, CKG_MGF1_SHA224, CKG_MGF1_SHA256, CKG_MGF1_SHA384, \
    CKG_MGF1_SHA512
from pycryptoki.attributes import convert_ck_char_array_to_string
from pycryptoki.cryptoki import C_VerifyInit, C_Verify, C_SignUpdate, \
    C_SignFinal, C_VerifyUpdate, C_VerifyFinal, CK_RSA_PKCS_PSS_PARAMS
from pycryptoki.encryption import _get_string_from_list, \
    get_c_data_to_sign_or_encrypt
from pycryptoki.test_functions import make_error_handle_function
import logging

logger = logging.getLogger(__name__)

def get_mechanism_for_sigver(flavour):
    """
    Tries to build a default mechanism if none is provided,
    most mechanisms just need the .pParameter field to be null.
    If they don't the mechanism can be instantiated here.
    """
    mech = CK_MECHANISM()
    mech.mechanism = CK_MECHANISM_TYPE(flavour)
   
    default_salt_len = 8
    if flavour == CKM_RSA_PKCS_PSS or \
        flavour == CKM_SHA1_RSA_PKCS_PSS:
        
        p = CK_RSA_PKCS_PSS_PARAMS()
        p.hashAlg = CK_ULONG(CKM_SHA_1)
        p.mgf = CK_ULONG(CKG_MGF1_SHA1)
        p.usSaltLen = CK_ULONG(default_salt_len)
        
        mech.pParameter = cast(pointer(p), c_void_p)
        mech.usParameterLen = CK_ULONG(sizeof(p))
    elif flavour == CKM_SHA224_RSA_PKCS_PSS:
        p = CK_RSA_PKCS_PSS_PARAMS()
        p.hashAlg = CK_ULONG(CKM_SHA224)
        p.mgf = CK_ULONG(CKG_MGF1_SHA224)
        p.usSaltLen = CK_ULONG(default_salt_len)
        
        mech.pParameter = cast(pointer(p), c_void_p)
        mech.usParameterLen = CK_ULONG(sizeof(p))
    elif flavour == CKM_SHA256_RSA_PKCS_PSS:
        p = CK_RSA_PKCS_PSS_PARAMS()
        p.hashAlg = CK_ULONG(CKM_SHA256)
        p.mgf = CK_ULONG(CKG_MGF1_SHA256)
        p.usSaltLen = CK_ULONG(default_salt_len)
        
        mech.pParameter = cast(pointer(p), c_void_p)
        mech.usParameterLen = CK_ULONG(sizeof(p))
    elif flavour == CKM_SHA384_RSA_PKCS_PSS:
        p = CK_RSA_PKCS_PSS_PARAMS()
        p.hashAlg = CK_ULONG(CKM_SHA384)
        p.mgf = CK_ULONG(CKG_MGF1_SHA384)
        p.usSaltLen = CK_ULONG(default_salt_len)
        
        mech.pParameter = cast(pointer(p), c_void_p)
        mech.usParameterLen = CK_ULONG(sizeof(p))        
    elif flavour == CKM_SHA512_RSA_PKCS_PSS:
        p = CK_RSA_PKCS_PSS_PARAMS()
        p.hashAlg = CK_ULONG(CKM_SHA512)
        p.mgf = CK_ULONG(CKG_MGF1_SHA512)
        p.usSaltLen = CK_ULONG(default_salt_len)
        
        mech.pParameter = cast(pointer(p), c_void_p)
        mech.usParameterLen = CK_ULONG(sizeof(p))
    else:
        mech.pParameter = CK_VOID_PTR(0)
        mech.usParameterLen = CK_ULONG(0)
    return mech

def c_sign(h_session, sign_flavor, data_to_sign, h_key, mech = None):
    '''
    Performs a C_SignInit and C_Sign operation on some data
    
    @param h_session: The current session
    @param sign_flavor: The flavour of signing to do
    @param data_to_sign: The data to sign, either a string or a list of strings. If this is a list
    a multipart operation will be used (using C_...Update and C_...Final)
    ex:
    - "This is a proper argument of some data to use in the function"
    - ["This is another format of data this", "function will accept.", "It will operate on these strings in parts"]
    @param h_key: The key to sign the data with
    @param mech: The mechanism to use, if None a blank mechanism will be created based on the sign_flavor
    
    @return The result code, A python string represeting the signature
    '''
    
    #Get the mechanism
    if (mech == None):
        mech = get_mechanism_for_sigver(sign_flavor)
    
    #Initialize the sign operation
    ret = C_SignInit(h_session, byref(mech), CK_ULONG(h_key))
    if ret != CKR_OK: return ret, None
    
    #if a list is passed out do a sign operation on each string in the list, otherwise just do one sign operation
    is_multi_part_operation = isinstance(data_to_sign, list) or isinstance(data_to_sign, tuple)
    
    if is_multi_part_operation:
        ret, signature_string = do_multipart_sign_or_digest(h_session, C_SignUpdate, C_SignFinal, data_to_sign)
    else:
        #Prepare the data to sign
        c_data_to_sign = get_c_data_to_sign_or_encrypt(data_to_sign)
        plain_date_len = CK_ULONG(len(data_to_sign))
        
        #Get the length of the output
        sign_len = CK_ULONG()
        ret = C_Sign(h_session, c_data_to_sign, plain_date_len, None, byref(sign_len))
        if ret != CKR_OK: return ret, None
    
        #Actually get the signature    
        signature_buffer = create_string_buffer("", sign_len.value)
        signature = cast(signature_buffer, CK_BYTE_PTR)
        ret = C_Sign(h_session, c_data_to_sign, plain_date_len, signature, byref(sign_len))
        
        ck_char_array = signature._objects.values()[0]
        signature_string = ''
        if sign_len.value > 0:
            signature_string = convert_ck_char_array_to_string(ck_char_array)[0:(sign_len.value)]
        
    return ret, signature_string
c_sign_ex = make_error_handle_function(c_sign)

def do_multipart_sign_or_digest(h_session, c_update_function, c_final_function, input_data_list):
    '''
    Does a multipart sign or digest operation
    '''
    max_data_chunk_size = 0xfff0
    plain_data_len = len(_get_string_from_list(input_data_list))
        
    remaining_length = plain_data_len
    python_string = ''
    i = 0
    while remaining_length > 0:
        current_chunk = input_data_list[i]
        
        #Prepare arguments for decrypt update operation
        current_chunk_len = min(len(current_chunk), remaining_length)
        
        if current_chunk_len > max_data_chunk_size:
            raise Exception("chunk_sizes variable too large, the maximum size of a chunk is " + str(max_data_chunk_size))
        
        data_chunk = get_c_data_to_sign_or_encrypt(current_chunk)
        
        ret = c_update_function(h_session, data_chunk, CK_ULONG(current_chunk_len))
        if ret != CKR_OK: return ret, None
        
        remaining_length -= current_chunk_len
        
        i += 1
    
    #Finalizing multipart decrypt operation
    out_data_len = CK_ULONG(max_data_chunk_size)
    output = cast(create_string_buffer("", out_data_len.value), CK_BYTE_PTR)
    ret = c_final_function(h_session, output, byref(out_data_len))
    
    #Get output
    ck_char_array = output._objects.values()[0]
    if (out_data_len.value > 0):
        python_string += convert_ck_char_array_to_string(ck_char_array)[0:out_data_len.value]
    
    return ret, python_string
    
def do_multipart_verify(h_session, input_data_list, signature):
    '''
    Does a multipart verify operation
    '''
    max_data_chunk_size = 0xfff0
    plain_data_len = len(_get_string_from_list(input_data_list))
        
    remaining_length = plain_data_len
    i = 0
    while remaining_length > 0:
        current_chunk = input_data_list[i]
        
        #Prepare arguments for decrypt update operation
        current_chunk_len = min(len(current_chunk), remaining_length)
        
        if current_chunk_len > max_data_chunk_size:
            raise Exception("chunk_sizes variable too large, the maximum size of a chunk is " + str(max_data_chunk_size))
        
        data_chunk = get_c_data_to_sign_or_encrypt(current_chunk)
        
        ret = C_VerifyUpdate(h_session, data_chunk, CK_ULONG(current_chunk_len))
        if ret != CKR_OK: return ret
        
        remaining_length -= current_chunk_len
        
        i += 1
    
    #Finalizing multipart decrypt operation
    out_data_len = CK_ULONG(len(signature))
    output = cast(get_c_data_to_sign_or_encrypt(signature), CK_BYTE_PTR)
    ret = C_VerifyFinal(h_session, output, out_data_len)
    
    return ret
    
def c_verify(h_session, h_key, verify_flavor, data_to_verify, signature, mech = None):
    '''
    Returns the result code of C_Verify which indicates whether or not the signature is
    valid.
    
    @param h_session: The current session
    @param h_key: The key handle to verify the signature against
    @param verify_flavor: The flavour of the mechanism to verify against
    @param data_to_verify: The data to verify, either a string or a list of strings. If this is a list
    a multipart operation will be used (using C_...Update and C_...Final)
    ex:
    - "This is a proper argument of some data to use in the function"
    - ["This is another format of data this", "function will accept.", "It will operate on these strings in parts"]
    @param signature: The signature of the data
    @param mech: The mechanism to use, if None is specified the mechanism will
    try to be automatically obtained
    
    @returns The result code
    '''

    #Get the mechanism
    if mech == None:
        mech = get_mechanism_for_sigver(verify_flavor)
    
    #Initialize the verify operation
    ret = C_VerifyInit(h_session, mech, CK_ULONG(h_key))
    if ret != CKR_OK: return ret
    
    #if a list is passed out do a verify operation on each string in the list, otherwise just do one verify operation
    is_multi_part_operation = isinstance(data_to_verify, list) or isinstance(data_to_verify, tuple)
    
    if is_multi_part_operation:
        ret = do_multipart_verify(h_session, data_to_verify, signature)
    else:
        #Prepare the data to verify
        c_data_to_verify = get_c_data_to_sign_or_encrypt(data_to_verify)
        plain_date_len = CK_ULONG(len(data_to_verify))
        
        c_signature = get_c_data_to_sign_or_encrypt(signature)
        
        #Actually verify the data
        ret = C_Verify(h_session, c_data_to_verify, plain_date_len, c_signature, CK_ULONG(len(signature)))
    
    return ret
    
c_verify_ex = make_error_handle_function(c_verify)
        
