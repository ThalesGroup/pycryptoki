from ctypes import create_string_buffer, cast, byref
from pycryptoki.attributes import convert_ck_char_array_to_string, \
    convert_string_to_CK_CHAR, Attributes
from pycryptoki.cryptoki import C_GenerateRandom, CK_BYTE_PTR, CK_ULONG, \
    C_SeedRandom, C_DigestInit, C_DigestUpdate, C_DigestFinal, C_Digest, C_CreateObject, \
    CA_SetPedId, CK_SLOT_ID, CA_GetPedId, C_DigestKey
from pycryptoki.defines import CKR_OK
from pycryptoki.encryption import get_c_data_to_sign_or_encrypt
from pycryptoki.key_generator import _get_mechanism
from pycryptoki.sign_verify import do_multipart_sign_or_digest
from pycryptoki.test_functions import make_error_handle_function

def c_generate_random(h_session, length):
    '''
    Generates a sequence of random numbers
    
    @param h_session: The current session
    @param length: The length in bytes of the random number sequence
    
    @return: The result code, A string of random data
    '''
    random_data = cast(create_string_buffer("", length), CK_BYTE_PTR)
    ret = C_GenerateRandom(h_session, random_data, CK_ULONG(length))
    
    random_string = convert_ck_char_array_to_string(random_data._objects.values()[0])
    return ret, random_string
c_generate_random_ex = make_error_handle_function(c_generate_random)

def c_seed_random(h_session, seed):
    '''
    Seeds the random number generator
    
    @param h_session: The current session
    @param seed: A python string of some seed
    
    @return: The result code
    '''
    seed_bytes = cast(convert_string_to_CK_CHAR(seed), CK_BYTE_PTR)
    seed_length = CK_ULONG(len(seed))
    ret = C_SeedRandom(h_session, seed_bytes, seed_length)
    return ret;
c_seed_random_ex = make_error_handle_function(c_seed_random)

def c_digest(h_session, data_to_digest, digest_flavor, mech = None):
    '''
    Digests some data
    
    @param h_session: Current session
    @param data_to_digest: The data to digest, either a string or a list of strings. If this is a list
    a multipart operation will be used (using C_...Update and C_...Final)
    ex:
    - "This is a proper argument of some data to use in the function"
    - ["This is another format of data this", "function will accept.", "It will operate on these strings in parts"]
    @param digest_flavor: The flavour of the mechanism to digest (MD2, SHA-1, HAS-160, 
    SHA224, SHA256, SHA384, SHA512)
    @param mech: The mechanism to be used. If None a blank one with the digest_flavour will be used
    
    @return: The result code, a python string of the digested data
    '''

    #Get mechanism if none provided
    if mech == None:
        mech = _get_mechanism(digest_flavor)

    #Initialize Digestion
    ret = C_DigestInit(h_session, mech)
    if ret != CKR_OK: return ret

    #if a list is passed out do an digest operation on each string in the list, otherwise just do one digest operation
    is_multi_part_operation = isinstance(data_to_digest, list) or isinstance(data_to_digest, tuple)
    
    if is_multi_part_operation:
        ret, digested_python_string = do_multipart_sign_or_digest(h_session, C_DigestUpdate, C_DigestFinal, data_to_digest)
    else:
        #Get arguments
        digest_data_length = len(data_to_digest)
        c_data_to_digest = get_c_data_to_sign_or_encrypt(data_to_digest)
    
        #Get the length of the digested data
        digest_length = CK_ULONG()
        ret = C_Digest(h_session, c_data_to_digest, CK_ULONG(digest_data_length), None, byref(digest_length))
        if ret != CKR_OK: return ret, None
    
        output = create_string_buffer("", digest_length.value)
        digested_data = cast(output, CK_BYTE_PTR)
        
        #Digest data
        ret = C_Digest(h_session, c_data_to_digest, CK_ULONG(digest_data_length), digested_data, byref(digest_length))
        
        #Convert Digested data into a python string
        ck_char_array = digested_data._objects.values()[0]
        digested_python_string = convert_ck_char_array_to_string(ck_char_array)
    
    return ret, digested_python_string
c_digest_ex = make_error_handle_function(c_digest)

def c_digestkey(h_session, h_key, digest_flavor, mech = None):
#Get mechanism if none provided
    if mech == None:
        mech = _get_mechanism(digest_flavor)

    #Initialize Digestion
    ret = C_DigestInit(h_session, mech)
    if ret != CKR_OK: return ret

    ret = C_DigestKey(h_session, h_key)

    return ret
c_digestkey_ex = make_error_handle_function(c_digestkey)



def c_create_object(h_session, template):
    '''
    Creates an object based on a given python template
    
    @param h_session: The session handle to use
    @param template: The python template which the object will be based on
    
    @return: The result code, the handle of the object
    '''
    c_template = Attributes(template).get_c_struct()
    new_object_handle = CK_ULONG()
    ret = C_CreateObject(h_session, c_template, CK_ULONG(len(template)), byref(new_object_handle))
    
    return ret, new_object_handle.value
c_create_object_ex = make_error_handle_function(c_create_object)

def c_set_ped_id(slot, id):
    '''
    Set the PED ID for the given slot.
    @param slot     : slot number
    @parm  id       : PED ID to use
    
    @return: The result code
    '''
    ret = CA_SetPedId(CK_SLOT_ID(slot), CK_ULONG(id))
    return ret;
c_set_ped_id_ex = make_error_handle_function(c_set_ped_id)

def c_get_ped_id(slot):
    '''
    Get the PED ID for the given slot.
    @param slot     : slot number
    
    @return: The result code and ID
    '''
    pedId = CK_ULONG()
    ret = CA_GetPedId(CK_SLOT_ID(slot), byref(pedId))
    return ret, pedId.value
c_get_ped_id_ex = make_error_handle_function(c_get_ped_id)
