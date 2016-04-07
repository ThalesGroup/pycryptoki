"""
Methods related to encrypting data/files.
"""
import logging
from _ctypes import POINTER
from ctypes import c_char, create_string_buffer, cast, c_void_p, byref, sizeof, pointer, \
    string_at, c_ubyte

from cryptoki import CK_MECHANISM, CK_MECHANISM_TYPE, CK_VOID_PTR, CK_ULONG, \
    C_EncryptInit, C_Encrypt, CK_RSA_PKCS_OAEP_PARAMS
from defines import CKM_DES_CBC, CKM_DES3_CBC, CKM_CAST3_CBC, CKM_DES_ECB, \
    CKM_DES3_ECB, CKM_CAST3_ECB, CKM_RC2_ECB, CKM_RC2_CBC, CKM_CAST5_ECB, \
    CKM_CAST5_CBC, CKM_RC4, CKM_RC5_ECB, CKM_RC5_CBC, CKM_RSA_X_509, CKM_DES_CBC_PAD, \
    CKM_DES3_CBC_PAD, CKM_DES3_CBC_PAD_IPSEC, CKM_RC2_CBC_PAD, CKM_RC5_CBC_PAD, \
    CKM_CAST3_CBC_PAD, CKM_CAST5_CBC_PAD, CKM_SEED_ECB, CKM_SEED_CBC, \
    CKM_SEED_CBC_PAD, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, \
    CKM_AES_CBC_PAD_IPSEC, CKM_ARIA_ECB, CKM_ARIA_CBC, CKM_ARIA_CBC_PAD, \
    CKM_RSA_PKCS, CKM_DES_CFB8, CKM_DES_CFB64, CKM_DES_OFB64, CKM_AES_CFB8, \
    CKM_AES_CFB128, CKM_AES_OFB, CKM_ARIA_CFB8, CKM_ARIA_CFB128, CKM_ARIA_OFB, \
    CKM_AES_GCM, CKM_XOR_BASE_AND_DATA_W_KDF, CKM_RSA_PKCS_OAEP, CKM_ECIES, CKR_OK, \
    CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, CKM_AES_KW, CKM_AES_KWP
from pycryptoki.attributes import Attributes, to_byte_array, to_char_array
from pycryptoki.common_utils import AutoCArray, refresh_c_arrays
from pycryptoki.cryptoki import C_Decrypt, C_DecryptInit, CK_OBJECT_HANDLE, \
    C_WrapKey, C_UnwrapKey, C_EncryptUpdate, C_EncryptFinal, CK_BYTE_PTR, \
    C_DecryptUpdate, C_DecryptFinal
from pycryptoki.test_functions import make_error_handle_function

LOG = logging.getLogger(__name__)


def get_encryption_mechanism(encryption_flavor, external_iv=None):
    """Returns the CK_MECHANISM() object associated with a given encryption flavor
    #TODO: Only works with one kind of encryption mechanism currently.

    :param encryption_flavor: The flavor of the encryption that the mechanism needs
    to encrypt for.
    :returns: Returns a CTypes CK_Mechanism given the encryption flavour that you have passed in

    """
    mech = CK_MECHANISM()
    mech.mechanism = CK_MECHANISM_TYPE(encryption_flavor)
    mech.pParameter = 0
    mech.usParameterLen = CK_ULONG(0)

    iv_required = 1
    RC2_params_required = 2
    RC2CBC_params_required = 3
    RC5_params_required = 4
    RC5CBC_params_required = 5
    IV16_required = 6
    GCM_params_required = 7
    xorkdf_params_required = 8
    OAEP_params_required = 9
    ECIES_params_required = 10

    encryption_flavors = {CKM_DES_CBC: iv_required,
                          CKM_DES3_CBC: iv_required,
                          CKM_CAST3_CBC: iv_required,
                          CKM_DES_ECB: 0,
                          CKM_DES3_ECB: 0,
                          CKM_CAST3_ECB: 0,
                          CKM_RC2_ECB: RC2_params_required,
                          CKM_RC2_CBC: RC2CBC_params_required,
                          CKM_CAST5_ECB: 0,
                          CKM_CAST5_CBC: iv_required,
                          CKM_RC4: 0,
                          CKM_RC5_ECB: RC5_params_required,
                          CKM_RC5_CBC: RC5CBC_params_required,
                          CKM_RSA_X_509: 0,
                          CKM_DES_CBC_PAD: iv_required,
                          CKM_DES3_CBC_PAD: iv_required,
                          CKM_DES3_CBC_PAD_IPSEC: iv_required,
                          CKM_RC2_CBC_PAD: RC2CBC_params_required,
                          CKM_RC5_CBC_PAD: RC5CBC_params_required,
                          CKM_CAST3_CBC_PAD: iv_required,
                          CKM_CAST5_CBC_PAD: iv_required,
                          CKM_SEED_ECB: 0,
                          CKM_SEED_CBC: IV16_required,
                          CKM_SEED_CBC_PAD: IV16_required,
                          CKM_AES_ECB: 0,
                          CKM_AES_KW: iv_required,
                          CKM_AES_KWP: iv_required,
                          CKM_AES_CBC: IV16_required,
                          CKM_AES_CBC_PAD: IV16_required,
                          CKM_AES_CBC_PAD_IPSEC: IV16_required,
                          CKM_ARIA_ECB: IV16_required,
                          CKM_ARIA_CBC: IV16_required,
                          CKM_ARIA_CBC_PAD: IV16_required,
                          CKM_RSA_PKCS: 0,
                          CKM_DES_CFB8: iv_required,
                          CKM_DES_CFB64: iv_required,
                          CKM_DES_OFB64: iv_required,
                          CKM_AES_CFB8: iv_required,
                          CKM_AES_CFB128: iv_required,
                          CKM_AES_OFB: iv_required,
                          CKM_ARIA_CFB8: iv_required,
                          CKM_ARIA_CFB128: iv_required,
                          CKM_ARIA_OFB: iv_required,
                          CKM_AES_GCM: GCM_params_required,
                          CKM_XOR_BASE_AND_DATA_W_KDF: xorkdf_params_required,
                          CKM_RSA_PKCS_OAEP: OAEP_params_required,
                          CKM_ECIES: ECIES_params_required}

    if external_iv:
        iv = external_iv
        iv16 = external_iv
    else:
        LOG.warning("Using static IVs can be insecure! ")
        iv = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
        iv16 = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]

    params = encryption_flavors.get(encryption_flavor)
    if params == iv_required:
        iv_ba, iv_len = to_byte_array(iv)
        mech.pParameter = iv_ba
        mech.usParameterLen = iv_len
    elif params == RC2_params_required:
        num_of_effective_bits = 0
        rc2_params = (c_char * 2)()
        rc2_params[0] = c_char(int(num_of_effective_bits, 8) & 0xff)
        rc2_params[1] = c_char(int((num_of_effective_bits >> 8), 8) & 0xff)
        rc2_params = create_string_buffer("", 2)
        mech.pParameter = cast(rc2_params, c_void_p)
        mech.usParameterLen = CK_ULONG(len(rc2_params))
    elif params == RC2CBC_params_required:
        num_of_effective_bits = 0
    elif params == RC5_params_required:
        num_rounds = 0
    elif params == RC5CBC_params_required:
        num_rounds = 0
    elif params == IV16_required:
        iv_ba, iv_len = to_byte_array(iv16)
        mech.pParameter = iv_ba
        mech.usParameterLen = iv_len
    elif params == GCM_params_required:
        pass
    elif params == xorkdf_params_required:
        pass
    elif params == OAEP_params_required:
        oaep_params = CK_RSA_PKCS_OAEP_PARAMS()
        oaep_params.hashAlg = CK_ULONG(CKM_SHA_1)
        oaep_params.mgf = CK_ULONG(CKG_MGF1_SHA1)
        oaep_params.source = CK_ULONG(CKZ_DATA_SPECIFIED)
        oaep_params.pSourceData = 0
        oaep_params.ulSourceDataLen = 0

        mech.pParameter = cast(pointer(oaep_params), CK_VOID_PTR)
        mech.usParameterLen = CK_ULONG(sizeof(oaep_params))
    elif params == ECIES_params_required:
        pass

    return mech


def c_encrypt(h_session, encryption_flavor, h_key, data_to_encrypt, mech=None, external_iv=None):
    """Encrypts data with a given key and encryption flavor
    encryption flavors

    :param h_session: Current session
    :param encryption_flavor: The flavor of encryption to use
    :param h_key: The key handle to encrypt the data with
    :param data_to_encrypt: The data to encrypt, either a string or a list of strings. If this is
    a list
        a multipart operation will be used
    :param mech: The mechanism to use, if None will try to look up a
        default mechanism based on the encryption flavor
    :param external_iv: The new Integrity Value to be used.
    :returns: Returns the result code of the operation, a python string representing the
    encrypted data

    """
    if mech is None:
        mech = get_encryption_mechanism(encryption_flavor, external_iv)

    # if a list is passed out do an encrypt operation on each string in the list, otherwise just
    # do one encrypt operation
    is_multi_part_operation = isinstance(data_to_encrypt, (list, tuple))

    # Initialize encryption
    ret = C_EncryptInit(h_session, byref(mech), CK_ULONG(h_key))
    if ret != CKR_OK:
        return ret, None

    if is_multi_part_operation:
        ret, encrypted_python_string = do_multipart_operation(h_session, C_EncryptUpdate,
                                                              C_EncryptFinal, data_to_encrypt)
    else:
        plain_data, plain_data_length = to_char_array(data_to_encrypt)
        plain_data = cast(plain_data, POINTER(c_ubyte))

        enc_data = AutoCArray(ctype=c_ubyte)

        @refresh_c_arrays(1)
        def _encrypt():
            return C_Encrypt(h_session,
                             plain_data, plain_data_length,
                             enc_data.array, enc_data.size)

        ret = _encrypt()
        if ret != CKR_OK:
            return ret, None

        # Convert encrypted data into a python string
        encrypted_python_string = string_at(enc_data.array, len(enc_data))

    return ret, encrypted_python_string


c_encrypt_ex = make_error_handle_function(c_encrypt)


def _split_string_into_list(python_string, block_size):
    """Splits a string into a list of equal size chunks

    :param python_string: The string to divide
    :param block_size: The size of the blocks to divide the string into
    :returns: A list of strings of block_size

    """
    return_list = []
    total_length = len(python_string)
    for index in range(0, (total_length / block_size)):
        start_index = index * block_size
        end_index = min(start_index + block_size, total_length)
        return_list.append(python_string[start_index: end_index])

    return return_list


def _get_string_from_list(list_of_strings):
    """Takes a list of strings and returns a single concatenated string.

    :param list_of_strings: A list of strings to be concatenated
    :returns: Single string representing the concatenated list

    """
    large_string = ''
    for substring in list_of_strings:
        large_string += substring

    return large_string


def c_decrypt(h_session, decryption_flavor, h_key, encrypted_data, mech=None, external_iv=None):
    """Decrypts some data

    :param h_session: The session to use
    :param decryption_flavor: The decryption flavor to create a new mechanism with if no mechanism
        is provided
    :param h_key: The handle of the key to use to decrypt
    :param mech: The mechanism, if none is provided a blank one will be
        provided based on the decryption_flavor (Default value = None)
    :param encrypted_data:
    :returns: The result code, a python string of the decrypted data

    """

    # Get the mechanism
    if mech is None:
        mech = get_encryption_mechanism(decryption_flavor, external_iv)

    # Initialize Decrypt
    ret = C_DecryptInit(h_session, mech, CK_ULONG(h_key))
    if ret != CKR_OK:
        return ret, None

    # if a list is passed out do a decrypt operation on each string in the list, otherwise just
    # do one decrypt operation
    is_multi_part_operation = isinstance(encrypted_data, (list, tuple))

    if is_multi_part_operation:
        ret, python_string = do_multipart_operation(h_session, C_DecryptUpdate, C_DecryptFinal,
                                                    encrypted_data)
    else:

        # Get the length of the final data
        # NOTE: The "Conventions for functions returning output in a variable-length buffer"
        # section of the PKCS#11 spec says that the length returned in this
        # case (no output buffer given to C_Decrypt) can exceed the precise
        # number of bytes needed. So the python string that's returned in the
        # end needs to be adjusted based on the second called to C_Decrypt
        # which will have the right length
        c_enc_data, c_enc_data_len = to_char_array(encrypted_data)
        c_enc_data = cast(c_enc_data, POINTER(c_ubyte))

        decrypted_data = AutoCArray(ctype=c_ubyte)

        @refresh_c_arrays(1)
        def _decrypt():
            """ Perform the decryption ops"""
            return C_Decrypt(h_session,
                             c_enc_data, c_enc_data_len,
                             decrypted_data.array, decrypted_data.size)

        ret = _decrypt()
        if ret != CKR_OK:
            return ret, None

        # Convert the decrypted data to a python readable format
        python_string = string_at(decrypted_data.array, len(decrypted_data))

    return ret, python_string


c_decrypt_ex = make_error_handle_function(c_decrypt)


def do_multipart_operation(h_session, c_update_function, c_finalize_function, input_data_list):
    """Some code which will do a multipart encrypt or decrypt since they are the same
    with just different functions called

    :param h_session:
    :param c_update_function:
    :param c_finalize_function:
    :param input_data_list:

    """
    max_data_chunk_size = 0xfff0
    plain_data_len = len(_get_string_from_list(input_data_list))

    remaining_length = plain_data_len
    python_string = ''
    i = 0
    while remaining_length > 0:
        current_chunk = input_data_list[i]

        # Prepare arguments for decrypt update operation
        current_chunk_len = min(len(current_chunk), remaining_length)

        if current_chunk_len > max_data_chunk_size:
            raise Exception(
                "chunk_sizes variable too large, the maximum size of a chunk is " + str(
                    max_data_chunk_size))

        out_data = create_string_buffer('', max_data_chunk_size)
        out_data_len = CK_ULONG(max_data_chunk_size)
        data_chunk, data_chunk_len = to_char_array(data_chunk)

        ret = c_update_function(h_session, data_chunk, data_chunk_len,
                                cast(out_data, CK_BYTE_PTR),
                                byref(out_data_len))
        if ret != CKR_OK:
            return ret, None

        remaining_length -= current_chunk_len

        # Get the output
        ck_char_array = out_data._objects.values()[0]
        python_string += string_at(ck_char_array, len(ck_char_array))[0:out_data_len.value]
        i += 1

    # Finalizing multipart decrypt operation
    out_data_len = CK_ULONG(max_data_chunk_size)
    output = cast(create_string_buffer("", out_data_len.value), CK_BYTE_PTR)
    ret = c_finalize_function(h_session, output, byref(out_data_len))
    if ret != CKR_OK:
        return ret, None
    # Get output
    ck_char_array = output._objects.values()[0]
    if out_data_len.value > 0:
        python_string += string_at(ck_char_array, len(ck_char_array))[0:out_data_len.value]

    return ret, python_string


def c_wrap_key(h_session, h_wrapping_key, h_key, encryption_flavor, mech=None, external_iv=None):
    """Function which wraps a key

    :param h_session: The session to use
    :param h_wrapping_key: The handle of the key to use to wrap another key
    :param h_key: The key to wrap
    :param encryption_flavor: The encryption flavor to create a new mechanism with if no mechanism
        is provided
    :param mech: The mechanism, if none is provided a blank one will be provided
        based on the encryption flavor (Default value = None)
    :returns: The result code, a ctypes byte array representing the new key

    """
    if mech is None:
        mech = get_encryption_mechanism(encryption_flavor, external_iv)

    wrapped_key = AutoCArray(ctype=c_ubyte)

    @refresh_c_arrays(1)
    def _wrap():
        """  Perform the Wrapping operation"""
        return C_WrapKey(h_session, mech,
                         CK_OBJECT_HANDLE(h_wrapping_key), CK_OBJECT_HANDLE(h_key),
                         wrapped_key.array, wrapped_key.size)

    ret = _wrap()
    if ret != CKR_OK:
        return ret, None

    return ret, string_at(wrapped_key.array, len(wrapped_key))


c_wrap_key_ex = make_error_handle_function(c_wrap_key)


def c_unwrap_key(h_session, h_unwrapping_key, wrapped_key, key_template, encryption_flavor,
                 mech=None, external_iv=None):
    """Function which unwraps a key

    :param h_session: The session to use
    :param h_unwrapping_key: The wrapping key handle
    :param wrapped_key: The wrapped key in a ctypes CK_CHAR_PTR array
    :param key_template: The python template representing the new key's template
    :param encryption_flavor: If the mechanism is not specified it will create a
        default one based on the encryption flavor
    :param mech: The mechanism to use, if null a default one will be created based on the
    encryption_flavor
    :param h_unwrapping_key:
    :param wrapped_key:
    :returns: The result code, the handle of the unwrapped key

    """
    if mech is None:
        mech = get_encryption_mechanism(encryption_flavor, external_iv)

    c_template = Attributes(key_template).get_c_struct()
    byte_wrapped_key = cast(wrapped_key, CK_BYTE_PTR)
    h_output_key = CK_ULONG()
    ret = C_UnwrapKey(h_session, mech, CK_OBJECT_HANDLE(h_unwrapping_key), byte_wrapped_key,
                      CK_ULONG(len(wrapped_key)),
                      c_template, CK_ULONG(len(key_template)), byref(h_output_key))

    return ret, h_output_key.value


c_unwrap_key_ex = make_error_handle_function(c_unwrap_key)
