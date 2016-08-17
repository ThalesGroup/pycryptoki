"""
Methods related to encrypting data/files.
"""
import logging
from _ctypes import POINTER
from ctypes import create_string_buffer, cast, byref, string_at, c_ubyte

from .attributes import Attributes, to_char_array
from .common_utils import AutoCArray, refresh_c_arrays
from .cryptoki import CK_ULONG, \
    C_EncryptInit, C_Encrypt
from .cryptoki import C_Decrypt, C_DecryptInit, CK_OBJECT_HANDLE, \
    C_WrapKey, C_UnwrapKey, C_EncryptUpdate, C_EncryptFinal, CK_BYTE_PTR, \
    C_DecryptUpdate, C_DecryptFinal
from .defines import CKR_OK
from .mechanism import parse_mechanism
from .return_values import ret_vals_dictionary
from .test_functions import make_error_handle_function

LOG = logging.getLogger(__name__)


def c_encrypt(h_session, h_key, data, mechanism):
    """Encrypts data with a given key and encryption flavor
    encryption flavors

    :param h_session: Current session
    :param h_key: The key handle to encrypt the data with
    :param data: The data to encrypt, either a string or a list of strings. If this is
    a list a multipart operation will be used
    :param mechanism: Will create a mechanism with the :py:func:`mechanism.parse_mechanism` function
    :returns: Returns the result code of the operation, a python string representing the
    encrypted data
    """
    mech = parse_mechanism(mechanism)
    # if a list is passed out do an encrypt operation on each string in the list, otherwise just
    # do one encrypt operation
    is_multi_part_operation = isinstance(data, (list, tuple))

    # Initialize encryption
    ret = C_EncryptInit(h_session, byref(mech), CK_ULONG(h_key))
    if ret != CKR_OK:
        return ret, None

    if is_multi_part_operation:
        ret, encrypted_python_string = do_multipart_operation(h_session, C_EncryptUpdate,
                                                              C_EncryptFinal, data)
    else:
        plain_data, plain_data_length = to_char_array(data)
        plain_data = cast(plain_data, POINTER(c_ubyte))

        enc_data = AutoCArray(ctype=c_ubyte)

        @refresh_c_arrays(1)
        def _encrypt():
            """Closure for getting the buffer size with encrypt."""
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
    total_length = len(python_string)
    return [python_string[x:x + block_size] for x in range(0, total_length, block_size)]


def _get_string_from_list(list_of_strings):
    """Takes a list of strings and returns a single concatenated string.

    :param list_of_strings: A list of strings to be concatenated
    :returns: Single string representing the concatenated list

    """
    return b"".join(list_of_strings)


def c_decrypt(h_session, h_key, encrypted_data, mechanism):
    """Decrypts some data

    :param h_session: The session to use
    :param h_key: The handle of the key to use to decrypt
    :param encrypted_data: Data to be decrypted
    :param mechanism: Will create a mechanism with the :py:func:`mechanism.parse_mechanism` function
    :returns: The result code, a python string of the decrypted data

    """
    mech = parse_mechanism(mechanism)
    # Initialize Decrypt
    ret = C_DecryptInit(h_session, mech, CK_ULONG(h_key))
    if ret != CKR_OK:
        return ret, None

    # if a list is passed out do a decrypt operation on each string in the list, otherwise just
    # do one decrypt operation
    is_multi_part_operation = isinstance(encrypted_data, (list, tuple))

    if is_multi_part_operation:
        ret, python_data = do_multipart_operation(h_session, C_DecryptUpdate, C_DecryptFinal,
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
        python_data = string_at(decrypted_data.array, len(decrypted_data))

    return ret, python_data


c_decrypt_ex = make_error_handle_function(c_decrypt)


def do_multipart_operation(h_session, c_update_function, c_finalize_function, input_data_list):
    """Some code which will do a multipart encrypt or decrypt since they are the same
    with just different functions called

    :param h_session: Session handle.
    :param c_update_function: C_<NAME>Update function to call to update each operation.
    :param c_finalize_function: Function to call at end of multipart operation.
    :param input_data_list: List of data to call update function on.
    """
    max_data_chunk_size = 0xfff0
    plain_data_len = len(b"".join(input_data_list))

    remaining_length = plain_data_len
    python_data = []
    i = 0
    while remaining_length > 0:
        current_chunk = input_data_list[i]

        # Prepare arguments for decrypt update operation
        current_chunk_len = min(len(current_chunk), remaining_length)

        if current_chunk_len > max_data_chunk_size:
            raise ValueError("chunk_sizes variable too large,"
                             " the maximum size of a chunk is %s" % max_data_chunk_size)

        out_data = create_string_buffer(b'', max_data_chunk_size)
        out_data_len = CK_ULONG(max_data_chunk_size)
        data_chunk, data_chunk_len = to_char_array(current_chunk)
        data_chunk = cast(data_chunk, POINTER(c_ubyte))

        ret = c_update_function(h_session,
                                data_chunk, data_chunk_len,
                                cast(out_data, CK_BYTE_PTR), byref(out_data_len))
        if ret != CKR_OK:
            LOG.debug("Failed C_Update operation on chunk %.20s (%s/%s) - ret %s",
                      current_chunk, i, len(input_data_list), ret_vals_dictionary[ret])
            return ret, None

        remaining_length -= current_chunk_len

        # Get the output
        python_data.append(string_at(out_data, out_data_len.value))
        i += 1

    # Finalizing multipart decrypt operation
    fin_out_data_len = CK_ULONG(max_data_chunk_size)
    fin_out_data = create_string_buffer(b"", fin_out_data_len.value)
    output = cast(fin_out_data, CK_BYTE_PTR)
    ret = c_finalize_function(h_session, output, byref(fin_out_data_len))
    if ret != CKR_OK:
        return ret, None

    if fin_out_data_len.value > 0:
        python_data.append(string_at(fin_out_data, fin_out_data_len.value))

    return ret, b"".join(python_data)


def c_wrap_key(h_session, h_wrapping_key, h_key, mechanism):
    """Function which wraps a key

    :param h_session: The session to use
    :param h_wrapping_key: The handle of the key to use to wrap another key
    :param h_key: The key to wrap
        based on the encryption flavor (Default value = None)
    :param mechanism: Will create a mechanism with the :py:func:`mechanism.parse_mechanism` function
    :returns: The result code, a ctypes byte array representing the new key

    """
    mech = parse_mechanism(mechanism)

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


def c_unwrap_key(h_session, h_unwrapping_key, wrapped_key, key_template, mechanism):
    """Function which unwraps a key

    :param h_session: The session to use
    :param h_unwrapping_key: The wrapping key handle
    :param wrapped_key: The wrapped key in a ctypes CK_CHAR_PTR array
    :param key_template: The python template representing the new key's template
    :param mechanism: Will create a mechanism with the :py:func:`mechanism.parse_mechanism` function
    :returns: The result code, the handle of the unwrapped key

    """
    mech = parse_mechanism(mechanism)
    c_template = Attributes(key_template).get_c_struct()
    byte_wrapped_key = cast(wrapped_key, CK_BYTE_PTR)
    h_output_key = CK_ULONG()
    ret = C_UnwrapKey(h_session, mech, CK_OBJECT_HANDLE(h_unwrapping_key), byte_wrapped_key,
                      CK_ULONG(len(wrapped_key)),
                      c_template, CK_ULONG(len(key_template)), byref(h_output_key))

    return ret, h_output_key.value


c_unwrap_key_ex = make_error_handle_function(c_unwrap_key)
