"""
PKCS11 Operations related to Signing and Verifying data
"""
import logging
from _ctypes import POINTER
from ctypes import create_string_buffer, cast, byref, string_at, c_ubyte

from .attributes import to_char_array, to_byte_array
from .common_utils import refresh_c_arrays, AutoCArray
from .conversions import from_bytestring
from .cryptoki import CK_ULONG, \
    CK_BYTE_PTR, C_SignInit, C_Sign
from .cryptoki import C_VerifyInit, C_Verify, C_SignUpdate, \
    C_SignFinal, C_VerifyUpdate, C_VerifyFinal
from .defines import CKR_OK
from .encryption import MAX_BUFFER
from .exceptions import make_error_handle_function
from .lookup_dicts import ret_vals_dictionary
from .mechanism import parse_mechanism

LOG = logging.getLogger(__name__)


def c_sign(h_session, h_key, data_to_sign, mechanism, output_buffer=None):
    """Signs the given data with given key and mechanism.

    .. note:: If data is a list or tuple of strings, multi-part operations will be used.

    :param int h_session: Session handle
    :param data_to_sign: The data to sign, either a string or a list of strings. If this is a list
         a multipart operation will be used (using C_...Update and C_...Final)

         ex:

             - "This is a proper argument of some data to use in the function"
             - ["This is another format of data this", "function will accept.",
               "It will operate on these strings in parts"]

    :param int h_key: The signing key
    :param mechanism: See the :py:func:`~pycryptoki.mechanism.parse_mechanism` function
        for possible values.
    :param list|int output_buffer: Integer or list of integers that specify a size of output
        buffer to use for an operation. By default will query with NULL pointer buffer
        to get required size of buffer.
    :return: (retcode, python string of signed data)
    :rtype: tuple
    """

    mech = parse_mechanism(mechanism)

    # Initialize the sign operation
    ret = C_SignInit(h_session, byref(mech), CK_ULONG(h_key))
    if ret != CKR_OK:
        return ret, None

    # if a list is passed out do a sign operation on each string in the list,
    # otherwise just do one sign operation
    is_multi_part_operation = isinstance(data_to_sign, (list, tuple))

    if is_multi_part_operation:
        ret, signature_string = do_multipart_sign_or_digest(h_session,
                                                            C_SignUpdate,
                                                            C_SignFinal,
                                                            data_to_sign,
                                                            output_buffer=output_buffer)
    else:
        # Prepare the data to sign
        c_data_to_sign, plain_date_len = to_byte_array(from_bytestring(data_to_sign))
        c_data_to_sign = cast(c_data_to_sign, POINTER(c_ubyte))

        if output_buffer is not None:
            size = CK_ULONG(output_buffer)
            signed_data = AutoCArray(ctype=c_ubyte,
                                     size=size)
            ret = C_Sign(h_session,
                         c_data_to_sign, plain_date_len,
                         signed_data.array, signed_data.size)
        else:
            signed_data = AutoCArray(ctype=c_ubyte)

            @refresh_c_arrays(1)
            def _sign():
                """Perform the signing operation"""
                return C_Sign(h_session,
                              c_data_to_sign, plain_date_len,
                              signed_data.array, signed_data.size)

            ret = _sign()
        if ret != CKR_OK:
            return ret, None

        signature_string = string_at(signed_data.array, signed_data.size.contents.value)

    return ret, signature_string


c_sign_ex = make_error_handle_function(c_sign)


def do_multipart_sign_or_digest(h_session, c_update_function, c_final_function,
                                input_data_list, output_buffer=None):
    """
    Do a multipart sign or digest operation

    :param int h_session: Session handle
    :param func c_update_function: signing update function
    :param func c_final_function: signing finalization function
    :param iterable input_data_list: Iterable of data to sign.
    :param int output_buffer: Integer that specifies a size of an output bufffer to use
        for the Sign/Digeste operation. By default will query with NULL pointer buffer
        to get required size of buffer
    :return: The result code, A python string representing the signature
    """
    error = None

    for index, chunk in enumerate(input_data_list):
        data_chunk, data_chunk_len = to_byte_array(from_bytestring(chunk))
        data_chunk = cast(data_chunk, POINTER(c_ubyte))

        ret = c_update_function(h_session, data_chunk, data_chunk_len)
        if ret != CKR_OK:
            LOG.debug("%s call on chunk %.20s (%s/%s) Failed w/ ret %s (%s)",
                      c_update_function.__name__,
                      chunk, index + 1, len(input_data_list), ret_vals_dictionary[ret], ret)
            error = ret
            break

    # An Update function failed. We should still try to call C_**Final() though to ensure that the
    # operation is still finalized, but we'll return the original error code. 
    if error:
        ret = c_final_function(h_session,
                               cast(create_string_buffer(b'', MAX_BUFFER), CK_BYTE_PTR),
                               CK_ULONG(MAX_BUFFER))
        LOG.debug("%s call after a %s failure returned: %s (%s)",
                  c_final_function.__name__,
                  c_update_function.__name__, ret_vals_dictionary[ret], ret)
        return error, None

    if output_buffer is not None:
        size = CK_ULONG(output_buffer)
        out_data = AutoCArray(ctype=c_ubyte,
                              size=size)

        ret = c_final_function(h_session, out_data.array, out_data.size)

    else:
        out_data = AutoCArray(ctype=c_ubyte)

        @refresh_c_arrays(1)
        def _final():
            """
            Closure to acces AutoCArray properties correctly
            """
            return c_final_function(h_session, out_data.array, out_data.size)

        ret = _final()

    if ret != CKR_OK:
        return ret, None
    else:
        python_string = string_at(out_data.array, out_data.size.contents.value)
        return ret, python_string


def do_multipart_verify(h_session, input_data_list, signature):
    """
    Do a multipart verify operation

    :param int h_session: Session handle
    :param input_data_list: list of data to verify with
    :param signature: signature to verify
    :return: The result code
    """
    error = None
    for index, chunk in enumerate(input_data_list):

        data_chunk, data_chunk_len = to_byte_array(from_bytestring(chunk))
        data_chunk = cast(data_chunk, POINTER(c_ubyte))

        ret = C_VerifyUpdate(h_session, data_chunk, data_chunk_len)
        if ret != CKR_OK:
            error = ret
            break

    # An C_VerifyUpdate failed. We should still try to call C_**Final() though to ensure
    #  that the
    # operation is still finalized, but we'll return the original error code. 
    if error:
        ret = C_VerifyFinal(h_session,
                            cast(create_string_buffer(b"", MAX_BUFFER), CK_BYTE_PTR),
                            CK_ULONG(MAX_BUFFER))
        LOG.debug("C_VerifyFinal call after a C_VerifyUpdate failure returned:"
                  " %s (%s)", ret_vals_dictionary[ret], ret)
        return error, None

    # Finalizing multipart decrypt operation
    c_sig_data, c_sig_data_len = to_char_array(signature)
    output = cast(c_sig_data, CK_BYTE_PTR)
    ret = C_VerifyFinal(h_session, output, c_sig_data_len)
    return ret


def c_verify(h_session, h_key, data_to_verify, signature, mechanism):
    """Verifies data with the given signature, key and mechanism.

    .. note:: If data is a list or tuple of strings, multi-part operations will be used.

    :param int h_session: Session handle
    :param data_to_verify: The data to sign, either a string or a list of strings. If this is a list
                         a multipart operation will be used (using C_...Update and C_...Final)

                         ex:

                         - "This is a proper argument of some data to use in the function"
                         - ["This is another format of data this", "function will accept.",
                           "It will operate on these strings in parts"]
    :param bytes signature: Signature with which to verify the data.
    :param int h_key: The verifying key
    :param mechanism: See the :py:func:`~pycryptoki.mechanism.parse_mechanism` function
        for possible values.
    :return: retcode of verify operation
    """

    mech = parse_mechanism(mechanism)

    # Initialize the verify operation
    ret = C_VerifyInit(h_session, mech, CK_ULONG(h_key))
    if ret != CKR_OK:
        return ret

    # if a list is passed out do a verify operation on each string in the list,
    # otherwise just do one verify operation
    is_multi_part_operation = isinstance(data_to_verify, list) or isinstance(data_to_verify, tuple)

    if is_multi_part_operation:
        ret = do_multipart_verify(h_session, data_to_verify, signature)
    else:
        # Prepare the data to verify
        c_data_to_verify, plain_date_len = to_byte_array(from_bytestring(data_to_verify))
        c_data_to_verify = cast(c_data_to_verify, POINTER(c_ubyte))

        c_signature, c_sig_length = to_char_array(signature)
        c_signature = cast(c_signature, POINTER(c_ubyte))

        # Actually verify the data
        ret = C_Verify(h_session,
                       c_data_to_verify, plain_date_len,
                       c_signature, c_sig_length)

    return ret


c_verify_ex = make_error_handle_function(c_verify)
