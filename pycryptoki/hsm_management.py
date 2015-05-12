"""
Methods responsible for pycryptoki 'hsm management' set of commands.
"""
from ctypes import byref, create_string_buffer, cast
from pycryptoki.cryptoki import CK_SLOT_ID, CK_USER_TYPE, \
    C_PerformSelfTest, CA_SetTokenCertificateSignature, CA_HAInit, \
    CA_CreateLoginChallenge, CA_InitializeRemotePEDVector, \
    CA_DeleteRemotePEDVector, CA_MTKRestore, CA_MTKResplit, CA_MTKZeroize, CK_ULONG, CK_BYTE_PTR, CK_BYTE, CK_CHAR_PTR, CK_CHAR
from pycryptoki.attributes import Attributes
from pycryptoki.test_functions import make_error_handle_function


def c_performselftest(slot,
                      test_type,
                      input_data,
                      input_data_len):
    '''
    Test: Performs a self test for specified test type on a given slot.

    @param slot: slot number
    @param test_type: type of test CK_ULONG
    @param input_data: pointer to input data CK_BYTE_PTR
    @param input_length: input data length CK_ULONG
    @param output_data: pointer to output data CK_BYTE_PTR
    @param output_length: output data length CK_ULONG_PTR
    @return: the result code

        [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
    '''

    test_type = CK_ULONG(test_type)
    input_length = CK_ULONG(input_data_len)
    input_data = (CK_BYTE * input_data)()
    output_data = cast(create_string_buffer('', input_data_len), CK_BYTE_PTR)
    output_data_len = CK_ULONG()

    ret = C_PerformSelfTest(slot,
                            test_type,
                            input_data,
                            input_length,
                            output_data,
                            byref(output_data_len))
    return ret, output_data
c_performselftest_ex = make_error_handle_function(c_performselftest)


def ca_settokencertificatesignature(h_session,
                                    access_level,
                                    customer_id,
                                    pub_template,
                                    signature,
                                    signature_len):
    '''
    Completes the installation of a certificate on a token.
    The caller must supply a public key and a signature for token certificate.
    The public key is provided through the template; it must contain a key
    type, a modulus and a public exponent.

    @param h_session: the current session
    @param access_level: the access level
    @param customer_id: the customer ID
    @param pub_template: the public template
    @param pub_template_length: the public template length
    @param signature: the signature
    @param signature_length: the length in bytes of the signature
    @return: the result code
    '''

    access_level = CK_ULONG(access_level)
    customer_id = CK_ULONG(customer_id)

    key_attributes = Attributes(pub_template)
    pub_template_len = CK_ULONG(len(pub_template))
    signature = (CK_BYTE * signature)()
    signature_length = CK_ULONG(signature_len)
    ret = CA_SetTokenCertificateSignature(h_session,
                                          access_level,
                                          customer_id,
                                          key_attributes.get_c_struct(),
                                          pub_template_len,
                                          signature,
                                          signature_length)
    return ret
ca_settokencertificatesignature_ex = \
    make_error_handle_function(ca_settokencertificatesignature)


def ca_hainit(h_session, h_key):
    '''
    Creates a login key pair on the primary token.

    @param h_session: the current session
    @param h_key: the login private key
    @return: the result code
    '''
    ret = CA_HAInit(h_session, h_key)

    return ret
ca_hainit_ex = make_error_handle_function(ca_hainit)


def ca_createloginchallenge(h_session,
                            user_type,
                            challenge):
    '''
    Creates a login challenge for the given user.

    @param h_session: the current session
    @param user_type: user type
    @param challenge_length: challenge length
    @param challenge: challenge
    @param output_data_length: PIN length
    @param output_data: PIN itself
    @return: the result code
    '''

    challenge_length = CK_ULONG(len(challenge))
    challenge = cast(create_string_buffer(challenge), CK_CHAR_PTR)
    output_data_length = CK_ULONG()
    output_data = (CK_CHAR)()
    ret = CA_CreateLoginChallenge(h_session,
                                  CK_USER_TYPE(user_type),
                                  challenge_length,
                                  challenge,
                                  output_data_length,
                                  output_data)
    return ret, output_data
ca_createloginchallenge_ex = \
    make_error_handle_function(ca_createloginchallenge)


def ca_initializeremotepedvector(h_session):
    '''
    Initializes a remote PED vector

    @param h_session: the current session
    @return: the result code
    '''
    ret = CA_InitializeRemotePEDVector(h_session)
    return ret
ca_initializeremotepedvector_ex = \
    make_error_handle_function(ca_initializeremotepedvector)


def ca_deleteremotepedvector(h_session):
    '''
    Deletes a remote PED vector

    @param h_session: the current session
    @return: the result code
    '''
    ret = CA_DeleteRemotePEDVector(h_session)
    return ret
ca_deleteremotepedvector_ex = \
    make_error_handle_function(ca_deleteremotepedvector)


def ca_mtkrestore(slot):
    '''
    Restore the MTK

    @param slot: slot number
    @return: the result code
    '''
    ret = CA_MTKRestore(CK_SLOT_ID(slot))
    return ret
ca_mtkrestore_ex = make_error_handle_function(ca_mtkrestore)


def ca_mtkresplit(slot):
    '''
    Resplit the MTK

    @param slot: slot number
    @return: the result code
    '''
    ret = CA_MTKResplit(CK_SLOT_ID(slot))
    return ret
ca_mtkresplit_ex = make_error_handle_function(ca_mtkresplit)


def ca_mtkzeroize(slot):
    '''
    Zeroize the MTK

    @param slot: slot number
    @return: the result code
    '''
    ret = CA_MTKZeroize(CK_SLOT_ID(slot))
    return ret
ca_mtkzeroize_ex = make_error_handle_function(ca_mtkzeroize)

