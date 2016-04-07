"""
Methods used to generate keys.
"""

from ctypes import byref

from cryptoki import C_DestroyObject, CK_OBJECT_HANDLE, CK_ULONG, CK_MECHANISM, \
    CK_MECHANISM_TYPE, CK_VOID_PTR, C_GenerateKey, C_GenerateKeyPair, C_CopyObject
from default_templates import CKM_DES_KEY_GEN_TEMP, \
    CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP, CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP
from defines import CKM_DES_KEY_GEN, CKM_RSA_PKCS_KEY_PAIR_GEN
from pycryptoki.attributes import Attributes
from pycryptoki.cryptoki import C_DeriveKey
from pycryptoki.test_functions import make_error_handle_function


def c_destroy_object(h_session, h_object_value):
    """Deletes the object corresponsing to the passed in object handle

    :param h_session: Current session
    :param h_object_value: The handle of the object to delete
    :returns: The resutl code from the C_DestroyObject operation

    """
    ret = C_DestroyObject(h_session, CK_OBJECT_HANDLE(h_object_value))
    return ret


c_destroy_object_ex = make_error_handle_function(c_destroy_object)


def c_copy_object(h_session, h_object, template=None):
    """Method to call the C_CopyObject cryptoki command.

    :param h_session: Handle to the session
    :param h_object: Handle to the object to be cloned
    :param template: Template for the new object. Defaults to None
    :return: Handle to the new cloned object.

    """
    if template is None:
        template = {}
    attributes = Attributes(template)
    template_size = CK_ULONG(len(template))

    h_new_object = CK_OBJECT_HANDLE()

    ret = C_CopyObject(h_session, h_object, attributes.get_c_struct(), template_size, h_new_object)

    return ret, h_new_object.value


c_copy_object_ex = make_error_handle_function(c_copy_object)


def _get_mechanism(flavor):
    """Method used to get the CK_MECHANISM variable for key generation.

    :param flavor: The key flavor of the mechanism
    :returns: Returns a blank mechanism of type flavor

    """
    mech = CK_MECHANISM()
    mech.mechanism = CK_MECHANISM_TYPE(flavor)
    mech.pParameter = CK_VOID_PTR(0)
    mech.usParameterLen = CK_ULONG(0)
    return mech


def c_generate_key(h_session, flavor=CKM_DES_KEY_GEN, template=CKM_DES_KEY_GEN_TEMP):
    """
    Generates a symmetric key of a given flavor given the correct template.

    :param h_session: Current session
    :param flavor: The flavour of the DES key to generate
    :param template: The template to use to generate the key

    :return: Returns the result code and the key's handle
    """
    # INITALIZE VARIABLES
    mech = _get_mechanism(flavor)

    key_attributes = Attributes(template)
    us_public_template_size = CK_ULONG(len(template))

    # ACTUALLY GENERATE KEY
    h_key = CK_OBJECT_HANDLE()
    ret = C_GenerateKey(h_session,
                        byref(mech), key_attributes.get_c_struct(),
                        us_public_template_size, byref(h_key))

    return ret, h_key.value


c_generate_key_ex = make_error_handle_function(c_generate_key)


def c_generate_key_pair(h_session, flavor=CKM_RSA_PKCS_KEY_PAIR_GEN,
                        pbkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP,
                        prkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP,
                        mech=None):
    """Generates a private and public key pair for a given flavor, and given public and private
    key templates. The return value will be the handle for the key.

    :param h_session: Current session
    :param flavor: The flavor of the key to generate (Default value = CKM_DES_KEY_GEN)
    :param pbkey_template: The public key template to use for key generation
    :param prkey_template: The private key template to use for key generation
    :param mech: The mechanism to generate the key with
    :returns: Returns the result code, the public key's handle, and the private key's handle

    """
    # INITALIZE VARIABLES
    if mech is None:
        mech = _get_mechanism(flavor)

    pbkey_template_size = len(pbkey_template)
    pbkey_attributes = Attributes(pbkey_template)

    prkey_template_size = len(prkey_template)
    prkey_attributes = Attributes(prkey_template)

    h_pbkey = CK_OBJECT_HANDLE()
    h_prkey = CK_OBJECT_HANDLE()
    ret = C_GenerateKeyPair(h_session, byref(mech),
                            pbkey_attributes.get_c_struct(), pbkey_template_size,
                            prkey_attributes.get_c_struct(), prkey_template_size,
                            byref(h_pbkey), byref(h_prkey))

    return ret, h_pbkey.value, h_prkey.value


c_generate_key_pair_ex = make_error_handle_function(c_generate_key_pair)


def c_derive_key(h_session, h_base_key, template, mech_flavor, mech=None):
    """Calls C_DeriveKey

    :param h_session: The session handle to use
    :param h_base_key: The base key
    :param template: A python template of attributes (ex. CKM_DES_KEY_GEN_TEMP)
    :param mech: The mechanism to use, if None a default mechanism will be used
    :param mech_flavor:
    :returns: The result code, The derived key's handle

    """

    if mech is None:
        mech = _get_mechanism(mech_flavor)

    h_key = CK_OBJECT_HANDLE()
    c_template = Attributes(template).get_c_struct()
    ret = C_DeriveKey(h_session, mech,
                      CK_OBJECT_HANDLE(h_base_key),
                      c_template, CK_ULONG(len(template)),
                      byref(h_key))
    return ret, h_key.value


c_derive_key_ex = make_error_handle_function(c_derive_key)


def clear_keys(h_session):
    """Quick hacked together function that can be used to clear the first 10 000 keys.

    :param h_session: Current session

    """
    for i in range(1, 10000):
        c_destroy_object(h_session, i)
