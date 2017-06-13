"""
Methods used to generate keys.
"""
from ctypes import byref

from .attributes import Attributes
from .cryptoki import C_DeriveKey
from .cryptoki import C_DestroyObject, CK_OBJECT_HANDLE, CK_ULONG, C_GenerateKey, \
    C_GenerateKeyPair, \
    C_CopyObject
from .default_templates import CKM_DES_KEY_GEN_TEMP, \
    get_default_key_pair_template
from .defines import CKM_DES_KEY_GEN, CKM_RSA_PKCS_KEY_PAIR_GEN
from .mechanism import parse_mechanism
from .test_functions import make_error_handle_function


def c_destroy_object(h_session, h_object_value):
    """Deletes the object corresponsing to the passed in object handle

    :param int h_session: Session handle
    :param int h_object_value: The handle of the object to delete
    :returns: Return code
    """
    ret = C_DestroyObject(h_session, CK_OBJECT_HANDLE(h_object_value))
    return ret


c_destroy_object_ex = make_error_handle_function(c_destroy_object)


def c_copy_object(h_session, h_object, template=None):
    """Method to call the C_CopyObject cryptoki command.

    :param int h_session: Session handle
    :param int h_object: Handle to the object to be cloned
    :param dict template: Template for the new object. Defaults to None
    :return: (retcode, Handle to the new cloned object)
    :rtype: tuple
    """
    if template is None:
        template = {}
    attributes = Attributes(template)
    template_size = CK_ULONG(len(template))

    h_new_object = CK_OBJECT_HANDLE()

    ret = C_CopyObject(h_session, h_object, attributes.get_c_struct(), template_size, h_new_object)

    return ret, h_new_object.value


c_copy_object_ex = make_error_handle_function(c_copy_object)


def c_generate_key(h_session, mechanism=None, template=None):
    """
    Generates a symmetric key of a given flavor given the correct template.

    :param int h_session: Session handle
    :param dict template: The template to use to generate the key
    :param mechanism: See the :py:func:`~pycryptoki.mechanism.parse_mechanism` function
        for possible values.
    :return: (retcode, generated key handle)
    :rtype tuple:
    """
    if mechanism is None:
        mechanism = {"mech_type": CKM_DES_KEY_GEN}

    mech = parse_mechanism(mechanism)

    if template is None:
        template = CKM_DES_KEY_GEN_TEMP

    key_attributes = Attributes(template)
    us_public_template_size = CK_ULONG(len(template))

    # ACTUALLY GENERATE KEY
    h_key = CK_OBJECT_HANDLE()
    ret = C_GenerateKey(h_session,
                        byref(mech), key_attributes.get_c_struct(),
                        us_public_template_size, byref(h_key))

    return ret, h_key.value


c_generate_key_ex = make_error_handle_function(c_generate_key)


def c_generate_key_pair(h_session,
                        mechanism=None,
                        pbkey_template=None,
                        prkey_template=None):
    """Generates a private and public key pair for a given flavor, and given public and private
    key templates. The return value will be the handle for the key.

    :param int h_session: Session handle
    :param dict pbkey_template: The public key template to use for key generation
    :param dict prkey_template: The private key template to use for key generation
    :param mechanism: See the :py:func:`~pycryptoki.mechanism.parse_mechanism` function
        for possible values.
    :returns: (retcode, public key handle, private key handle)
    :rtype: tuple
    """
    if mechanism is None:
        mechanism = {"mech_type": CKM_RSA_PKCS_KEY_PAIR_GEN}

    if pbkey_template is None and prkey_template is None:
        pbkey_template, prkey_template = get_default_key_pair_template(CKM_RSA_PKCS_KEY_PAIR_GEN)

    mech = parse_mechanism(mechanism)

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


def c_derive_key(h_session, h_base_key, template, mechanism=None):
    """Derives a key from another key.

    :param int h_session: Session handle
    :param int h_base_key: The base key
    :param dict template: A python template of attributes to set on derived key
    :param mechanism: See the :py:func:`~pycryptoki.mechanism.parse_mechanism` function
        for possible values.
    :returns: The result code, The derived key's handle

    """
    mech = parse_mechanism(mechanism)
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

    :param int h_session: Session handle
    """
    for i in range(1, 10000):
        c_destroy_object(h_session, i)
