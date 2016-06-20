import logging

import pytest

from . import config as hsm_config
from ...default_templates import CKM_DES_KEY_GEN_TEMP, \
    CKM_DES2_KEY_GEN_TEMP, CKM_DES3_KEY_GEN_TEMP, CKM_CAST3_KEY_GEN_TEMP, \
    CKM_GENERIC_SECRET_KEY_GEN_TEMP, CKM_CAST5_KEY_GEN_TEMP, CKM_RC2_KEY_GEN_TEMP, \
    CKM_RC4_KEY_GEN_TEMP, CKM_RC5_KEY_GEN_TEMP, CKM_AES_KEY_GEN_TEMP, CKM_SEED_KEY_GEN_TEMP, \
    CKM_ARIA_KEY_GEN_TEMP, \
    CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP, \
    CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_1024_160, \
    CKM_DSA_KEY_PAIR_GEN_PRIVTEMP, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_224, \
    CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_256, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_3072_256, \
    CKM_DH_PKCS_KEY_PAIR_GEN_PUBTEMP, CKM_DH_PKCS_KEY_PAIR_GEN_PRIVTEMP, \
    CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP, CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP, \
    CKM_KCDSA_KEY_PAIR_GEN_PUBTEMP_1024_160, CKM_KCDSA_KEY_PAIR_GEN_PRIVTEMP, \
    CKM_KCDSA_KEY_PAIR_GEN_PUBTEMP_2048_256, CKM_RSA_X9_31_KEY_PAIR_GEN_PUBTEMP, \
    CKM_RSA_X9_31_KEY_PAIR_GEN_PRIVTEMP, curve_list
from ...defines import CKM_DES_KEY_GEN, CKR_OK, \
    CKM_DES2_KEY_GEN, CKM_DES3_KEY_GEN, CKM_CAST3_KEY_GEN, \
    CKM_GENERIC_SECRET_KEY_GEN, CKM_CAST5_KEY_GEN, CKM_RC2_KEY_GEN, CKM_RC4_KEY_GEN, \
    CKM_RC5_KEY_GEN, CKM_AES_KEY_GEN, CKM_SEED_KEY_GEN, \
    CKM_ARIA_KEY_GEN, \
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN, \
    CKM_DH_PKCS_KEY_PAIR_GEN, CKM_ECDSA_KEY_PAIR_GEN, CKM_KCDSA_KEY_PAIR_GEN, \
    CKM_RSA_X9_31_KEY_PAIR_GEN, CKA_ECDSA_PARAMS, \
    CKM_SHA224_KEY_DERIVATION, CKM_SHA256_KEY_DERIVATION, CKM_SHA1_KEY_DERIVATION, \
    CKM_SHA384_KEY_DERIVATION, CKM_SHA512_KEY_DERIVATION, CKM_MD5_KEY_DERIVATION, \
    CKM_MD2_KEY_DERIVATION, CKA_VALUE_LEN, CKR_KEY_SIZE_RANGE
from ...key_generator import c_generate_key, c_generate_key_pair, \
    c_derive_key, c_generate_key_ex, c_destroy_object
from ...mechanism import NullMech
from ...return_values import ret_vals_dictionary
from ...test_functions import verify_object_attributes

logger = logging.getLogger(__name__)


class TestKeys(object):
    """ """

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session
        self.admin_slot = hsm_config['test_slot']

    @pytest.mark.parametrize(("key_type", "key_template"), [
        (CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP),
        (CKM_DES2_KEY_GEN, CKM_DES2_KEY_GEN_TEMP),
        (CKM_DES3_KEY_GEN, CKM_DES3_KEY_GEN_TEMP),
        (CKM_CAST3_KEY_GEN, CKM_CAST3_KEY_GEN_TEMP),
        (CKM_GENERIC_SECRET_KEY_GEN, CKM_GENERIC_SECRET_KEY_GEN_TEMP),
        (CKM_CAST5_KEY_GEN, CKM_CAST5_KEY_GEN_TEMP),
        (CKM_RC2_KEY_GEN, CKM_RC2_KEY_GEN_TEMP),
        (CKM_RC4_KEY_GEN, CKM_RC4_KEY_GEN_TEMP),
        (CKM_RC5_KEY_GEN, CKM_RC5_KEY_GEN_TEMP),
        (CKM_AES_KEY_GEN, CKM_AES_KEY_GEN_TEMP),
        (CKM_SEED_KEY_GEN, CKM_SEED_KEY_GEN_TEMP),
        (CKM_ARIA_KEY_GEN, CKM_ARIA_KEY_GEN_TEMP)
    ])
    def test_generate_key(self, key_type, key_template):
        """Tests generating a key, asserts that the operation returns correctly with key handles
        greater than 0

        :param key_type: The type of key to generate (ex. CKM_DES_KEY_GEN)
        :param key_template: The key template to generate (ex. CKM_DES_KEY_GEN_TEMP)

        """
        ret, key_handle = c_generate_key(self.h_session, key_type, key_template)
        assert ret == CKR_OK, "Return code should be " + ret_vals_dictionary[CKR_OK] + " not " + \
                              ret_vals_dictionary[ret]
        assert key_handle > 0, "The key handle returned should be non zero"

    @pytest.mark.parametrize(("key_type", "public_key_template", "private_key_template"), [
        (CKM_RSA_PKCS_KEY_PAIR_GEN,
         CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP,
         CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP),
        (CKM_DSA_KEY_PAIR_GEN,
         CKM_DSA_KEY_PAIR_GEN_PUBTEMP_1024_160,
         CKM_DSA_KEY_PAIR_GEN_PRIVTEMP),
        (CKM_DSA_KEY_PAIR_GEN,
         CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_224,
         CKM_DSA_KEY_PAIR_GEN_PRIVTEMP),
        (CKM_DSA_KEY_PAIR_GEN,
         CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_256,
         CKM_DSA_KEY_PAIR_GEN_PRIVTEMP),
        (CKM_DSA_KEY_PAIR_GEN,
         CKM_DSA_KEY_PAIR_GEN_PUBTEMP_3072_256,
         CKM_DSA_KEY_PAIR_GEN_PRIVTEMP),
        (CKM_DH_PKCS_KEY_PAIR_GEN,
         CKM_DH_PKCS_KEY_PAIR_GEN_PUBTEMP,
         CKM_DH_PKCS_KEY_PAIR_GEN_PRIVTEMP),
        (CKM_ECDSA_KEY_PAIR_GEN,
         CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP,
         CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP),
        (CKM_KCDSA_KEY_PAIR_GEN,
         CKM_KCDSA_KEY_PAIR_GEN_PUBTEMP_1024_160,
         CKM_KCDSA_KEY_PAIR_GEN_PRIVTEMP),
        (CKM_KCDSA_KEY_PAIR_GEN,
         CKM_KCDSA_KEY_PAIR_GEN_PUBTEMP_2048_256,
         CKM_KCDSA_KEY_PAIR_GEN_PRIVTEMP),
        (CKM_RSA_X9_31_KEY_PAIR_GEN,
         CKM_RSA_X9_31_KEY_PAIR_GEN_PUBTEMP,
         CKM_RSA_X9_31_KEY_PAIR_GEN_PRIVTEMP),
        #         (CKM_X9_42_DH_KEY_PAIR_GEN, CKM_X9_42_DH_KEY_PAIR_GEN_PUBTEMP,
        # CKM_X9_42_DH_KEY_PAIR_GEN_PRIVTEMP) #XXX
    ])
    def test_generate_key_pair(self, key_type, public_key_template, private_key_template):
        """Tests generating a key pair, asserts that the operation returns correctly with key
        handles
        greater than 0.

        :param key_type: The type of key to create (ex. CKM_DSA_KEY_PAIR_GEN)
        :param public_key_template: The template to use for public key generation (ex.
        CKM_DSA_KEY_PAIR_GEN_PUBTEMP_1024_160
        :param private_key_template: The template to use for private key generation (ex.
        CKM_DSA_KEY_PAIR_GEN_PRIVTEMP_1024_160

        """
        ret, public_key_handle, private_key_handle = c_generate_key_pair(self.h_session, key_type,
                                                                         public_key_template,
                                                                         private_key_template)
        assert ret == CKR_OK, "Return code should be " + ret_vals_dictionary[CKR_OK] + " not " + \
                              ret_vals_dictionary[ret]
        assert public_key_handle > 0, "The public key handle returned should be non zero"
        assert private_key_handle > 0, "The private key handle returned should be non zero"

    @pytest.mark.parametrize("curve_type", curve_list.keys())
    def test_generate_ecdsa_key_pairs(self, curve_type):
        """

        :param curve_type:

        """
        CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP[CKA_ECDSA_PARAMS] = curve_list[curve_type]
        ret, public_key_handle, private_key_handle = c_generate_key_pair(self.h_session,
                                                                         CKM_ECDSA_KEY_PAIR_GEN,
                                                                         CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP,
                                                                         CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP)
        try:
            assert ret == CKR_OK, "Return code should be " + ret_vals_dictionary[CKR_OK] + " not " \
                                                                                           "" + \
                                  ret_vals_dictionary[ret]
            assert public_key_handle > 0, "The public key handle returned should be non zero"
            assert private_key_handle > 0, "The private key handle returned should be non zero"
        finally:
            if public_key_handle:
                c_destroy_object(self.h_session, public_key_handle)
            if private_key_handle:
                c_destroy_object(self.h_session, private_key_handle)

    @pytest.mark.parametrize("derive_type", [CKM_SHA1_KEY_DERIVATION,
                                             CKM_SHA224_KEY_DERIVATION,
                                             CKM_SHA256_KEY_DERIVATION,
                                             CKM_SHA384_KEY_DERIVATION,
                                             CKM_SHA512_KEY_DERIVATION,
                                             CKM_MD5_KEY_DERIVATION,
                                             CKM_MD2_KEY_DERIVATION],
                             ids=["SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
                                  "MD5", "MD2"])
    @pytest.mark.parametrize(("key_type", "key_template"), [
        (CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP),
        (CKM_DES2_KEY_GEN, CKM_DES2_KEY_GEN_TEMP),
        (CKM_CAST3_KEY_GEN, CKM_CAST3_KEY_GEN_TEMP),
        (CKM_GENERIC_SECRET_KEY_GEN, CKM_GENERIC_SECRET_KEY_GEN_TEMP),
        (CKM_CAST5_KEY_GEN, CKM_CAST5_KEY_GEN_TEMP),
        (CKM_SEED_KEY_GEN, CKM_SEED_KEY_GEN_TEMP),
    ],
                             ids=["DES", "DES2", 'CAST3',
                                  'GENERIC', 'CAST5', "SEED", ])
    def test_derive_key(self, key_type, key_template, derive_type):
        """Tests deriving a key

        :param key_type:
        :param key_template:

        """
        h_base_key = c_generate_key_ex(self.h_session, key_type, key_template)
        mech = NullMech(derive_type).to_c_mech()

        derived_key_template = key_template.copy()
        del derived_key_template[CKA_VALUE_LEN]

        ret, h_derived_key = c_derive_key(self.h_session,
                                          h_base_key,
                                          key_template,
                                          mech_flavor=derive_type,
                                          mech=mech)
        try:
            assert ret == CKR_OK, "Deriving a key should not fail, instead it failed with " + \
                                  ret_vals_dictionary[ret]

            verify_object_attributes(self.h_session, h_derived_key, key_template)
        finally:
            if h_base_key:
                c_destroy_object(self.h_session, h_base_key)
            if h_derived_key:
                c_destroy_object(self.h_session, h_derived_key)

    @pytest.mark.parametrize("derive_type", [CKM_SHA1_KEY_DERIVATION,
                                             CKM_MD5_KEY_DERIVATION,
                                             CKM_MD2_KEY_DERIVATION],
                             ids=["SHA1", "MD5", "MD2"])
    @pytest.mark.parametrize(("key_type", "key_template"), [
        (CKM_DES3_KEY_GEN, CKM_DES3_KEY_GEN_TEMP),
        (CKM_AES_KEY_GEN, CKM_AES_KEY_GEN_TEMP),
        (CKM_ARIA_KEY_GEN, CKM_ARIA_KEY_GEN_TEMP)
    ],
                             ids=['DES3', 'AES', 'ARIA'])
    def test_too_long_length_derives(self, key_type, key_template, derive_type):
        """
        Verify that trying to derive a key that is too long for the given derivation function
        will return CKR_KEY_SIZE_RANGE

        :param key_type:
        :param key_template:
        :param derive_type:
        :return:
        """
        h_base_key = c_generate_key_ex(self.h_session, key_type, key_template)
        mech = NullMech(derive_type).to_c_mech()

        derived_key_template = key_template.copy()
        del derived_key_template[CKA_VALUE_LEN]

        ret, h_derived_key = c_derive_key(self.h_session,
                                          h_base_key,
                                          key_template,
                                          mech_flavor=derive_type,
                                          mech=mech)
        try:
            assert ret == CKR_KEY_SIZE_RANGE
        finally:
            if h_base_key:
                c_destroy_object(self.h_session, h_base_key)
            if h_derived_key:
                c_destroy_object(self.h_session, h_derived_key)

    @pytest.mark.parametrize("derive_type", [CKM_SHA224_KEY_DERIVATION,
                                             CKM_SHA256_KEY_DERIVATION,
                                             CKM_SHA384_KEY_DERIVATION,
                                             CKM_SHA512_KEY_DERIVATION],
                             ids=["SHA224", "SHA256", "SHA384", "SHA512"])
    @pytest.mark.parametrize(("key_type", "key_template"), [
        (CKM_DES3_KEY_GEN, CKM_DES3_KEY_GEN_TEMP),
        (CKM_AES_KEY_GEN, CKM_AES_KEY_GEN_TEMP),
        (CKM_ARIA_KEY_GEN, CKM_ARIA_KEY_GEN_TEMP)
    ],
                             ids=['DES3', 'AES', 'ARIA'])
    def test_long_length_derive_key(self, key_type, key_template, derive_type):
        """Tests deriving a key

        :param key_type:
        :param key_template:

        """
        h_base_key = c_generate_key_ex(self.h_session, key_type, key_template)
        mech = NullMech(derive_type).to_c_mech()

        derived_key_template = key_template.copy()
        del derived_key_template[CKA_VALUE_LEN]

        ret, h_derived_key = c_derive_key(self.h_session,
                                          h_base_key,
                                          key_template,
                                          mech_flavor=derive_type,
                                          mech=mech)
        try:
            assert ret == CKR_OK, "Deriving a key should not fail, instead it failed with " + \
                                  ret_vals_dictionary[ret]

            verify_object_attributes(self.h_session, h_derived_key, key_template)
        finally:
            if h_base_key:
                c_destroy_object(self.h_session, h_base_key)
            if h_derived_key:
                c_destroy_object(self.h_session, h_derived_key)
