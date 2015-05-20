from ctypes import cast, pointer
import ctypes
import logging
import os

import pytest

from pycryptoki.cryptoki import CK_VOID_PTR, CK_ULONG
from pycryptoki.default_templates import CKM_DES_KEY_GEN_TEMP, \
    CKM_DES2_KEY_GEN_TEMP, CKM_DES3_KEY_GEN_TEMP, CKM_CAST3_KEY_GEN_TEMP, \
    CKM_GENERIC_SECRET_KEY_GEN_TEMP, CKM_CAST5_KEY_GEN_TEMP, CKM_RC2_KEY_GEN_TEMP, \
    CKM_RC4_KEY_GEN_TEMP, CKM_RC5_KEY_GEN_TEMP, CKM_AES_KEY_GEN_TEMP, CKM_SEED_KEY_GEN_TEMP, CKM_ARIA_KEY_GEN_TEMP, \
    CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP, \
    CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_1024_160, \
    CKM_DSA_KEY_PAIR_GEN_PRIVTEMP, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_224, \
    CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_256, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_3072_256, \
    CKM_DH_PKCS_KEY_PAIR_GEN_PUBTEMP, CKM_DH_PKCS_KEY_PAIR_GEN_PRIVTEMP, \
    CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP, CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP, \
    CKM_KCDSA_KEY_PAIR_GEN_PUBTEMP_1024_160, CKM_KCDSA_KEY_PAIR_GEN_PRIVTEMP, \
    CKM_KCDSA_KEY_PAIR_GEN_PUBTEMP_2048_256, CKM_RSA_X9_31_KEY_PAIR_GEN_PUBTEMP, \
    CKM_RSA_X9_31_KEY_PAIR_GEN_PRIVTEMP, curve_list
from pycryptoki.defaults import ADMIN_PARTITION_LABEL, CO_PASSWORD
from pycryptoki.defines import CKU_USER, CKM_DES_KEY_GEN, CKR_OK, \
    CKM_DES2_KEY_GEN, CKM_DES3_KEY_GEN, CKM_CAST3_KEY_GEN, \
    CKM_GENERIC_SECRET_KEY_GEN, CKM_CAST5_KEY_GEN, CKM_RC2_KEY_GEN, CKM_RC4_KEY_GEN, \
    CKM_RC5_KEY_GEN, CKM_AES_KEY_GEN, CKM_SEED_KEY_GEN, \
    CKM_ARIA_KEY_GEN, \
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN, \
    CKM_DH_PKCS_KEY_PAIR_GEN, CKM_ECDSA_KEY_PAIR_GEN, CKM_KCDSA_KEY_PAIR_GEN, \
    CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_CONCATENATE_BASE_AND_KEY, CKA_ECDSA_PARAMS
from pycryptoki.key_generator import c_generate_key, c_generate_key_pair, \
    c_derive_key, c_generate_key_ex, _get_mechanism
from pycryptoki.return_values import ret_vals_dictionary
from pycryptoki.session_management import c_finalize_ex, c_open_session_ex, \
    login_ex, c_logout_ex, c_close_session_ex, c_initialize_ex
from pycryptoki.test_functions import verify_object_attributes
from pycryptoki.tests.setup_for_tests import setup_for_tests
from pycryptoki.token_management import get_token_by_label_ex

logger = logging.getLogger(__name__)

class TestKeys:
    """ """
    @classmethod
    def setup_class(cls):
        """ """
        setup_for_tests(True, True, True)
        c_initialize_ex()

    @classmethod
    def teardown_class(cls):
        """ """
        c_finalize_ex()

    def setup(self):
        """ """
        admin_slot = get_token_by_label_ex(ADMIN_PARTITION_LABEL)
        self.h_session = c_open_session_ex(slot_num=admin_slot)
        login_ex(self.h_session, admin_slot, CO_PASSWORD, CKU_USER)

    def teardown(self):
        """ """
        c_logout_ex(self.h_session)
        c_close_session_ex(self.h_session)

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
#          (CKM_SSL3_PRE_MASTER_KEY_GEN, CKM_SSL3_PRE_MASTER_KEY_GEN_TEMP), XXX
          (CKM_AES_KEY_GEN, CKM_AES_KEY_GEN_TEMP),
          (CKM_SEED_KEY_GEN, CKM_SEED_KEY_GEN_TEMP),
#          (CKM_DSA_PARAMETER_GEN, CKM_DSA_PARAMETER_GEN_TEMP), XXX
#          (CKM_KCDSA_PARAMETER_GEN, CKM_KCDSA_PARAMETER_GEN_TEMP), XXX
          (CKM_ARIA_KEY_GEN, CKM_ARIA_KEY_GEN_TEMP)
#          (CKM_DH_PKCS_PARAMETER_GEN, CKM_DH_PKCS_PARAMETER_GEN_TEMP) XXX
    ])
    def test_generate_key(self, key_type, key_template):
        """Tests generating a key, asserts that the operation returns correctly with key handles
        greater than 0

        :param key_type: The type of key to generate (ex. CKM_DES_KEY_GEN)
        :param key_template: The key template to generate (ex. CKM_DES_KEY_GEN_TEMP)

        """
        ret, key_handle = c_generate_key(self.h_session, key_type, key_template)
        assert ret == CKR_OK, "Return code should be " + ret_vals_dictionary[CKR_OK] + " not " + ret_vals_dictionary[ret]
        assert key_handle > 0, "The key handle returned should be non zero"


    @pytest.mark.parametrize(("key_type", "public_key_template", "private_key_template"), [
         (CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP, CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP),
         (CKM_DSA_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_1024_160, CKM_DSA_KEY_PAIR_GEN_PRIVTEMP),
         (CKM_DSA_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_224, CKM_DSA_KEY_PAIR_GEN_PRIVTEMP),
         (CKM_DSA_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_2048_256, CKM_DSA_KEY_PAIR_GEN_PRIVTEMP),
         (CKM_DSA_KEY_PAIR_GEN, CKM_DSA_KEY_PAIR_GEN_PUBTEMP_3072_256, CKM_DSA_KEY_PAIR_GEN_PRIVTEMP),
         (CKM_DH_PKCS_KEY_PAIR_GEN, CKM_DH_PKCS_KEY_PAIR_GEN_PUBTEMP, CKM_DH_PKCS_KEY_PAIR_GEN_PRIVTEMP),
         (CKM_ECDSA_KEY_PAIR_GEN, CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP, CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP),
         (CKM_KCDSA_KEY_PAIR_GEN, CKM_KCDSA_KEY_PAIR_GEN_PUBTEMP_1024_160, CKM_KCDSA_KEY_PAIR_GEN_PRIVTEMP),
         (CKM_KCDSA_KEY_PAIR_GEN, CKM_KCDSA_KEY_PAIR_GEN_PUBTEMP_2048_256, CKM_KCDSA_KEY_PAIR_GEN_PRIVTEMP),
         (CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_X9_31_KEY_PAIR_GEN_PUBTEMP, CKM_RSA_X9_31_KEY_PAIR_GEN_PRIVTEMP),
#         (CKM_X9_42_DH_KEY_PAIR_GEN, CKM_X9_42_DH_KEY_PAIR_GEN_PUBTEMP, CKM_X9_42_DH_KEY_PAIR_GEN_PRIVTEMP) #XXX
    ])
    def test_generate_key_pair(self, key_type, public_key_template, private_key_template):
        """Tests generating a key pair, asserts that the operation returns correctly with key handles
        greater than 0.

        :param key_type: The type of key to create (ex. CKM_DSA_KEY_PAIR_GEN)
        :param public_key_template: The template to use for public key generation (ex. CKM_DSA_KEY_PAIR_GEN_PUBTEMP_1024_160
        :param private_key_template: The template to use for private key generation (ex. CKM_DSA_KEY_PAIR_GEN_PRIVTEMP_1024_160

        """
        ret, public_key_handle, private_key_handle = c_generate_key_pair(self.h_session, key_type, public_key_template, private_key_template)
        assert ret == CKR_OK, "Return code should be " + ret_vals_dictionary[CKR_OK] + " not " + ret_vals_dictionary[ret]
        assert public_key_handle > 0, "The public key handle returned should be non zero"
        assert private_key_handle > 0, "The private key handle returned should be non zero"

    @pytest.mark.parametrize("curve_type", curve_list.keys())
    def test_generate_ecdsa_key_pairs(self, curve_type):
        """

        :param curve_type:

        """
        print curve_list.keys()
        CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP[CKA_ECDSA_PARAMS] = curve_list[curve_type]
        ret, public_key_handle, private_key_handle = c_generate_key_pair(self.h_session, CKM_ECDSA_KEY_PAIR_GEN, CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP, CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP)
        assert ret == CKR_OK, "Return code should be " + ret_vals_dictionary[CKR_OK] + " not " + ret_vals_dictionary[ret]
        assert public_key_handle > 0, "The public key handle returned should be non zero"
        assert private_key_handle > 0, "The private key handle returned should be non zero"

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
#          (CKM_SSL3_PRE_MASTER_KEY_GEN, CKM_SSL3_PRE_MASTER_KEY_GEN_TEMP), XXX
          (CKM_AES_KEY_GEN, CKM_AES_KEY_GEN_TEMP),
          (CKM_SEED_KEY_GEN, CKM_SEED_KEY_GEN_TEMP),
#          (CKM_DSA_PARAMETER_GEN, CKM_DSA_PARAMETER_GEN_TEMP), XXX
#          (CKM_KCDSA_PARAMETER_GEN, CKM_KCDSA_PARAMETER_GEN_TEMP), XXX
          (CKM_ARIA_KEY_GEN, CKM_ARIA_KEY_GEN_TEMP)
#          (CKM_DH_PKCS_PARAMETER_GEN, CKM_DH_PKCS_PARAMETER_GEN_TEMP) XXX
    ])
    def test_derive_key(self, key_type, key_template):
        """Tests deriving a key

        :param key_type:
        :param key_template:

        """
        h_base_key = c_generate_key_ex(self.h_session, key_type, key_template)
        h_second_key = c_generate_key_ex(self.h_session, key_type, key_template)

        mech = _get_mechanism(CKM_CONCATENATE_BASE_AND_KEY)
        c_second_key = CK_ULONG(h_second_key)
        mech.pParameter = cast(pointer(c_second_key), CK_VOID_PTR)
        mech.usParameterLen = ctypes.sizeof(c_second_key)

        ret, h_derived_key = c_derive_key(self.h_session, h_base_key, key_template, None, mech)
        assert ret == CKR_OK, "Deriving a key should not fail, instead it failed with " + ret_vals_dictionary[ret]

        verify_object_attributes(self.h_session, h_derived_key, key_template)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-v', os.path.abspath(__file__)])
