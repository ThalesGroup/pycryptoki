"""
Testcases for wrapping/unwrapping keys.
"""
import logging

import pytest

from pycryptoki.default_templates import MECHANISM_LOOKUP_EXT as LOOKUP
from pycryptoki.default_templates import get_default_key_template
from pycryptoki.defines import (CKM_DES_ECB, CKM_DES_CBC, CKM_DES_CBC_PAD, CKM_DES_KEY_GEN,
                                CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD, CKM_DES3_KEY_GEN,
                                CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_KEY_GEN,
                                CKM_CAST3_ECB, CKM_CAST3_CBC, CKM_CAST3_CBC_PAD, CKM_CAST3_KEY_GEN,
                                CKM_CAST5_ECB, CKM_CAST5_CBC, CKM_CAST5_CBC_PAD, CKM_CAST5_KEY_GEN,
                                CKM_SEED_ECB, CKM_SEED_CBC, CKM_SEED_KEY_GEN,

                                CKR_OK, CKA_DECRYPT, CKA_VERIFY, CKA_UNWRAP,
                                CKA_VALUE_LEN, CKA_EXTRACTABLE)
from pycryptoki.encryption import c_wrap_key, c_unwrap_key, c_encrypt, c_decrypt
from pycryptoki.key_generator import c_destroy_object, c_generate_key
from pycryptoki.lookup_dicts import ret_vals_dictionary
from pycryptoki.test_functions import verify_object_attributes

logger = logging.getLogger(__name__)

PARAM_LIST = [(CKM_DES_ECB, CKM_DES_KEY_GEN),
              (CKM_DES_CBC, CKM_DES_KEY_GEN),
              (CKM_DES_CBC_PAD, CKM_DES_KEY_GEN),

              (CKM_DES3_ECB, CKM_DES3_KEY_GEN),
              (CKM_DES3_CBC, CKM_DES3_KEY_GEN),
              (CKM_DES3_CBC_PAD, CKM_DES3_KEY_GEN),

              (CKM_AES_ECB, CKM_AES_KEY_GEN),
              (CKM_AES_CBC, CKM_AES_KEY_GEN),
              (CKM_AES_CBC_PAD, CKM_AES_KEY_GEN),

              (CKM_CAST3_ECB, CKM_CAST3_KEY_GEN),
              (CKM_CAST3_CBC, CKM_CAST3_KEY_GEN),
              (CKM_CAST3_CBC_PAD, CKM_CAST3_KEY_GEN),

              (CKM_CAST5_ECB, CKM_CAST5_KEY_GEN),
              (CKM_CAST5_CBC, CKM_CAST5_KEY_GEN),
              (CKM_CAST5_CBC_PAD, CKM_CAST5_KEY_GEN),

              (CKM_SEED_ECB, CKM_SEED_KEY_GEN),
              (CKM_SEED_CBC, CKM_SEED_KEY_GEN)]

EXTRA_PARAM = {CKM_DES_ECB: {},
               CKM_DES_CBC: {'iv': list(range(8))},
               CKM_DES_CBC_PAD: {},

               CKM_DES3_ECB: {},
               CKM_DES3_CBC: {'iv': list(range(8))},
               CKM_DES3_CBC_PAD: {'iv': list(range(8))},

               CKM_AES_ECB: {},
               CKM_AES_CBC: {'iv': list(range(16))},
               CKM_AES_CBC_PAD: {},

               CKM_CAST3_ECB: {},
               CKM_CAST3_CBC: {'iv': list(range(8))},
               CKM_CAST3_CBC_PAD: {},

               CKM_CAST5_ECB: {},
               CKM_CAST5_CBC: {},
               CKM_CAST5_CBC_PAD: {},

               CKM_SEED_ECB: {},
               CKM_SEED_CBC: {}}

# Don't pop 'CKA_VALUE_LEN' for these mechs
VALUE_LEN = [CKM_AES_KEY_GEN, CKM_CAST3_KEY_GEN, CKM_CAST5_KEY_GEN]


@pytest.yield_fixture(scope='class')
def keys(auth_session):
    """ Fixture containing keys"""
    keys = {}
    try:
        for key_gen in set(param[1] for param in PARAM_LIST):
            template = get_default_key_template(key_gen)

            ret, key_handle = c_generate_key(auth_session, key_gen, template)
            ret2, wrap_handle = c_generate_key(auth_session, key_gen, template)
            if ret == CKR_OK and ret2 == CKR_OK:
                keys[key_gen] = key_handle, wrap_handle
            elif ret2 != CKR_OK:
                keys[key_gen] = key_handle, None
                logger.info("Failed to generate key: {}\nReturn code: {}".format(key_gen, ret2))
            elif ret != CKR_OK:
                keys[key_gen] = None, wrap_handle
                logger.info("Failed to generate key: {}\nReturn code: {}".format(key_gen, ret))
            else:
                logger.info("Failed to generate key: {}\nReturn code: {}".format(key_gen, ret))
        yield keys

    finally:
        for key, wrap in keys.values():
            if key is not None:
                c_destroy_object(auth_session, key)
            if wrap is not None:
                c_destroy_object(auth_session, wrap)


class TestWrappingKeys(object):
    """
    Testcases for wrapping/unwrapping keys.
    """
    def verify_ret(self, ret, expected_ret):
        """
        Assert that ret is as expected
        :param ret: the actual return value
        :param expected_ret: the expected return value
        """
        assert ret == expected_ret, "Function should return: " + ret_vals_dictionary[expected_ret] \
                                    + ".\nInstead returned: " + ret_vals_dictionary[ret]

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session

    def generate_unwrap_temp(self, key_gen):
        """
        Create an unwrap template which is slightly different then the original template
        :param key_gen:
        :return: the new unwrap template
        """
        unwrap_temp = get_default_key_template(key_gen)
        unwrap_temp.pop(CKA_DECRYPT, None)
        unwrap_temp.pop(CKA_VERIFY, None)
        unwrap_temp.pop(CKA_UNWRAP, None)
        unwrap_temp.pop(CKA_EXTRACTABLE, None)
        if key_gen not in VALUE_LEN:
            unwrap_temp.pop(CKA_VALUE_LEN, None)

        return unwrap_temp

    @pytest.mark.parametrize(('mech', 'k_type'), PARAM_LIST,
                             ids=[LOOKUP[m][0] for m, _ in PARAM_LIST])
    def test_wrap_unwrap_key(self, mech, k_type, keys):
        """
        Test key wrapping
        :param mech: encryption mech
        :param k_type: key gen mech
        :param keys: keys fixture
        """
        temp = get_default_key_template(k_type)
        unwrap_temp = self.generate_unwrap_temp(k_type)
        extra_p = EXTRA_PARAM[mech]
        h_key, h_wrap_key = keys[k_type]
        if h_key is None or h_wrap_key is None:
            pytest.fail("No valid key found for {}".format(LOOKUP[mech][0]))

        # Wrap the key
        wrap_mech = {"mech_type": mech,
                     "params": extra_p}
        ret, wrapped_key = c_wrap_key(self.h_session, h_wrap_key, h_key, mechanism=wrap_mech)
        self.verify_ret(ret, CKR_OK)

        # Unwrap the Key
        ret, h_unwrapped_key = c_unwrap_key(self.h_session,
                                            h_wrap_key,
                                            wrapped_key,
                                            unwrap_temp,
                                            mechanism=wrap_mech)
        self.verify_ret(ret, CKR_OK)

        # Verify all of the attributes against the originally generated attributes
        verify_object_attributes(self.h_session, h_unwrapped_key, temp)

    @pytest.mark.parametrize(('mech', 'k_type'), PARAM_LIST,
                             ids=[LOOKUP[m][0] for m, _ in PARAM_LIST])
    def test_encrypt_wrap_unwrap_decrypt_key(self, mech, k_type, keys):
        """
        Test that encrypt/decrypt works with wrapped keys

        :param mech: encryption mech
        :param k_type: key gen mech
        :param keys: keys fixture
        """
        unwrap_temp = self.generate_unwrap_temp(k_type)
        h_key, h_wrap_key = keys[k_type]
        extra_p = EXTRA_PARAM[mech]
        if h_key is None or h_wrap_key is None:
            pytest.fail("No valid key found for {}".format(LOOKUP[mech][0]))

        # Encrypt some data
        data_to_encrypt = b"a" * 512
        enc_mech = {"mech_type": mech}
        ret, encrypted_data = c_encrypt(self.h_session, h_key, data_to_encrypt, mechanism=enc_mech)
        self.verify_ret(ret, CKR_OK)

        # Wrap the key
        wrap_mech = {"mech_type": mech,
                     "params": extra_p}
        ret, wrapped_key = c_wrap_key(self.h_session, h_wrap_key, h_key, mechanism=wrap_mech)
        self.verify_ret(ret, CKR_OK)

        # Unwrap the Key
        ret, h_unwrapped_key = c_unwrap_key(self.h_session, h_wrap_key,
                                            wrapped_key,
                                            unwrap_temp,
                                            mechanism=wrap_mech)
        self.verify_ret(ret, CKR_OK)

        # Decrypt the data
        ret, decrypted_string = c_decrypt(self.h_session,
                                          h_unwrapped_key,
                                          encrypted_data,
                                          mechanism=enc_mech)
        self.verify_ret(ret, CKR_OK)

        assert decrypted_string == data_to_encrypt, \
            "The decrypted data should be the same as the data that was encrypted. " \
            "Instead found " + str(decrypted_string)
