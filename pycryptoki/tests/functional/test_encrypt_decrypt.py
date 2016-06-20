import logging
import os

import pytest

from . import config as hsm_config
from ...default_templates import CKM_DES_KEY_GEN_TEMP
from ...defines import CKM_DES_KEY_GEN, CKM_DES_CBC, CKR_OK
from ...encryption import c_encrypt, c_decrypt, _split_string_into_list, \
    _get_string_from_list
from ...key_generator import c_generate_key_ex
from ...return_values import ret_vals_dictionary

logger = logging.getLogger(__name__)


class TestEncryptData(object):
    """ """

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.admin_slot = hsm_config["test_slot"]
        self.h_session = auth_session

    def test_encrypt_decrypt_string(self):
        """Tests encrypting and decrypting a string with a key"""
        h_key = c_generate_key_ex(self.h_session, CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP)

        data_to_encrypt = "a" * 0xfff0
        ret, encrypted_data = c_encrypt(self.h_session, CKM_DES_CBC, h_key, data_to_encrypt)
        assert ret == CKR_OK, \
            "Encryption should go through successfully, instead it returned " + \
            ret_vals_dictionary[ret]

        ret, decrypted_string = c_decrypt(self.h_session, CKM_DES_CBC, h_key, encrypted_data)
        assert ret == CKR_OK, \
            "There should be no errors when decrypting, instead found " + ret_vals_dictionary[ret]
        assert decrypted_string == data_to_encrypt, \
            "The decrypted data should be the same as the " \
            "data that was encrypted. Instead found " + str(decrypted_string)

    def test_multipart_encrypt_decrypt(self):
        """Tests encryption and decryption using C_EncryptUpdate and C_DecryptUpdate therefore
        doing it in multiple
        parts


        """
        h_key = c_generate_key_ex(self.h_session, CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP)

        data_to_encrypt = ['a' * 512, 'b' * 512, 'c' * 512, 'd' * 512]
        ret, encrypted_data = c_encrypt(self.h_session, CKM_DES_CBC, h_key, data_to_encrypt)
        assert ret == CKR_OK, "Encryption should go through successfully, instead it returned " + \
                              ret_vals_dictionary[ret]
        assert len(encrypted_data) == len(_get_string_from_list(data_to_encrypt))

        encrypted_data_chunks = _split_string_into_list(encrypted_data, 512)

        ret, decrypted_data = c_decrypt(self.h_session, CKM_DES_CBC, h_key, encrypted_data_chunks)
        assert ret == CKR_OK, "Decryption should succeed, instead it returned " + \
                              ret_vals_dictionary[ret]
        assert _get_string_from_list(
            data_to_encrypt) == decrypted_data, "The data before encryption should match the data " \
                                                "" \
                                                "after encryption"
