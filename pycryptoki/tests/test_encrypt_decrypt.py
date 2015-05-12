from pycryptoki.default_templates import CKM_DES_KEY_GEN_TEMP
from pycryptoki.defaults import ADMIN_PARTITION_LABEL, CO_PASSWORD
from pycryptoki.defines import CKU_USER, CKM_DES_KEY_GEN, CKM_DES_CBC, CKR_OK, \
    CKM_DES_CBC_PAD, CKM_DES_CBC_ENCRYPT_DATA
from pycryptoki.encryption import c_encrypt, c_decrypt, _split_string_into_list, \
    _get_string_from_list
from pycryptoki.key_generator import c_generate_key_ex
from pycryptoki.return_values import ret_vals_dictionary
from pycryptoki.session_management import c_finalize_ex, c_open_session_ex, \
    login_ex, c_logout_ex, c_close_session_ex, c_initialize_ex
from pycryptoki.tests.setup_for_tests import setup_for_tests
from pycryptoki.token_management import get_token_by_label_ex
import logging
import os
import pytest

logger = logging.getLogger(__name__)

class TestEncryptData():
    @classmethod
    def setup_class(self):
        setup_for_tests(True, True, True)
        c_initialize_ex()
        
    @classmethod
    def teardown_class(self):
        c_finalize_ex()
        
    def setup(self):
        admin_slot = get_token_by_label_ex(ADMIN_PARTITION_LABEL)
        self.h_session = c_open_session_ex(slot_num=admin_slot)
        login_ex(self.h_session, admin_slot, CO_PASSWORD, CKU_USER)
    
    def teardown(self):
        c_logout_ex(self.h_session)
        c_close_session_ex(self.h_session)

    def test_encrypt_decrypt_string(self):
        '''
        Tests encrypting and decrypting a string with a key
        '''
        h_key = c_generate_key_ex(self.h_session, CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP)
        
        data_to_encrypt = "a" * (0xfff0)
        ret, encrypted_data  = c_encrypt(self.h_session, CKM_DES_CBC, h_key, data_to_encrypt)
        assert ret == CKR_OK, "Encryption should go through successfully, instead it returned " + ret_vals_dictionary[ret]
        
        ret, decrypted_string = c_decrypt(self.h_session, CKM_DES_CBC, h_key, encrypted_data)
        assert ret == CKR_OK, "There should be no errors when decrypting, instead found " + ret_vals_dictionary[ret]
        assert decrypted_string == data_to_encrypt, "The decrypted data should be the same as the data that was encrypted. Instead found " + str(decrypted_string)
        
    def test_multipart_encrypt_decrypt(self):
        '''
        Tests encryption and decryption using C_EncryptUpdate and C_DecryptUpdate therefore doing it in multiple
        parts
        '''
        h_key = c_generate_key_ex(self.h_session, CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP)
        
        data_to_encrypt = ['a' * 512, 'b' * 512, 'c' * 512, 'd' * 512]
        ret, encrypted_data  = c_encrypt(self.h_session, CKM_DES_CBC, h_key, data_to_encrypt)
        assert ret == CKR_OK, "Encryption should go through successfully, instead it returned " + ret_vals_dictionary[ret]
        assert len(encrypted_data) == len(_get_string_from_list(data_to_encrypt))
        
        encrypted_data_chunks = _split_string_into_list(encrypted_data, 512)
        
        ret, decrypted_data = c_decrypt(self.h_session, CKM_DES_CBC, h_key, encrypted_data_chunks)
        assert ret == CKR_OK, "Decryption should succeed, instead it returned " + ret_vals_dictionary[ret]
        assert _get_string_from_list(data_to_encrypt) == decrypted_data, "The data before encryption should match the data after encryption"
        
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-vs', os.path.abspath(__file__)])  