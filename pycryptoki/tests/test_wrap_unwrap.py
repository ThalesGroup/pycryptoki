from pycryptoki.default_templates import CKM_DES_KEY_GEN_TEMP, \
    CKM_DES_UNWRAP_TEMP
from pycryptoki.defaults import ADMIN_PARTITION_LABEL, CO_PASSWORD
from pycryptoki.defines import CKU_USER, CKM_DES_KEY_GEN, CKM_DES_CBC, CKR_OK, \
    CKA_LABEL, CKM_DES_ECB
from pycryptoki.encryption import c_wrap_key, c_unwrap_key, c_encrypt, c_decrypt
from pycryptoki.key_generator import c_generate_key, c_generate_key_ex
from pycryptoki.return_values import ret_vals_dictionary
from pycryptoki.session_management import c_finalize_ex, c_open_session_ex, \
    login_ex, c_logout_ex, c_close_session_ex, c_initialize_ex
from pycryptoki.test_functions import verify_object_attributes
from pycryptoki.tests.setup_for_tests import setup_for_tests
from pycryptoki.token_management import get_token_by_label_ex
import logging
import os
import pytest

logger = logging.getLogger(__name__)

class TestWrappingKeys():
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

    def test_wrap_unwrap_key(self):
        '''
        Tests the attributes of an unwrapped key are idential to the original key
        '''
        h_key = c_generate_key_ex(self.h_session, CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP)
        h_wrapping_key = c_generate_key_ex(self.h_session, CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP)
        
        #Wrap the key
        ret, wrapped_key = c_wrap_key(self.h_session, h_wrapping_key, h_key, CKM_DES_ECB)
        assert ret == CKR_OK, "Wrapping the key should pass, instead it returns " + ret_vals_dictionary[ret]
        
        #Unwrap the Key
        ret, h_unwrapped_key = c_unwrap_key(self.h_session, h_wrapping_key, wrapped_key, CKM_DES_UNWRAP_TEMP, CKM_DES_ECB)
        assert ret == CKR_OK, "Unwrapping the key should pass, instead it returns " + ret_vals_dictionary[ret]
        
        #Verify all of the attributes against the originally generated attributes
        verify_object_attributes(self.h_session, h_unwrapped_key, CKM_DES_KEY_GEN_TEMP)
        
    def test_encrypt_wrap_unwrap_decrypt_key(self):
        '''
        Tests encrypting some data with a key. Then wrapping and unwrapping the key
        and using the unwrapped key to decrypt the data. It then compares the data to the
        original data.
        '''
        h_key = c_generate_key_ex(self.h_session, CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP)
        h_wrapping_key = c_generate_key_ex(self.h_session, CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP)
        
        #Encrypt some data
        data_to_encrypt = "a" * 512
        ret, encrypted_data  = c_encrypt(self.h_session, CKM_DES_CBC, h_key, data_to_encrypt)
        assert ret == CKR_OK, "Encryption should go through successfully, instead it returned " + ret_vals_dictionary[ret]
        
        #Wrap the key
        ret, wrapped_key = c_wrap_key(self.h_session, h_wrapping_key, h_key, CKM_DES_ECB)
        assert ret == CKR_OK, "Wrapping the key should pass, instead it returns " + ret_vals_dictionary[ret]
        
        #Unwrap the Key
        ret, h_unwrapped_key = c_unwrap_key(self.h_session, h_wrapping_key, wrapped_key, CKM_DES_UNWRAP_TEMP, CKM_DES_ECB)
        assert ret == CKR_OK, "Unwrapping the key should pass, instead it returns " + ret_vals_dictionary[ret]
        
        #Decrypt the data
        ret, decrypted_string = c_decrypt(self.h_session, CKM_DES_CBC, h_unwrapped_key, encrypted_data)
        assert ret == CKR_OK, "There should be no errors when decrypting, instead found " + ret_vals_dictionary[ret]
        assert decrypted_string == data_to_encrypt, "The decrypted data should be the same as the data that was encrypted. Instead found " + str(decrypted_string)
        

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-v', os.path.abspath(__file__)])  