from pycryptoki.defaults import ADMIN_PARTITION_LABEL, CO_PASSWORD
from pycryptoki.defines import CKU_USER, CKR_OK
from pycryptoki.misc import c_generate_random_ex, c_seed_random, \
    c_generate_random
from pycryptoki.return_values import ret_vals_dictionary
from pycryptoki.session_management import c_finalize_ex, c_open_session_ex, \
    login_ex, c_logout_ex, c_close_session_ex, c_initialize_ex
from pycryptoki.tests.setup_for_tests import setup_for_tests
from pycryptoki.token_management import get_token_by_label_ex
import logging
import os
import pytest

logger = logging.getLogger(__name__)

class TestSupportingOperations():
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

    def test_rng(self):
        '''
        Tests generating a random number
        '''
        length = 15
        ret, random_string = c_generate_random(self.h_session, length)
        assert ret == CKR_OK, "C_GenerateRandom should return CKR_OK, instead it returned " + ret_vals_dictionary[ret]
        assert len(random_string) == length, "The length of the random string should be the same as the length of the requested data."
    
    def test_seeded_rng(self):
        '''
        Tests that seeding the random number generator with the same data will
        generate the same random number
        '''
        seed = "k" * 1024
        ret = c_seed_random(self.h_session, seed)
        assert ret == CKR_OK, "Seeding the random number generator shouldn't return an error, it returned " + ret_vals_dictionary[ret]
        
        random_string_one = c_generate_random_ex(self.h_session, 10)
        
        ret = c_seed_random(self.h_session, seed)
        assert ret == CKR_OK, "Seeding the random number generator a second time shouldn't return an error, it returned " + ret_vals_dictionary[ret]
        
        random_string_two = c_generate_random_ex(self.h_session, 10)
        
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-vs', os.path.abspath(__file__)])  