from pycryptoki.defaults import ADMIN_PARTITION_LABEL, CO_PASSWORD
from pycryptoki.defines import CKU_USER, CKM_MD2, CKR_OK
from pycryptoki.encryption import _get_string_from_list
from pycryptoki.misc import c_digest
from pycryptoki.session_management import c_finalize_ex, c_open_session_ex, \
    login_ex, c_logout_ex, c_close_session_ex, c_initialize_ex
from pycryptoki.tests.setup_for_tests import setup_for_tests
from pycryptoki.token_management import get_token_by_label_ex
import logging
import os
import pytest

logger = logging.getLogger(__name__)

class TestDigestData():
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

    def test_digest_data(self):
        '''
        Calls C_Digest on some data and makes sure there is no failure
        '''
        data_to_digest = "Some arbitrary string"
        ret, digested_data = c_digest(self.h_session, data_to_digest, CKM_MD2)
        assert ret == CKR_OK, "Digesting should occur with no errors"
        assert len(digested_data) > 0, "The digested data should have a length"
        assert data_to_digest != digested_data, "The digested data should not be the same as the original string"
    
    def test_multipart_digest_data(self):
        data_to_digest = ["Some arbitrary string", "Some second arbitrary string"]
        ret, digested_data = c_digest(self.h_session, data_to_digest, CKM_MD2)
        assert ret == CKR_OK, "Digesting should occur with no errors"
        assert len(digested_data) > 0, "The digested data should have a length"
        assert _get_string_from_list(data_to_digest) != digested_data, "The digested data should not be the same as the original string"
    
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-vs', os.path.abspath(__file__)])  