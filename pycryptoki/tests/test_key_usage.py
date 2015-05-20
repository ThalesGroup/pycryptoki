"""
Test methods for pycryptoki 'hsm usage' set of commands.
"""
from pycryptoki.defaults import ADMIN_PARTITION_LABEL, CO_PASSWORD
from pycryptoki.defines import CKU_USER, CKR_SESSION_HANDLE_INVALID, \
    CKR_USER_NOT_AUTHORIZED
from pycryptoki.return_values import ret_vals_dictionary
from pycryptoki.session_management import c_finalize_ex, c_open_session_ex, \
    login_ex, c_logout_ex, c_close_session_ex, c_initialize_ex
from pycryptoki.tests.setup_for_tests import setup_for_tests
from pycryptoki.token_management import get_token_by_label_ex
from pycryptoki.key_usage import ca_clonemofn, ca_duplicatemofn
import logging
import os
import pytest

class TestAlgorithm:
    """Test algorithm class"""
    h_session = 0
    admin_slot = 0

    @classmethod
    def setup_class(cls):
        """Setup class"""
        setup_for_tests(True, True, True)
        c_initialize_ex()

    @classmethod
    def teardown_class(cls):
        """Finalize tests"""
        c_finalize_ex()

    def setup(self):
        """Setup test"""
        self.admin_slot = get_token_by_label_ex(ADMIN_PARTITION_LABEL)
        self.h_session = c_open_session_ex(slot_num=self.admin_slot)
        login_ex(self.h_session, self.admin_slot, CO_PASSWORD, CKU_USER)

    def teardown(self):
        """Teardown test"""
        c_logout_ex(self.h_session)
        c_close_session_ex(self.h_session)


    def test_clonemofn(self):
        """Test clone M of N"""
        ret = ca_clonemofn(self.h_session)
        assert ret == CKR_SESSION_HANDLE_INVALID, \
            "Return code should be " + \
            ret_vals_dictionary[CKR_SESSION_HANDLE_INVALID] + \
            " not " + ret_vals_dictionary[ret]


    def test_duplicatemofn(self):
        """Test duplicate M of N"""
        ret = ca_duplicatemofn(self.h_session)
        assert ret == CKR_USER_NOT_AUTHORIZED, \
            "Return code should be " + \
            ret_vals_dictionary[CKR_USER_NOT_AUTHORIZED] + \
            " not " + ret_vals_dictionary[ret]


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-v', os.path.abspath(__file__)])
