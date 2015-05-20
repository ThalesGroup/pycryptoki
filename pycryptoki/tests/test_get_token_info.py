import logging
import os

import pytest

from pycryptoki.defaults import ADMIN_PARTITION_LABEL, ADMINISTRATOR_PASSWORD
from pycryptoki.defines import CKF_TOKEN_PRESENT, CKF_LOGIN_REQUIRED, \
    CKF_RESTORE_KEY_NOT_NEEDED, CKF_TOKEN_INITIALIZED
from pycryptoki.session_management import c_finalize, ca_factory_reset_ex, \
    c_get_token_info_ex, c_close_all_sessions, c_initialize_ex
from pycryptoki.tests.setup_for_tests import setup_for_tests
from pycryptoki.token_management import get_token_by_label_ex, c_init_token_ex

logger = logging.getLogger(__name__)

class TestGetTokenInfo:
    """ """

    def setup(self):
        """ """
        setup_for_tests(True, False, False)
        c_initialize_ex()

    def teardown(self):
        """ """
        c_finalize()

    def test_initial_flags(self):
        """ """
        admin_slot = get_token_by_label_ex(ADMIN_PARTITION_LABEL)

        #Get to clean state
        c_close_all_sessions(admin_slot)
        ca_factory_reset_ex(admin_slot)

        #Look at flags before initialization
        flags = c_get_token_info_ex(admin_slot)['flags']
        expected_flags = CKF_TOKEN_PRESENT | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED
        assert flags == expected_flags, "After factory reset found flags " + str(hex(flags)) + " on admin partition should match expected flags"+ str(hex(expected_flags))

        c_init_token_ex(admin_slot, ADMINISTRATOR_PASSWORD, ADMIN_PARTITION_LABEL)

        #Test flags after initialization
        flags = c_get_token_info_ex(admin_slot)['flags']
        expected_flags = expected_flags | CKF_TOKEN_INITIALIZED
        assert flags == expected_flags, "After initialization found flags " + str(hex(flags)) + " on admin partition should match expected flags"+ str(hex(expected_flags))
        logger.info("After initialization found flags " + str(hex(flags)) + " on admin partition should match expected flags"+ str(hex(expected_flags)))

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-s', os.path.abspath(__file__)])

