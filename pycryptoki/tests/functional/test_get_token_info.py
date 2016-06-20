import logging
import os

import pytest

from . import config as hsm_config
from ...defaults import ADMIN_PARTITION_LABEL, ADMINISTRATOR_PASSWORD
from ...defines import CKF_TOKEN_PRESENT, CKF_LOGIN_REQUIRED, \
    CKF_RESTORE_KEY_NOT_NEEDED, CKF_TOKEN_INITIALIZED, CKF_SERIAL_SESSION, CKF_SO_SESSION, \
    CKF_RW_SESSION
from ...session_management import ca_factory_reset_ex, \
    c_get_token_info_ex, c_close_all_sessions, c_close_all_sessions_ex, \
    c_open_session_ex
from ...token_management import get_token_by_label_ex, c_init_token_ex

logger = logging.getLogger(__name__)


@pytest.yield_fixture(scope="class", autouse=True)
def reset_to_defaults():
    yield
    # Factory Reset
    slot = hsm_config['test_slot']

    c_close_all_sessions_ex(slot)
    ca_factory_reset_ex(slot)

    # Initialize the Admin Token
    session_flags = (CKF_SERIAL_SESSION | CKF_RW_SESSION | CKF_SO_SESSION)

    h_session = c_open_session_ex(slot, session_flags)
    c_init_token_ex(slot, hsm_config['admin_pwd'], ADMIN_PARTITION_LABEL)

    # TODO: change this for ppso hardware.
    # slot = get_token_by_label_ex(ADMIN_PARTITION_LABEL)
    # c_close_all_sessions_ex(slot)
    # h_session = c_open_session_ex(slot, session_flags)
    # login_ex(h_session, slot, ADMINISTRATOR_PASSWORD, 0)
    # c_init_pin_ex(h_session, CO_PASSWORD)
    # c_logout_ex(h_session)
    c_close_all_sessions_ex(slot)


@pytest.mark.skipif("config.getoption('user') != 'SO'")
class TestGetTokenInfo(object):
    """ """

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session
        self.admin_slot = hsm_config["test_slot"]

    def test_initial_flags(self):
        """ """
        admin_slot = self.admin_slot

        # Get to clean state
        c_close_all_sessions(admin_slot)
        ca_factory_reset_ex(admin_slot)

        # Look at flags before initialization
        flags = c_get_token_info_ex(admin_slot)['flags']
        expected_flags = CKF_TOKEN_PRESENT | CKF_LOGIN_REQUIRED | CKF_RESTORE_KEY_NOT_NEEDED
        assert expected_flags & flags != 0, "After factory reset found flags " + str(
            hex(flags)) + " on admin partition should match expected flags" + str(
            hex(expected_flags))

        c_init_token_ex(admin_slot, ADMINISTRATOR_PASSWORD, ADMIN_PARTITION_LABEL)

        # Test flags after initialization
        flags = c_get_token_info_ex(admin_slot)['flags']
        expected_flags = expected_flags | CKF_TOKEN_INITIALIZED
        assert flags & expected_flags != 0, "After initialization found flags " + str(
            hex(flags)) + " on admin partition should match expected flags" + str(
            hex(expected_flags))
        logger.info("After initialization found flags " + str(
            hex(flags)) + " on admin partition should match expected flags" + str(
            hex(expected_flags)))
