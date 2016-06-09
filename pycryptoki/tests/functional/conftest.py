"""
Fixtures for pycryptoki functional tests
"""
import os

import pytest

from . import config as hsm_config
from ...defaults import ADMINISTRATOR_PASSWORD, ADMIN_PARTITION_LABEL, CO_PASSWORD
from ...defines import CKF_RW_SESSION, CKF_SERIAL_SESSION, CKF_PROTECTED_AUTHENTICATION_PATH
from ...defines import CKF_SO_SESSION
from ...session_management import c_initialize_ex, c_close_all_sessions_ex, \
    ca_factory_reset_ex, c_open_session_ex, login_ex, c_finalize_ex, \
    c_close_session, c_logout, c_get_token_info_ex
from ...token_management import c_init_token_ex


def pytest_addoption(parser):
    """
    Set up some commandline options so we can specify what we want to test.
    """
    optiongroup = parser.getgroup("pycryptoki", "Pycryptoki test options")

    optiongroup.addoption("--slot",
                          help="Specify the admin slot of the HSM you are testing on",
                          type=int,
                          default=os.environ.get("ADMIN_SLOT", 1),
                          dest="test_slot")


def pytest_configure(config):
    """
    Set up the globals for this test run.
    """
    hsm_config["test_slot"] = config.getoption("test_slot")
    c_initialize_ex()
    try:
        # Factory Reset
        slot = hsm_config["test_slot"]

        token_info = c_get_token_info_ex(slot)
        flags = token_info['flags']
        is_ped = (flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0
        hsm_config["is_ped"] = is_ped

        if is_ped:
            admin_pwd = None
            co_pwd = None
        else:
            admin_pwd = ADMINISTRATOR_PASSWORD
            co_pwd = CO_PASSWORD
        hsm_config['admin_pwd'] = admin_pwd
        hsm_config['co_pwd'] = co_pwd
    finally:
        c_finalize_ex()


@pytest.yield_fixture(scope='session', autouse=True)
def hsm_configured():
    """
    Factory reset & init the hsm.
    """
    c_initialize_ex()
    try:
        slot = hsm_config["test_slot"]
        c_close_all_sessions_ex(slot)
        ca_factory_reset_ex(slot)

        # Initialize the Admin Token
        session_flags = (CKF_SERIAL_SESSION | CKF_RW_SESSION | CKF_SO_SESSION)

        _ = c_open_session_ex(slot, session_flags)
        c_init_token_ex(slot, hsm_config['admin_pwd'], ADMIN_PARTITION_LABEL)

        # TODO: This will need to change for testing on CO slots.
        # In the meantime, we test on the admin slot just fine.
        # slot = get_token_by_label_ex(ADMIN_PARTITION_LABEL)
        # c_close_all_sessions_ex(slot)
        # h_session = c_open_session_ex(slot, session_flags)
        # login_ex(h_session, slot, hsm_config['admin_pwd'], 0)
        # c_init_pin_ex(h_session, hsm_config['co_pwd'])
        # c_logout_ex(h_session)
        c_close_all_sessions_ex(slot)
        yield
    finally:
        c_finalize_ex()


@pytest.yield_fixture(scope="class")
def session(hsm_configured):
    """
    Creates & returns a session on the Admin slot.
    """
    _ = hsm_configured
    session_flags = (CKF_SERIAL_SESSION | CKF_RW_SESSION | CKF_SO_SESSION)

    slot = hsm_config["test_slot"]
    h_session = c_open_session_ex(slot, session_flags)
    yield h_session
    c_close_session(slot)


@pytest.yield_fixture(scope="class")
def auth_session(session):
    """
    Logs into the created admin session
    """
    slot = hsm_config["test_slot"]
    login_ex(session, slot, hsm_config["admin_pwd"], 0)
    yield session
    c_logout(session)
