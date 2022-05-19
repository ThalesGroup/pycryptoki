"""
Fixtures for pycryptoki functional tests
"""
import logging
import os
import sys

import pytest

from . import config as hsm_config
from pycryptoki.attributes import Attributes
from pycryptoki.defaults import ADMINISTRATOR_PASSWORD, ADMIN_PARTITION_LABEL, CO_PASSWORD
from pycryptoki.defines import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_OK,
    CKF_SO_SESSION,
    CKF_PROTECTED_AUTHENTICATION_PATH,
)
from pycryptoki.key_generator import c_destroy_object
from pycryptoki.object_attr_lookup import c_find_objects_ex
from pycryptoki.session_management import (
    c_initialize_ex,
    c_close_all_sessions_ex,
    ca_factory_reset_ex,
    c_open_session_ex,
    login_ex,
    c_finalize_ex,
    c_close_session,
    c_logout,
    c_get_token_info_ex,
    get_firmware_version,
)
from pycryptoki.test_functions import LunaException
from pycryptoki.token_management import c_init_token_ex, c_get_mechanism_list_ex

LOG = logging.getLogger(__name__)


def pytest_addoption(parser):
    """
    Set up some commandline options so we can specify what we want to test.
    """
    optiongroup = parser.getgroup("pycryptoki", "Pycryptoki test options")

    optiongroup.addoption(
        "--slot",
        help="Specify the slot you are testing on (Can be Admin or " "User slot)",
        type=int,
        default=os.environ.get("SLOT", 1),
        dest="test_slot",
    )
    optiongroup.addoption(
        "--clo-slot",
        help="Specify the slot as the target cloning slot",
        type=int,
        default=os.environ.get("CLONE_SLOT", 2),
        dest="test_clone_slot",
        required=False,
    )
    optiongroup.addoption(
        "--reset",
        help="Reset the HSM back to its default settings with a factory" " reset.",
        action="store_true",
        default=False,
    )
    optiongroup.addoption(
        "--password",
        help="Password for the Admin Slot. Can be None for PED-authentication " "devices.",
        action="store",
        type=str,
        default=ADMINISTRATOR_PASSWORD,
    )
    optiongroup.addoption(
        "--copassword",
        help="Password for the Crypto Officer user/slot. Can be None for " "PED-authentication.",
        action="store",
        type=str,
    )
    optiongroup.addoption(
        "--user",
        help="User type to test with. Defaults to SO. Can also test w/ " "Crypto Officer",
        choices=["SO", "CO"],
        default="SO",
        action="store",
    )
    optiongroup.addoption(
        "--loglevel",
        help="Specify what level of logging to run the tests ",
        choices=["debug", "info", "warning", "error"],
        default="warning",
    )


def pytest_configure(config):
    """
    Set up the globals for this test run.
    """
    if config.getoption("loglevel", None):
        logger = logging.getLogger()
        log_formatter = logging.Formatter("%(asctime)s:%(name)s:%(levelname)s: %(message)s")
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(log_formatter)
        logger.addHandler(console_handler)
        logger.setLevel(config.getoption("loglevel").upper())

    hsm_config["test_slot"] = config.getoption("test_slot")
    hsm_config["test_clone_slot"] = config.getoption("test_clone_slot")
    hsm_config["user"] = config.getoption("user")
    hsm_config["reset"] = config.getoption("reset")

    if config.getoption("--collect-only"):
        # Break early
        hsm_config["is_ped"] = False
        # Used so you can verify collection on multiple FW versions
        hsm_config["firmware"] = os.environ.get("FIRMWARE", "7.0.0")
        return

    c_initialize_ex()
    try:
        # Factory Reset
        slot = hsm_config["test_slot"]

        token_info = c_get_token_info_ex(slot)
        flags = token_info["flags"]
        is_ped = (flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0
        hsm_config["is_ped"] = is_ped
        hsm_config["firmware"] = get_firmware_version(slot)
        if is_ped:
            admin_pwd = None
            co_pwd = config.getoption("copassword", default=None)
        else:
            admin_pwd = config.getoption("password")
            co_pwd = config.getoption("copassword", default=CO_PASSWORD)

        if admin_pwd:
            admin_pwd = admin_pwd
        if co_pwd:
            co_pwd = co_pwd

        hsm_config["admin_pwd"] = admin_pwd
        hsm_config["co_pwd"] = co_pwd

        if config.getoption("user") == "CO":
            hsm_config["password"] = co_pwd
        else:
            hsm_config["password"] = admin_pwd
    finally:
        c_finalize_ex()


def pytest_collection_modifyitems(session, config, items):
    """
    Deselect tests marked with @pytest.mark.reset if --reset isn't given on cmdline.
    """
    reset = config.getoption("reset")
    for test_item in items[:]:
        if test_item.get_closest_marker("reset") and not reset:
            items.remove(test_item)


@pytest.fixture(scope="session", autouse=True)
def hsm_configured(pytestconfig):
    """
    Factory reset & init the hsm.
    """
    c_initialize_ex()
    try:
        if pytestconfig.getoption("reset"):
            slot = hsm_config["test_slot"]
            c_close_all_sessions_ex(slot)
            ca_factory_reset_ex(slot)

            # Initialize the Admin Token
            session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION | CKF_SO_SESSION

            _ = c_open_session_ex(slot, session_flags)
            c_init_token_ex(slot, hsm_config["admin_pwd"], ADMIN_PARTITION_LABEL)

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


@pytest.fixture(scope="class")
def session(pytestconfig, hsm_configured):
    """
    Creates & returns a session on the Admin slot.
    """
    _ = hsm_configured
    session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
    if pytestconfig.getoption("user") == "SO":
        session_flags = session_flags | CKF_SO_SESSION

    slot = hsm_config["test_slot"]
    h_session = c_open_session_ex(slot, session_flags)
    yield h_session
    c_close_session(slot)


@pytest.fixture(scope="class")
def auth_session(pytestconfig, session):
    """
    Logs into the created admin session
    """
    slot = hsm_config["test_slot"]
    usertype = 0 if pytestconfig.getoption("user") == "SO" else 1
    login_ex(session, slot, hsm_config["password"], usertype)
    yield session
    c_logout(session)


@pytest.fixture(scope="class")
def valid_mechanisms():
    """
    Fixture that will query the active slot to get a list of valid mechanisms.
    This can be used for assertions across FW versions/configurations. Note, this ends up being
    just a list of constants, but it should match up w/ what you're using from `pycryptoki.defines`.

    :return: list of integers, each corresponding to a mechanism.
    """
    raw_mechs = c_get_mechanism_list_ex(slot=hsm_config["test_slot"])
    yield raw_mechs
