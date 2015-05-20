"""
Created on Sep 18, 2012

@author: mhughes
"""
from pycryptoki.defaults import ADMIN_PARTITION_LABEL, ADMINISTRATOR_PASSWORD, \
    CO_PASSWORD
from pycryptoki.defines import CKF_SERIAL_SESSION, CKF_RW_SESSION, \
    CKF_SO_SESSION
from pycryptoki.session_management import ca_factory_reset_ex, c_open_session_ex, \
    c_close_all_sessions_ex, login_ex, c_init_pin_ex, c_logout_ex, c_initialize_ex, \
    c_finalize_ex
from pycryptoki.token_management import get_token_by_label_ex, c_init_token_ex
import logging

logger = logging.getLogger(__name__)

def setup_for_tests(should_factory_reset, initialize_admin_token, initialize_users):
    """

    :param should_factory_reset:
    :param initialize_admin_token:
    :param initialize_users:

    """
    c_initialize_ex()

    #Factory Reset
    slot = get_token_by_label_ex(ADMIN_PARTITION_LABEL)
    if should_factory_reset:
        c_close_all_sessions_ex(slot)
        ca_factory_reset_ex(slot)

    #Initialize the Admin Token
    session_flags = (CKF_SERIAL_SESSION | CKF_RW_SESSION | CKF_SO_SESSION)
    if initialize_admin_token:
        h_session = c_open_session_ex(slot, session_flags)
        c_init_token_ex(slot, ADMINISTRATOR_PASSWORD, ADMIN_PARTITION_LABEL)


    if initialize_users and initialize_admin_token:
        slot = get_token_by_label_ex(ADMIN_PARTITION_LABEL)
        c_close_all_sessions_ex(slot)
        h_session = c_open_session_ex(slot, session_flags)
        login_ex(h_session, slot, ADMINISTRATOR_PASSWORD, 0)
        c_init_pin_ex(h_session, CO_PASSWORD)
        c_logout_ex(h_session)
        c_close_all_sessions_ex(slot)

    c_finalize_ex()
