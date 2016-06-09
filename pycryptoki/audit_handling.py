"""
Methods responsible for managing a user's session and login/c_logout
"""
import logging
from ctypes import cast, c_ulong, byref

from cryptoki import CK_ULONG, CA_TimeSync, CA_InitAudit, CK_SLOT_ID, CA_GetTime, CK_CHAR_PTR
from .test_functions import make_error_handle_function

logger = logging.getLogger(__name__)


def ca_init_audit(slot, audit_pin, audit_label):
    """

    :param slot:
    :param audit_pin:
    :param audit_label:

    """
    if audit_pin == '':
        ret = CA_InitAudit(CK_SLOT_ID(slot), None, CK_ULONG(0), cast(audit_label, CK_CHAR_PTR))
    else:
        ret = CA_InitAudit(CK_SLOT_ID(slot), cast(audit_pin, CK_CHAR_PTR), CK_ULONG(len(audit_pin)),
                           cast(audit_label, CK_CHAR_PTR))
    return ret


ca_init_audit_ex = make_error_handle_function(ca_init_audit)


def ca_time_sync(h_session, ultime):
    """

    :param h_session:
    :param ultime:

    """

    ret = CA_TimeSync(h_session, CK_ULONG(ultime))
    return ret


ca_time_sync_ex = make_error_handle_function(ca_time_sync)


def ca_get_time(h_session):
    """

    :param h_session:

    """

    hsm_time = c_ulong()

    ret = CA_GetTime(h_session, byref(hsm_time))
    return ret, hsm_time


ca_get_time_ex = make_error_handle_function(ca_get_time)
