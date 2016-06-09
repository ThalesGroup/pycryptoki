"""
Methods responsible for key usage
"""
from .cryptoki import CA_CloneMofN, CA_DuplicateMofN, \
    CK_VOID_PTR, CK_SESSION_HANDLE
from .test_functions import make_error_handle_function


def ca_clonemofn(h_session):
    """Clones MofN secret from one token to another.

    :param h_session: the current session
    :returns: the result code

    """
    h_primary_session = CK_SESSION_HANDLE(0)
    reserved = CK_VOID_PTR(0)

    ret = CA_CloneMofN(h_session, h_primary_session, reserved)
    return ret


ca_clonemofn_ex = make_error_handle_function(ca_clonemofn)


def ca_duplicatemofn(h_session):
    """Duplicates a set of M of N vectors.

    :param h_session: the current session
    :returns: the result code

    """
    ret = CA_DuplicateMofN(h_session)
    return ret


ca_duplicatemofn_ex = make_error_handle_function(ca_duplicatemofn)
