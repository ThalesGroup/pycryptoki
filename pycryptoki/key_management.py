"""
Methods responsible for key management
"""
from .cryptoki import CA_GenerateMofN, CA_ModifyUsageCount, \
    CK_VOID_PTR, CK_ULONG, CA_MOFN_GENERATION, CK_BYTE, CA_MOFN_GENERATION_PTR
from .exceptions import make_error_handle_function


def ca_generatemofn(h_session,
                    m_value,
                    vector_value,
                    vector_count,
                    is_secure_port_used):
    """Generates MofN secret information on a token.

    :param int h_session: Session handle
    :param m_value: m
    :param vector_count: number of vectors
    :param is_secure_port_used: is secure port used
    :param vector_value:
    :returns: the result code

    """
    reserved = CK_VOID_PTR(0)

    m_value = CK_ULONG(m_value)
    vector_count = CK_ULONG(vector_count)
    is_secure_port_used = CK_ULONG(is_secure_port_used)

    vector_value = (CK_BYTE * vector_value)()
    vector = (CA_MOFN_GENERATION * 2)()
    vector[0].ulWeight = CK_ULONG(1)
    vector[0].pVector = vector_value
    vector[0].ulVectorLen = CK_ULONG(16)
    vector[1].ulWeight = CK_ULONG(1)
    vector[1].pVector = (CK_BYTE * 16)()
    vector[1].ulVectorLen = CK_ULONG(16)
    vectors = CA_MOFN_GENERATION_PTR(vector)

    ret = CA_GenerateMofN(h_session,
                          m_value,
                          vectors,
                          vector_count,
                          is_secure_port_used,
                          reserved)
    return ret


ca_generatemofn_ex = make_error_handle_function(ca_generatemofn)


def ca_modifyusagecount(h_session, h_object, command_type, value):
    """Modifies CKA_USAGE_COUNT attribute of the object.

    :param int h_session: Session handle
    :param h_object: object
    :param command_type: command type
    :param value: value
    :returns: the result code

    """
    ret = CA_ModifyUsageCount(h_session, h_object, command_type, CK_ULONG(value))
    return ret


ca_modifyusagecount_ex = make_error_handle_function(ca_modifyusagecount)
