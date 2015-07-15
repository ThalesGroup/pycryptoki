"""
Created on Aug 24, 2012

@author: mhughes
"""
from ctypes import byref, cast, create_string_buffer
import logging

# Cryptoki Constants
from pycryptoki.cryptoki import (CK_ULONG,
                                 CK_CHAR_PTR,
                                 CK_BBOOL,
                                 CK_SLOT_ID,
                                 CK_MECHANISM_TYPE,
                                 CK_MECHANISM_TYPE_PTR,
                                 CK_MECHANISM_INFO)
from pycryptoki.defaults import ADMIN_PARTITION_LABEL, ADMIN_SLOT
from pycryptoki.defines import CKR_OK


# Cryptoki functions.
from pycryptoki.cryptoki import (C_InitToken,
                                 C_GetSlotList,
                                 C_GetMechanismList,
                                 C_GetMechanismInfo,
                                 CA_GetHSMCapabilitySet,
                                 CA_GetHSMPolicySet)
from pycryptoki.session_management import c_get_token_info
from pycryptoki.test_functions import make_error_handle_function

logger = logging.getLogger(__name__)


def c_init_token(slot_num, password, token_label='Main Token'):
    """Initializes at token at a given slot with the proper password and label

    :param slot_num: The index of the slot to c_initialize a token in
    :param password: The password to c_initialize the slot with
    :param token_label: The label to c_initialize the slot with (Default value = 'Main Token')
    :returns: The result code

    """
    if password == '':
        logger.info("C_InitToken: Initializing token. slot=" + str(
            slot_num) + ", label='" + token_label + "', password='" + password + "'")
        ret = C_InitToken(CK_ULONG(slot_num), None,
                          CK_ULONG(0), cast(create_string_buffer(token_label), CK_CHAR_PTR))
        return ret
    else:
        logger.info("C_InitToken: Initializing token. slot=" + str(
            slot_num) + ", label='" + token_label + "', password='" + password + "'")
        ret = C_InitToken(CK_ULONG(slot_num), cast(create_string_buffer(password), CK_CHAR_PTR),
                          CK_ULONG(len(password)),
                          cast(create_string_buffer(token_label), CK_CHAR_PTR))
        return ret


c_init_token_ex = make_error_handle_function(c_init_token)


def get_token_by_label(label):
    """Iterates through all the tokens and returns the first token that
    has a label that is identical to the one that is passed in

    :param label: The label of the token to search for
    :returns: The result code, The slot of the token

    """

    if label == ADMIN_PARTITION_LABEL:  # XXX the admin partition's label changes depending on
    # the boards state
        #        ret, slot_info = get_slot_info("Viper")
        #        return ret, slot_info.keys()[1]
        return CKR_OK, ADMIN_SLOT

    us_count = CK_ULONG(0)
    ret = C_GetSlotList(CK_BBOOL(1), None, byref(us_count))
    if ret != CKR_OK: return ret, None
    num_slots = us_count.value
    slot_list = (CK_SLOT_ID * num_slots)()
    ret = C_GetSlotList(CK_BBOOL(1), slot_list, byref(us_count))
    if ret != CKR_OK: return ret, None

    for slot in slot_list:
        ret, token_info = c_get_token_info(slot)
        if token_info['label'] == label:
            return ret, slot

    raise Exception("Slot with label " + str(label) + " not found.")


get_token_by_label_ex = make_error_handle_function(get_token_by_label)


def c_get_mechanism_list(slot):
    """Gets the list of mechanisms from the HSM

    :param slot: The slot number to get the mechanism list on
    :returns: The result code, A python dictionary representing the mechanism list

    """
    count = CK_ULONG()
    ret = C_GetMechanismList(CK_SLOT_ID(slot), None, byref(count))
    last_count = count
    if ret != CKR_OK: return ret, None
    mech_list = (CK_MECHANISM_TYPE * count.value)()
    ret = C_GetMechanismList(CK_SLOT_ID(slot), CK_MECHANISM_TYPE_PTR(mech_list), byref(count))
    if ret != CKR_OK: return ret, None
    if last_count != count: raise Exception(
        "Mechanism list count was not consistent between function calls")

    ret_list = []
    for i in range(0, count.value):
        ret_list.append(mech_list[i])
    return ret, ret_list


c_get_mechanism_list_ex = make_error_handle_function(c_get_mechanism_list)


def c_get_mechanism_info(slot, mechanism_type):
    """Gets a mechanism's info

    :param slot: The slot to query
    :param mechanism_type: The type of the mechanism to get the information for
    :returns: The result code, The mechanism info

    """
    mech_info = CK_MECHANISM_INFO()
    ret = C_GetMechanismInfo(CK_ULONG(slot), CK_MECHANISM_TYPE(mechanism_type), byref(mech_info))
    return ret, mech_info


c_get_mechanism_info_ex = make_error_handle_function(c_get_mechanism_info)


def ca_get_hsm_capability_set(slot):
    """
    Get the capabilities of the given slot.

    :param int slot: Target slot number
    :return: retcode, {id: val} dict of policies (None if command failed)
    """
    slot_id = CK_ULONG(slot)
    cap_id_count = CK_ULONG()
    cap_val_count = CK_ULONG()
    ret = CA_GetHSMCapabilitySet(slot_id, None, byref(cap_id_count),
                                 None, byref(cap_val_count))
    if ret != CKR_OK:
        return ret, None

    c_cap_ids = (CK_ULONG * cap_id_count.value)()
    c_cap_vals = (CK_ULONG * cap_val_count.value)()
    ret = CA_GetHSMCapabilitySet(slot_id, c_cap_ids, byref(cap_id_count),
                                 c_cap_vals, byref(cap_val_count))

    if ret != CKR_OK:
        return ret, None

    return ret, dict(zip(c_cap_ids, c_cap_vals))


ca_get_hsm_capability_set_ex = make_error_handle_function(ca_get_hsm_capability_set)


def ca_get_hsm_policy_set(slot):
    """
    Get the policies of the given slot.

    :param int slot: Target slot number
    :return: retcode, {id: val} dict of policies (None if command failed)
    """
    slot_id = CK_ULONG(slot)
    cap_id_count = CK_ULONG()
    cap_val_count = CK_ULONG()
    ret = CA_GetHSMPolicySet(slot_id, None, byref(cap_id_count),
                             None, byref(cap_val_count))
    if ret != CKR_OK:
        return ret, None

    c_cap_ids = (CK_ULONG * cap_id_count.value)()
    c_cap_vals = (CK_ULONG * cap_val_count.value)()
    ret = CA_GetHSMPolicySet(slot_id, c_cap_ids, byref(cap_id_count),
                             c_cap_vals, byref(cap_val_count))

    if ret != CKR_OK:
        return ret, None

    return ret, dict(zip(c_cap_ids, c_cap_vals))


ca_get_hsm_policy_set_ex = make_error_handle_function(ca_get_hsm_policy_set)
