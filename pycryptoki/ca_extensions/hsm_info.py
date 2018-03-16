"""
Methods responsible for retrieving hsm info from the K7 card
"""
import logging
from ctypes import c_ulong, byref, cast, POINTER
from pycryptoki.cryptoki import CA_GetNumberOfAllowedContainers, CA_RetrieveLicenseList
from pycryptoki.exceptions import make_error_handle_function
from pycryptoki.defines import CKR_OK

LOG = logging.getLogger(__name__)


def ca_retrieve_license_list(slot):
    """Gets the license info for a given slot id

    :param int slot_id: Slot index to get the license id's
    :returns: (A python list representing the license id's)
    :rtype: list
    """

    license_len = c_ulong()
    ret = CA_RetrieveLicenseList(slot, byref(license_len), None)
    if ret == CKR_OK:
        licenses = (c_ulong * license_len.value)()
        ret = CA_RetrieveLicenseList(slot, license_len, cast(licenses, POINTER(c_ulong)))
        LOG.info("Getting license id. slot=%s", slot)
        if ret != CKR_OK:
            return ret, []
    else:
        return ret, []
    return ret, [(licenses[x], licenses[x + 1]) for x in range(0, license_len.value, 2)]


ca_retrieve_license_list_ex = make_error_handle_function(ca_retrieve_license_list)


def ca_retrieve_allowed_containers(slot):
    """Gets the maximum allowed container number for a given slot id

    :param int slot_id: Slot index to get the maximum allowed container number
    :returns: (ret code, A unsigned integer representing the maximum allowed container number)
    :rtype: unsigned integer
    """

    allowed_partition_number = c_ulong()
    ret = CA_GetNumberOfAllowedContainers(slot, byref(allowed_partition_number))
    LOG.info("Getting allowed maximum container number. slot=%s", slot)
    return ret, allowed_partition_number

ca_retrieve_allowed_containers_ex = make_error_handle_function(ca_retrieve_allowed_containers)
