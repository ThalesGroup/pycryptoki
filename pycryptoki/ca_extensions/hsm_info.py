"""
Methods responsible for retrieving hsm info from the K7 card
"""
import logging
from ctypes import c_ulong, byref, cast, POINTER
from pycryptoki.cryptoki import (
    CK_ULONG,
    CA_GetNumberOfAllowedContainers,
    CA_RetrieveLicenseList,
    CA_GetHSMStorageInformation,
    CA_GetTSV,
    CA_GetCVFirmwareVersion,
)
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


def ca_retrieve_hsm_storage_info(slot):
    """Gets the hsm storage info for a given slot id

    :param int slot_id: Slot index to get the hsm storage info
    :returns: (ret code, hsm_storage_info dictionary)
    :rtype: dictionary
    """

    hsm_storage_info = {}

    container_overhead = c_ulong()
    total_hsm_storage = c_ulong()
    used_hsm_storage = c_ulong()
    free_hsm_storage = c_ulong()
    ret = CA_GetHSMStorageInformation(
        slot,
        byref(container_overhead),
        byref(total_hsm_storage),
        byref(used_hsm_storage),
        byref(free_hsm_storage),
    )
    LOG.info("Getting allowed maximum container number. slot=%s", slot)

    if ret == CKR_OK:
        hsm_storage_info["ContainerOverhead"] = container_overhead
        hsm_storage_info["TotalHsmStorage"] = total_hsm_storage
        hsm_storage_info["UsedHsmStorage"] = used_hsm_storage
        hsm_storage_info["FreeHsmStorage"] = free_hsm_storage
    return ret, hsm_storage_info


ca_retrieve_hsm_storage_info_ex = make_error_handle_function(ca_retrieve_hsm_storage_info)


def ca_get_tsv(slot):
    """Get the TSV(Module State Vector) for a given slot id

    :param int slot_id: Slot index to get the TSV(Module State Vector)
    :returns: (ret code, TSV)
    :rtype: tuple
    """

    tsv = c_ulong()
    ret = CA_GetTSV(slot, byref(tsv))
    LOG.info("Getting Module state vector. slot=%s", slot)
    return ret, tsv


ca_get_tsv_ex = make_error_handle_function(ca_get_tsv)


def ca_get_cv_firmware_version(slot_id):
    """
    Cryptovisor specific ca extension function to get cv fw version

    :param slot_id: slot id
    :return: tuple of return code and cv fw version
    """
    major = CK_ULONG()
    minor = CK_ULONG()
    sub_minor = CK_ULONG()
    ret = CA_GetCVFirmwareVersion(CK_ULONG(slot_id), byref(major), byref(minor), byref(sub_minor))
    if ret != CKR_OK:
        return ret, None
    cv_fwv = {}
    cv_fwv["major"] = major.value
    cv_fwv["minor"] = minor.value
    cv_fwv["sub_minor"] = sub_minor.value

    return ret, cv_fwv


ca_get_cv_firmware_version_ex = make_error_handle_function(ca_get_cv_firmware_version)
