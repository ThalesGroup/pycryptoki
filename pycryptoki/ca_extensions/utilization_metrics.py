"""
Module to work with utilization metrics
"""
import collections
from ctypes import c_ulong
from pycryptoki.cryptoki import (
    CA_ReadUtilizationMetrics,
    CA_ReadAllUtilizationCounters,
    CA_ReadAndResetUtilizationMetrics,
)
from pycryptoki.cryptoki import CK_UTILIZATION_COUNTER
from pycryptoki.cryptoki import CK_SESSION_HANDLE
from pycryptoki.exceptions import make_error_handle_function

BIN_IDS = {
    0: "SIGN",
    1: "VERIFY",
    2: "ENCRYPT",
    3: "DECRYPT",
    4: "KEY_GENERATION",
    5: "KEY_DERIVATION",
}


def ca_read_utilization_metrics(session):
    """
    HSM reads utilization data and saves as a snapshot

    :param session: session id that was opened to run the function
    :return: Ret code
    """
    h_session = CK_SESSION_HANDLE(session)
    return CA_ReadUtilizationMetrics(h_session)


ca_read_utilization_metrics_ex = make_error_handle_function(ca_read_utilization_metrics)


def ca_read_and_reset_utilization_metrics(session):
    """
    HSM reads current utilization data and saves as a snapshot;
    HSM resets metrics to zeroes

    :param session: session id that was opened to run the function
    :return: a dictionary with partition serial numbers as keys,
            value - dictionary of utilization metrics
    """
    h_session = CK_SESSION_HANDLE(session)

    return CA_ReadAndResetUtilizationMetrics(h_session)


ca_read_and_reset_utilization_metrics_ex = make_error_handle_function(
    ca_read_and_reset_utilization_metrics
)


def ca_read_all_utilization_counters(h_session):
    """
        Read Metrics from previously saved HSM snapshot
        Call either functions prior to create snapshot:
        ca_read_utilization_metrics
        ca_read_and_reset_utilization_metrics

        :return: a dictionary, where keys are serial numbers
        and values are dictionaries of bins and values, example: 'SIGN':0
    """
    # Reading length of counters
    length = c_ulong()
    CA_ReadAllUtilizationCounters(h_session, None, length)

    arr = (CK_UTILIZATION_COUNTER * length.value)()
    # Reading actual Metrics
    ret = CA_ReadAllUtilizationCounters(h_session, arr, length)

    # HSM returns a list of dictionaries of all counters
    # Restructuting this list as a dictionary
    partitions = collections.defaultdict(dict)
    for counter in arr:
        partitions[str(counter.ullSerialNumber)][BIN_IDS[counter.ulBindId]] = counter.ullCount

    return ret, partitions


ca_read_all_utilization_counters_ex = make_error_handle_function(ca_read_all_utilization_counters)
