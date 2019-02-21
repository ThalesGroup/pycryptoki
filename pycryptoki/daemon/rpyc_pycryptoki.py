#!/usr/bin/env python -u
"""
RPYC-based daemon that allows for remote execution
of pycryptoki commands.

Start via ``./rpyc_pycryptoki.py -i <ip> -p <port>``
or ``python rpyc_pycryptoki.py -i <ip> -p <port>``

All methods starting with ``exposed_`` are useable via just
``rpyc_conn.<method>`` instead of ``rpyc_conn.exposed_<method>``

All methods ending with ``_ex`` will automatically check the return code from
cryptoki & raise an exception if it is not CKR_OK. It will *NOT* give you the return code, instead
just returning the second part of the regular return tuple::

    c_open_session()     # Returns: (ret_code, session_handle)
    c_open_session_ex()  # Returns: session_handle, raises exception if ret_code != CKR_OK

"""
from __future__ import print_function

import multiprocessing
import os
import signal
import sys
import time
from argparse import ArgumentParser
from logging.handlers import RotatingFileHandler

import rpyc
from rpyc.utils.server import ThreadedServer

import pycryptoki
from pycryptoki.attributes import *
from pycryptoki.audit_handling import (ca_get_time, ca_get_time_ex,
                                       ca_init_audit, ca_init_audit_ex,
                                       ca_time_sync, ca_time_sync_ex)
from pycryptoki.backup import (ca_open_secure_token, ca_open_secure_token_ex,
                               ca_close_secure_token, ca_close_secure_token_ex,
                               ca_extract, ca_extract_ex,
                               ca_insert, ca_insert_ex, ca_sim_insert, ca_sim_insert_ex,
                               ca_sim_extract_ex, ca_sim_extract, ca_sim_multisign,
                               ca_sim_multisign_ex)
from pycryptoki.ca_extensions.derive_wrap import ca_derive_key_and_wrap, ca_derive_key_and_wrap_ex
from pycryptoki.ca_extensions.session import ca_get_session_info, ca_get_session_info_ex
from pycryptoki.ca_extensions.object_handler import ca_destroy_multiple_objects, \
    ca_destroy_multiple_objects_ex, ca_get_object_handle, ca_get_object_handle_ex
from pycryptoki.cryptoki import CK_ULONG
from pycryptoki.encryption import (c_encrypt, c_encrypt_ex,
                                   c_decrypt, c_decrypt_ex,
                                   c_wrap_key, c_wrap_key_ex,
                                   c_unwrap_key, c_unwrap_key_ex)
from pycryptoki.hsm_management import (c_performselftest, c_performselftest_ex,
                                       ca_settokencertificatesignature,
                                       ca_settokencertificatesignature_ex,
                                       ca_hainit, ca_hainit_ex,
                                       ca_createloginchallenge, ca_createloginchallenge_ex,
                                       ca_initializeremotepedvector,
                                       ca_initializeremotepedvector_ex,
                                       ca_deleteremotepedvector, ca_deleteremotepedvector_ex,
                                       ca_mtkrestore, ca_mtkrestore_ex,
                                       ca_mtkresplit, ca_mtkresplit_ex,
                                       ca_mtkzeroize, ca_mtkzeroize_ex, ca_set_hsm_policy,
                                       ca_set_hsm_policy_ex, ca_set_destructive_hsm_policy,
                                       ca_set_destructive_hsm_policy_ex, ca_get_hsm_capability_set,
                                       ca_get_hsm_capability_set_ex, ca_get_hsm_policy_set,
                                       ca_get_hsm_policy_set_ex, ca_get_hsm_policy_setting,
                                       ca_get_hsm_policy_setting_ex, ca_get_hsm_capability_setting,
                                       ca_get_hsm_capability_setting_ex, ca_set_hsm_policies,
                                       ca_set_hsm_policies_ex, ca_set_destructive_hsm_policies,
                                       ca_set_destructive_hsm_policies_ex)
from pycryptoki.ca_extensions.utilization_metrics \
                                        import (ca_read_all_utilization_counters,
                                                ca_read_all_utilization_counters_ex,
                                                ca_read_utilization_metrics,
                                                ca_read_utilization_metrics_ex,
                                                ca_read_and_reset_utilization_metrics,
                                                ca_read_and_reset_utilization_metrics_ex)
from pycryptoki.ca_extensions.per_key_auth import (ca_set_authorization_data,
                                                   ca_set_authorization_data_ex,
                                                   ca_authorize_key,
                                                   ca_authorize_key_ex)
from pycryptoki.key_generator import (c_destroy_object, c_destroy_object_ex,
                                      c_generate_key_pair, c_generate_key_pair_ex,
                                      c_generate_key, c_generate_key_ex,
                                      c_derive_key, c_derive_key_ex,
                                      c_copy_object_ex, c_copy_object)
from pycryptoki.key_management import (ca_generatemofn, ca_generatemofn_ex,
                                       ca_modifyusagecount, ca_modifyusagecount_ex)
from pycryptoki.key_usage import (ca_clonemofn, ca_clonemofn_ex,
                                  ca_duplicatemofn, ca_duplicatemofn_ex)
from pycryptoki.misc import (c_generate_random, c_generate_random_ex,
                             c_seed_random, c_seed_random_ex,
                             c_digest, c_digest_ex,
                             c_set_ped_id, c_set_ped_id_ex,
                             c_get_ped_id, c_get_ped_id_ex,
                             c_create_object, c_create_object_ex,
                             c_digestkey, c_digestkey_ex)
from pycryptoki.object_attr_lookup import (c_find_objects, c_find_objects_ex,
                                           c_get_attribute_value, c_get_attribute_value_ex,
                                           c_set_attribute_value, c_set_attribute_value_ex)
from pycryptoki.partition_management import (ca_create_container,
                                             ca_create_container_ex,
                                             ca_delete_container_with_handle_ex,
                                             ca_delete_container_with_handle,
                                             ca_set_container_policy,
                                             ca_set_container_policy_ex,
                                             ca_get_container_capability_set,
                                             ca_get_container_capability_set_ex,
                                             ca_get_container_capability_setting,
                                             ca_get_container_capability_setting_ex,
                                             ca_get_container_list,
                                             ca_get_container_list_ex,
                                             ca_get_container_name,
                                             ca_get_container_name_ex,
                                             ca_get_container_policy_set,
                                             ca_get_container_policy_set_ex,
                                             ca_get_container_policy_setting,
                                             ca_get_container_policy_setting_ex,
                                             ca_get_container_status,
                                             ca_get_container_status_ex,
                                             ca_get_container_storage_information,
                                             ca_get_container_storage_information_ex,
                                             ca_set_container_policies,
                                             ca_set_container_policies_ex,
                                             ca_set_container_size,
                                             ca_set_container_size_ex)
from pycryptoki.session_management import (c_initialize, c_initialize_ex,
                                           c_finalize, c_finalize_ex,
                                           c_open_session, c_open_session_ex,
                                           c_get_session_info, c_get_session_info_ex,
                                           c_get_token_info, c_get_token_info_ex,
                                           c_close_session, c_close_session_ex,
                                           c_logout, c_logout_ex,
                                           c_init_pin, c_init_pin_ex,
                                           ca_factory_reset, ca_factory_reset_ex,
                                           c_set_pin, c_set_pin_ex,
                                           c_close_all_sessions, c_close_all_sessions_ex,
                                           login, login_ex,
                                           ca_openapplicationID_ex, ca_openapplicationID,
                                           ca_closeapplicationID, ca_closeapplicationID_ex,
                                           ca_restart, ca_restart_ex,
                                           ca_setapplicationID, ca_setapplicationID_ex,
                                           c_get_slot_list, c_get_slot_list_ex,
                                           c_get_slot_info, c_get_slot_info_ex,
                                           c_get_info, c_get_info_ex)
from pycryptoki.sign_verify import (c_sign, c_sign_ex,
                                    c_verify, c_verify_ex)
from pycryptoki.token_management import (c_init_token, c_init_token_ex,
                                         c_get_mechanism_list, c_get_mechanism_list_ex,
                                         c_get_mechanism_info, c_get_mechanism_info_ex,
                                         get_token_by_label, get_token_by_label_ex,
                                         ca_get_token_policies_ex, ca_get_token_policies)

CRYPTO_OPS = pycryptoki.cryptoki.__all__[:]

MAX_LOG_SIZE = 5242880


class PycryptokiService(rpyc.SlaveService):
    """This is the core service to expose to the daemon.
    Add in a static method preceded by 'exposed\_' and it'll be visible to anything
    connecting to the daemon.

    If you're working with pointers, you'll need to create the pointer in a function here
    rather than passing in a pointer from the client (pointers getting pickled makes no sense).
    """

    def _rpyc_getattr(self, name):
        """Override RPYC's default getattr.

        The startswith exposed is rpyc's default.
        The pycryptoki.cryptoki.__all__ is an extension,
        as is the _ex bit.

        :param name:
        """
        if name.startswith("exposed_"):
            name = name
        elif name in CRYPTO_OPS:
            return getattr(pycryptoki.cryptoki, name)
        else:
            name = "exposed_" + name
        return getattr(self, name)

    # attribute transforms
    exposed_to_byte_array = staticmethod(to_byte_array)
    exposed_to_char_array = staticmethod(to_char_array)
    exposed_to_bool = staticmethod(to_bool)
    exposed_to_long = staticmethod(to_long)
    exposed_to_ck_date = staticmethod(to_ck_date)
    exposed_to_subattributes = staticmethod(to_sub_attributes)

    # encryption.py
    exposed_c_wrap_key = staticmethod(c_wrap_key)
    exposed_c_wrap_key_ex = staticmethod(c_wrap_key_ex)
    exposed_c_unwrap_key = staticmethod(c_unwrap_key)
    exposed_c_unwrap_key_ex = staticmethod(c_unwrap_key_ex)
    exposed_c_encrypt = staticmethod(c_encrypt)
    exposed_c_encrypt_ex = staticmethod(c_encrypt_ex)
    exposed_c_decrypt = staticmethod(c_decrypt)
    exposed_c_decrypt_ex = staticmethod(c_decrypt_ex)

    # sign_verify.py
    exposed_c_sign = staticmethod(c_sign)
    exposed_c_sign_ex = staticmethod(c_sign_ex)
    exposed_c_verify = staticmethod(c_verify)
    exposed_c_verify_ex = staticmethod(c_verify_ex)

    # token_management.py
    exposed_c_init_token = staticmethod(c_init_token)
    exposed_c_init_token_ex = staticmethod(c_init_token_ex)
    exposed_c_get_mechanism_list = staticmethod(c_get_mechanism_list)
    exposed_c_get_mechanism_list_ex = staticmethod(c_get_mechanism_list_ex)
    exposed_c_get_mechanism_info = staticmethod(c_get_mechanism_info)
    exposed_c_get_mechanism_info_ex = staticmethod(c_get_mechanism_info_ex)
    exposed_ca_get_token_policies = staticmethod(ca_get_token_policies)
    exposed_ca_get_token_policies_ex = staticmethod(ca_get_token_policies_ex)

    # session_management.py
    exposed_c_initialize = staticmethod(c_initialize)
    exposed_c_initialize_ex = staticmethod(c_initialize_ex)
    exposed_c_finalize = staticmethod(c_finalize)
    exposed_c_finalize_ex = staticmethod(c_finalize_ex)
    exposed_c_open_session = staticmethod(c_open_session)
    exposed_c_open_session_ex = staticmethod(c_open_session_ex)
    exposed_login = staticmethod(login)
    exposed_login_ex = staticmethod(login_ex)
    exposed_c_get_session_info = staticmethod(c_get_session_info)
    exposed_c_get_session_info_ex = staticmethod(c_get_session_info_ex)
    exposed_c_get_token_info = staticmethod(c_get_token_info)
    exposed_c_get_token_info_ex = staticmethod(c_get_token_info_ex)
    exposed_c_close_session = staticmethod(c_close_session)
    exposed_c_close_session_ex = staticmethod(c_close_session_ex)
    exposed_c_logout = staticmethod(c_logout)
    exposed_c_logout_ex = staticmethod(c_logout_ex)
    exposed_c_set_pin = staticmethod(c_set_pin)
    exposed_c_set_pin_ex = staticmethod(c_set_pin_ex)
    exposed_c_init_pin = staticmethod(c_init_pin)
    exposed_c_init_pin_ex = staticmethod(c_init_pin_ex)
    exposed_ca_factory_reset = staticmethod(ca_factory_reset)
    exposed_ca_factory_reset_ex = staticmethod(ca_factory_reset_ex)
    exposed_get_token_by_label = staticmethod(get_token_by_label)
    exposed_get_token_by_label_ex = staticmethod(get_token_by_label_ex)
    exposed_ca_close_secure_token = staticmethod(ca_close_secure_token)
    exposed_ca_close_secure_token_ex = staticmethod(ca_close_secure_token_ex)
    exposed_ca_open_secure_token = staticmethod(ca_open_secure_token)
    exposed_ca_open_secure_token_ex = staticmethod(ca_open_secure_token_ex)
    exposed_c_close_all_sessions = staticmethod(c_close_all_sessions)
    exposed_c_close_all_sessions_ex = staticmethod(c_close_all_sessions_ex)
    exposed_ca_openapplicationID_ex = staticmethod(ca_openapplicationID_ex)
    exposed_ca_openapplicationID = staticmethod(ca_openapplicationID)
    exposed_ca_closeapplicationID_ex = staticmethod(ca_closeapplicationID_ex)
    exposed_ca_closeapplicationID = staticmethod(ca_closeapplicationID)
    exposed_ca_setapplicationID_ex = staticmethod(ca_setapplicationID_ex)
    exposed_ca_setapplicationID = staticmethod(ca_setapplicationID)
    exposed_ca_restart_ex = staticmethod(ca_restart_ex)
    exposed_ca_restart = staticmethod(ca_restart)
    exposed_c_get_slot_list = staticmethod(c_get_slot_list)
    exposed_c_get_slot_list_ex = staticmethod(c_get_slot_list_ex)
    exposed_c_get_slot_info = staticmethod(c_get_slot_info)
    exposed_c_get_slot_info_ex = staticmethod(c_get_slot_info_ex)
    exposed_c_get_info = staticmethod(c_get_info)
    exposed_c_get_info_ex = staticmethod(c_get_info_ex)

    # object_attr_lookup.py
    exposed_c_find_objects = staticmethod(c_find_objects)
    exposed_c_find_objects_ex = staticmethod(c_find_objects_ex)
    exposed_c_get_attribute_value = staticmethod(c_get_attribute_value)
    exposed_c_get_attribute_value_ex = staticmethod(c_get_attribute_value_ex)
    exposed_c_set_attribute_value = staticmethod(c_set_attribute_value)
    exposed_c_set_attribute_value_ex = staticmethod(c_set_attribute_value_ex)

    # misc.py
    exposed_c_generate_random = staticmethod(c_generate_random)
    exposed_c_generate_random_ex = staticmethod(c_generate_random_ex)
    exposed_c_seed_random = staticmethod(c_seed_random)
    exposed_c_seed_random_ex = staticmethod(c_seed_random_ex)
    exposed_c_digest = staticmethod(c_digest)
    exposed_c_digest_ex = staticmethod(c_digest_ex)
    exposed_c_set_ped_id = staticmethod(c_set_ped_id)
    exposed_c_set_ped_id_ex = staticmethod(c_set_ped_id_ex)
    exposed_c_get_ped_id = staticmethod(c_get_ped_id)
    exposed_c_get_ped_id_ex = staticmethod(c_get_ped_id_ex)
    exposed_c_create_object = staticmethod(c_create_object)
    exposed_c_create_object_ex = staticmethod(c_create_object_ex)
    exposed_c_digest_key = staticmethod(c_digestkey)
    exposed_c_digest_key_ex = staticmethod(c_digestkey_ex)

    # key_generator.py
    exposed_c_generate_key = staticmethod(c_generate_key)
    exposed_c_generate_key_ex = staticmethod(c_generate_key_ex)
    exposed_c_generate_key_pair = staticmethod(c_generate_key_pair)
    exposed_c_generate_key_pair_ex = staticmethod(c_generate_key_pair_ex)
    exposed_c_destroy_object = staticmethod(c_destroy_object)
    exposed_c_destroy_object_ex = staticmethod(c_destroy_object_ex)
    exposed_c_copy_object = staticmethod(c_copy_object)
    exposed_c_copy_object_ex = staticmethod(c_copy_object_ex)

    # backup.py
    exposed_ca_extract = staticmethod(ca_extract)
    exposed_ca_extract_ex = staticmethod(ca_extract_ex)
    exposed_ca_insert = staticmethod(ca_insert)
    exposed_ca_insert_ex = staticmethod(ca_insert_ex)
    exposed_ca_sim_insert = staticmethod(ca_sim_insert)
    exposed_ca_sim_insert_ex = staticmethod(ca_sim_insert_ex)
    exposed_ca_sim_extract = staticmethod(ca_sim_extract)
    exposed_ca_sim_extract_ex = staticmethod(ca_sim_extract_ex)
    exposed_ca_sim_multisign = staticmethod(ca_sim_multisign)
    exposed_ca_sim_multisign_ex = staticmethod(ca_sim_multisign_ex)

    # audit_handling.py
    exposed_ca_get_time = staticmethod(ca_get_time)
    exposed_ca_get_time_ex = staticmethod(ca_get_time_ex)
    exposed_ca_init_audit = staticmethod(ca_init_audit)
    exposed_ca_init_audit_ex = staticmethod(ca_init_audit_ex)
    exposed_ca_time_sync = staticmethod(ca_time_sync)
    exposed_ca_time_sync_ex = staticmethod(ca_time_sync_ex)

    # hsm_management.py
    exposed_c_performselftest = staticmethod(c_performselftest)
    exposed_c_performselftest_ex = staticmethod(c_performselftest_ex)
    exposed_ca_settokencertificatesignature = staticmethod(ca_settokencertificatesignature)
    exposed_ca_settokencertificatesignature_ex = staticmethod(ca_settokencertificatesignature_ex)
    exposed_ca_hainit = staticmethod(ca_hainit)
    exposed_ca_hainit_ex = staticmethod(ca_hainit_ex)
    exposed_ca_createloginchallenge = staticmethod(ca_createloginchallenge)
    exposed_ca_createloginchallenge_ex = staticmethod(ca_createloginchallenge_ex)
    exposed_ca_initializeremotepedvector = staticmethod(ca_initializeremotepedvector)
    exposed_ca_initializeremotepedvector_ex = staticmethod(ca_initializeremotepedvector_ex)
    exposed_ca_deleteremotepedvector = staticmethod(ca_deleteremotepedvector)
    exposed_ca_deleteremotepedvector_ex = staticmethod(ca_deleteremotepedvector_ex)
    exposed_ca_mtkrestore = staticmethod(ca_mtkrestore)
    exposed_ca_mtkrestore_ex = staticmethod(ca_mtkrestore_ex)
    exposed_ca_mtkresplit = staticmethod(ca_mtkresplit)
    exposed_ca_mtkresplit_ex = staticmethod(ca_mtkresplit_ex)
    exposed_ca_mtkzeroize = staticmethod(ca_mtkzeroize)
    exposed_ca_mtkzeroize_ex = staticmethod(ca_mtkzeroize_ex)
    exposed_ca_get_hsm_policy_set = staticmethod(ca_get_hsm_policy_set)
    exposed_ca_get_hsm_policy_set_ex = staticmethod(ca_get_hsm_policy_set_ex)
    exposed_ca_get_hsm_capability_set = staticmethod(ca_get_hsm_capability_set)
    exposed_ca_get_hsm_capability_set_ex = staticmethod(ca_get_hsm_capability_set_ex)
    exposed_ca_get_hsm_policy_setting = staticmethod(ca_get_hsm_policy_setting)
    exposed_ca_get_hsm_policy_setting_ex = staticmethod(ca_get_hsm_policy_setting_ex)
    exposed_ca_get_hsm_capability_setting = staticmethod(ca_get_hsm_capability_setting)
    exposed_ca_get_hsm_capability_setting_ex = staticmethod(ca_get_hsm_capability_setting_ex)
    exposed_ca_set_hsm_policy = staticmethod(ca_set_hsm_policy)
    exposed_ca_set_hsm_policy_ex = staticmethod(ca_set_hsm_policy_ex)
    exposed_ca_set_destructive_hsm_policy = staticmethod(ca_set_destructive_hsm_policy)
    exposed_ca_set_destructive_hsm_policy_ex = staticmethod(ca_set_destructive_hsm_policy_ex)
    exposed_ca_set_hsm_policies = staticmethod(ca_set_hsm_policies)
    exposed_ca_set_hsm_policies_ex = staticmethod(ca_set_hsm_policies_ex)
    exposed_ca_set_destructive_hsm_policies = staticmethod(ca_set_destructive_hsm_policies)
    exposed_ca_set_destructive_hsm_policies_ex = staticmethod(ca_set_destructive_hsm_policies_ex)

    # partition_management.py
    exposed_ca_create_container = staticmethod(ca_create_container)
    exposed_ca_create_container_ex = staticmethod(ca_create_container_ex)
    exposed_ca_delete_container_with_handle = staticmethod(ca_delete_container_with_handle)
    exposed_ca_delete_container_with_handle_ex = staticmethod(ca_delete_container_with_handle_ex)
    exposed_ca_set_container_policy = staticmethod(ca_set_container_policy)
    exposed_ca_set_container_policy_ex = staticmethod(ca_set_container_policy_ex)
    exposed_ca_get_container_capability_set = staticmethod(ca_get_container_capability_set)
    exposed_ca_get_container_capability_set_ex = staticmethod(ca_get_container_capability_set_ex)
    exposed_ca_get_container_capability_setting = staticmethod(ca_get_container_capability_setting)
    exposed_ca_get_container_capability_setting_ex = staticmethod(
        ca_get_container_capability_setting_ex)
    exposed_ca_get_container_list = staticmethod(ca_get_container_list)
    exposed_ca_get_container_list_ex = staticmethod(ca_get_container_list_ex)
    exposed_ca_get_container_name = staticmethod(ca_get_container_name)
    exposed_ca_get_container_name_ex = staticmethod(ca_get_container_name_ex)
    exposed_ca_get_container_policy_set = staticmethod(ca_get_container_policy_set)
    exposed_ca_get_container_policy_set_ex = staticmethod(ca_get_container_policy_set_ex)
    exposed_ca_get_container_policy_setting = staticmethod(ca_get_container_policy_setting)
    exposed_ca_get_container_policy_setting_ex = staticmethod(ca_get_container_policy_setting_ex)
    exposed_ca_get_container_status = staticmethod(ca_get_container_status)
    exposed_ca_get_container_status_ex = staticmethod(ca_get_container_status_ex)
    exposed_ca_get_container_storage_information = staticmethod(
        ca_get_container_storage_information)
    exposed_ca_get_container_storage_information_ex = staticmethod(
        ca_get_container_storage_information_ex)
    exposed_ca_set_container_policies = staticmethod(ca_set_container_policies)
    exposed_ca_set_container_policies_ex = staticmethod(ca_set_container_policies_ex)
    exposed_ca_set_container_size = staticmethod(ca_set_container_size)
    exposed_ca_set_container_size_ex = staticmethod(ca_set_container_size_ex)

    # key_management.py
    exposed_ca_generatemofn = staticmethod(ca_generatemofn)
    exposed_ca_generatemofn_ex = staticmethod(ca_generatemofn_ex)
    exposed_ca_modifyusagecount = staticmethod(ca_modifyusagecount)
    exposed_ca_modifyusagecount_ex = staticmethod(ca_modifyusagecount_ex)

    # key_usage.py
    exposed_ca_clonemofn = staticmethod(ca_clonemofn)
    exposed_ca_clonemofn_ex = staticmethod(ca_clonemofn_ex)
    exposed_ca_duplicatemofn = staticmethod(ca_duplicatemofn)
    exposed_ca_duplicatemofn_ex = staticmethod(ca_duplicatemofn_ex)
    exposed_c_derive_key = staticmethod(c_derive_key)
    exposed_c_derive_key_ex = staticmethod(c_derive_key_ex)

    # CA extensions
    exposed_ca_destroy_multiple_objects = staticmethod(ca_destroy_multiple_objects)
    exposed_ca_destroy_multiple_objects_ex = staticmethod(ca_destroy_multiple_objects_ex)
    exposed_ca_get_object_handle = staticmethod(ca_get_object_handle)
    exposed_ca_get_object_handle_ex = staticmethod(ca_get_object_handle_ex)
    exposed_ca_get_session_info = staticmethod(ca_get_session_info)
    exposed_ca_get_session_info_ex = staticmethod(ca_get_session_info_ex)
    exposed_ca_derive_key_and_wrap = staticmethod(ca_derive_key_and_wrap)
    exposed_ca_derive_key_and_wrap_ex = staticmethod(ca_derive_key_and_wrap_ex)

    exposed_ca_read_all_utilization_counters = staticmethod(ca_read_all_utilization_counters)
    exposed_ca_read_all_utilization_counters_ex = staticmethod(ca_read_all_utilization_counters_ex)
    exposed_ca_read_utilization_metrics = staticmethod(ca_read_utilization_metrics)
    exposed_ca_read_utilization_metrics_ex = staticmethod(ca_read_utilization_metrics_ex)
    exposed_ca_read_and_reset_utilization_metrics =\
                                    staticmethod(ca_read_and_reset_utilization_metrics)
    exposed_ca_read_and_reset_utilization_metrics_ex =\
                                    staticmethod(ca_read_and_reset_utilization_metrics_ex)

    exposed_ca_set_authorization_data = staticmethod(ca_set_authorization_data)
    exposed_ca_set_authorization_data_ex = staticmethod(ca_set_authorization_data_ex)
    exposed_ca_authorize_key = staticmethod(ca_authorize_key)
    exposed_ca_authorize_key_ex = staticmethod(ca_authorize_key_ex)

def server_launch(service, ip, port, config):
    """
    Target for the multiprocessing Pycryptoki service.

    :param service:
    :param ip:
    :param port:
    :param config:
    :return:
    """
    t = ThreadedServer(service,
                       hostname=ip,
                       port=port,
                       protocol_config=config)
    t.start()


def create_server_subprocess(target, args):
    """
    Create the subprocess, set it as a daemon, setup a signal handler
    in case the parent process is killed, the child process should also be killed, then return
    the subprocess.

    :param target: Target function to run in a subprocess
    :param args: Args to pass to the function
    :return: `multiprocessing.Process`
    """
    server = multiprocessing.Process(target=target,
                                     args=args)
    server.daemon = True
    server.start()

    logger.info("Created subprocess w/ PID %s", server.pid)

    def sighandler(signum, frame):
        print("Caught SIGTERM, closing subprocess")
        server.terminate()
        exit(0)

    signal.signal(signal.SIGTERM, sighandler)
    return server


def configure_logging(logfile=None):
    """
    Setup logging. If a log file is specified, will log to that file.

    :param str logfile: Log file path/name to use for logging.
    :return: Configured logger.
    """
    logger = logging.getLogger("pycryptoki")
    logger.setLevel(getattr(logging, args.loglevel))
    if not logfile:
        handler = logging.StreamHandler(sys.stdout)
    else:
        # 5 megabyte file, max of 10 files.
        handler = RotatingFileHandler(logfile, maxBytes=MAX_LOG_SIZE, backupCount=10)
    handler.setFormatter(logging.Formatter('%(asctime)s:%(name)s:%(levelname)s: %(message)s'))
    logger.addHandler(handler)
    return logger


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-i", "--ip_address",
                        dest="i",
                        help="pycryptoki daemon IP address",
                        metavar="<IP address>",
                        default="localhost",
                        action="store")
    parser.add_argument("-p", "--port", dest="p",
                        help="pycryptoki daemon IP port", metavar="<number>",
                        default=8001,
                        action="store",
                        type=int)
    parser.add_argument("-f", "--forked", dest="forked",
                        help="Fork the daemon from the parent process so we can recover from "
                             "segfaults", default=False, action="store_true")
    parser.add_argument("-l", "--loglevel",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        default="DEBUG",
                        action="store",
                        help="Log level.")
    parser.add_argument("-lf", "--logfile",
                        action="store",
                        dest="logfile",
                        help="Specifies a logfile to output to. Will perform log rotation based "
                             "on file size. If specified, will NOT output to stdout.")
    args = parser.parse_args()
    ip = args.i
    port = args.p

    logger = configure_logging(args.logfile)
    logger.info("Pycryptoki Daemon ip={}, port={}, PID={}".format(ip, port, os.getpid()))

    server_config = {'allow_public_attrs': True,
                     'allow_all_attrs': True,
                     'allow_getattr': True,
                     'allow_setattr': True,
                     'allow_delattr': True}

    server_kwargs = dict(target=server_launch,
                         args=(PycryptokiService,
                               ip, port,
                               server_config))

    if args.forked:
        logger.info("Starting PycryptokiServer in a separate process...")
        server = create_server_subprocess(**server_kwargs)
        if server.exitcode is not None and not server.is_alive():
            logger.error("Failed to start PycryptokiServer!")
            exit(-1)

        while True:
            if server.exitcode not in (1, None, -15) and not server.is_alive():
                logger.error("PycryptokiServer died w/ exit code %s! Possible segfault",
                             server.exitcode)
                logger.info("Restarting Pycryptoki server")
                server.terminate()
                server = create_server_subprocess(**server_kwargs)

            time.sleep(0.5)

    else:
        server_launch(PycryptokiService, ip, port, server_config)
