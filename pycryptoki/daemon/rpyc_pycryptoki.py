#!/usr/bin/env python -u
"""
RPYC-based daemon that allows for remote execution
of pycryptoki commands.

Start via ``./rpyc_pycryptoki.py -i <ip> -p <port>``
or ``python rpyc_pycryptoki.py -i <ip> -p <port>``

All methods starting are useable via ``rpyc_conn.root.<method>``

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

import pkg_resources
import rpyc
from rpyc.utils.server import ThreadedServer

import pycryptoki
from pycryptoki.attributes import *
from pycryptoki.audit_handling import (
    ca_get_time,
    ca_get_time_ex,
    ca_init_audit,
    ca_init_audit_ex,
    ca_time_sync,
    ca_time_sync_ex,
)
from pycryptoki.backup import (
    ca_open_secure_token,
    ca_open_secure_token_ex,
    ca_close_secure_token,
    ca_close_secure_token_ex,
    ca_extract,
    ca_extract_ex,
    ca_insert,
    ca_insert_ex,
    ca_sim_insert,
    ca_sim_insert_ex,
    ca_sim_extract_ex,
    ca_sim_extract,
    ca_sim_multisign,
    ca_sim_multisign_ex,
)
from pycryptoki.ca_extensions.bip32 import (
    ca_bip32_export_public_key,
    ca_bip32_export_public_key_ex,
    ca_bip32_import_public_key,
    ca_bip32_import_public_key_ex,
)
from pycryptoki.ca_extensions.derive_wrap import ca_derive_key_and_wrap, ca_derive_key_and_wrap_ex
from pycryptoki.ca_extensions.object_handler import (
    ca_destroy_multiple_objects,
    ca_destroy_multiple_objects_ex,
    ca_get_object_handle,
    ca_get_object_handle_ex,
)
from pycryptoki.ca_extensions.per_key_auth import (
    ca_set_authorization_data,
    ca_set_authorization_data_ex,
    ca_authorize_key,
    ca_authorize_key_ex,
    ca_assign_key,
    ca_assign_key_ex,
    ca_increment_failed_auth_count,
    ca_increment_failed_auth_count_ex,
    ca_reset_authorization_data,
    ca_reset_authorization_data_ex,
)
from pycryptoki.ca_extensions.session import (
    ca_get_session_info,
    ca_get_session_info_ex,
    ca_close_application_id_v2,
    ca_close_application_id_v2_ex,
    ca_get_application_id,
    ca_get_application_id_ex,
    ca_open_application_id_v2,
    ca_open_application_id_v2_ex,
)
from pycryptoki.ca_extensions.stc import (
    ca_stc_register,
    ca_stc_register_ex,
    ca_stc_register_v2,
    ca_stc_register_v2_ex,
    ca_stc_deregister,
    ca_stc_deregister_ex,
    ca_stc_get_pub_key,
    ca_stc_get_pub_key_ex,
    ca_stc_get_clients_list,
    ca_stc_get_clients_list_ex,
    ca_stc_get_client_info,
    ca_stc_get_client_info_ex,
    ca_stc_get_client_info_v2,
    ca_stc_get_client_info_v2_ex,
    ca_stc_get_part_pub_key,
    ca_stc_get_part_pub_key_ex,
    ca_stc_get_admin_pub_key,
    ca_stc_get_admin_pub_key_ex,
    ca_stc_get_pid,
    ca_stc_get_pid_ex,
    ca_stc_get_admin_pid,
    ca_stc_get_admin_pid_ex,
    ca_stc_set_cipher_algorithm,
    ca_stc_set_cipher_algorithm_ex,
    ca_stc_get_cipher_algorithm,
    ca_stc_get_cipher_algorithm_ex,
    ca_stc_clear_cipher_algorithm,
    ca_stc_clear_cipher_algorithm_ex,
    ca_stc_set_digest_algorithm,
    ca_stc_set_digest_algorithm_ex,
    ca_stc_get_digest_algorithm,
    ca_stc_get_digest_algorithm_ex,
    ca_stc_clear_digest_algorithm,
    ca_stc_clear_digest_algorithm_ex,
    ca_stc_set_key_life_time,
    ca_stc_set_key_life_time_ex,
    ca_stc_get_key_life_time,
    ca_stc_get_key_life_time_ex,
    ca_stc_set_key_activation_time_out,
    ca_stc_set_key_activation_time_out_ex,
    ca_stc_get_key_activation_time_out,
    ca_stc_get_key_activation_time_out_ex,
    ca_stc_set_max_sessions,
    ca_stc_set_max_sessions_ex,
    ca_stc_get_max_sessions,
    ca_stc_get_max_sessions_ex,
    ca_stc_set_sequence_window_size,
    ca_stc_set_sequence_window_size_ex,
    ca_stc_get_sequence_window_size,
    ca_stc_get_sequence_window_size_ex,
    ca_stc_is_enabled,
    ca_stc_is_enabled_ex,
    ca_stc_get_state,
    ca_stc_get_state_ex,
    ca_stc_get_channel_id,
    ca_stc_get_channel_id_ex,
    ca_stc_get_cipher_id,
    ca_stc_get_cipher_id_ex,
    ca_stc_get_digest_id,
    ca_stc_get_digest_id_ex,
    ca_stc_get_current_key_life,
    ca_stc_get_current_key_life_ex,
    ca_stc_get_cipher_ids,
    ca_stc_get_cipher_ids_ex,
    ca_stc_get_cipher_name_by_id,
    ca_stc_get_cipher_name_by_id_ex,
    ca_stc_get_digest_ids,
    ca_stc_get_digest_ids_ex,
    ca_stc_get_digest_name_by_id,
    ca_stc_get_digest_name_by_id_ex,
)
from pycryptoki.ca_extensions.utilization_metrics import (
    ca_read_all_utilization_counters,
    ca_read_all_utilization_counters_ex,
    ca_read_utilization_metrics,
    ca_read_utilization_metrics_ex,
    ca_read_and_reset_utilization_metrics,
    ca_read_and_reset_utilization_metrics_ex,
)
from pycryptoki.ca_extensions.hsm_info import (
    ca_get_cv_firmware_version,
    ca_get_cv_firmware_version_ex,
)
from pycryptoki.cryptoki import CK_ULONG
from pycryptoki.encryption import (
    c_encrypt,
    c_encrypt_ex,
    c_decrypt,
    c_decrypt_ex,
    c_wrap_key,
    c_wrap_key_ex,
    c_unwrap_key,
    c_unwrap_key_ex,
)
from pycryptoki.hsm_management import (
    c_performselftest,
    c_performselftest_ex,
    ca_settokencertificatesignature,
    ca_settokencertificatesignature_ex,
    ca_hainit,
    ca_hainit_ex,
    ca_hainitextended,
    ca_hainitextended_ex,
    ca_createloginchallenge,
    ca_createloginchallenge_ex,
    ca_initializeremotepedvector,
    ca_initializeremotepedvector_ex,
    ca_deleteremotepedvector,
    ca_deleteremotepedvector_ex,
    ca_mtkrestore,
    ca_mtkrestore_ex,
    ca_mtkresplit,
    ca_mtkresplit_ex,
    ca_mtkzeroize,
    ca_mtkzeroize_ex,
    ca_set_hsm_policy,
    ca_set_hsm_policy_ex,
    ca_set_destructive_hsm_policy,
    ca_set_destructive_hsm_policy_ex,
    ca_get_hsm_capability_set,
    ca_get_hsm_capability_set_ex,
    ca_get_hsm_policy_set,
    ca_get_hsm_policy_set_ex,
    ca_get_hsm_policy_setting,
    ca_get_hsm_policy_setting_ex,
    ca_get_hsm_capability_setting,
    ca_get_hsm_capability_setting_ex,
    ca_set_hsm_policies,
    ca_set_hsm_policies_ex,
    ca_set_destructive_hsm_policies,
    ca_set_destructive_hsm_policies_ex,
)
from pycryptoki.key_generator import (
    c_destroy_object,
    c_destroy_object_ex,
    c_generate_key_pair,
    c_generate_key_pair_ex,
    c_generate_key,
    c_generate_key_ex,
    c_derive_key,
    c_derive_key_ex,
    c_copy_object_ex,
    c_copy_object,
)
from pycryptoki.key_management import (
    ca_generatemofn,
    ca_generatemofn_ex,
    ca_modifyusagecount,
    ca_modifyusagecount_ex,
)
from pycryptoki.key_usage import (
    ca_clonemofn,
    ca_clonemofn_ex,
    ca_duplicatemofn,
    ca_duplicatemofn_ex,
)
from pycryptoki.misc import (
    c_generate_random,
    c_generate_random_ex,
    c_seed_random,
    c_seed_random_ex,
    c_digest,
    c_digest_ex,
    c_set_ped_id,
    c_set_ped_id_ex,
    c_get_ped_id,
    c_get_ped_id_ex,
    c_create_object,
    c_create_object_ex,
    c_digestkey,
    c_digestkey_ex,
)
from pycryptoki.object_attr_lookup import (
    c_find_objects,
    c_find_objects_ex,
    c_get_attribute_value,
    c_get_attribute_value_ex,
    c_set_attribute_value,
    c_set_attribute_value_ex,
)
from pycryptoki.partition_management import (
    ca_create_container,
    ca_create_container_ex,
    ca_delete_container_with_handle_ex,
    ca_delete_container_with_handle,
    ca_set_container_policy,
    ca_set_container_policy_ex,
    ca_get_container_capability_set,
    ca_get_container_capability_set_ex,
    ca_get_container_capability_setting,
    ca_get_container_capability_setting_ex,
    ca_get_container_handle,
    ca_get_container_handle_ex,
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
    ca_set_container_size_ex,
    ca_init_token,
    ca_init_token_ex,
    ca_init_role_pin,
    ca_init_role_pin_ex,
)
from pycryptoki.session_management import (
    c_initialize,
    c_initialize_ex,
    c_finalize,
    c_finalize_ex,
    c_open_session,
    c_open_session_ex,
    c_get_session_info,
    c_get_session_info_ex,
    c_get_token_info,
    c_get_token_info_ex,
    c_close_session,
    c_close_session_ex,
    c_logout,
    c_logout_ex,
    c_init_pin,
    c_init_pin_ex,
    ca_factory_reset,
    ca_factory_reset_ex,
    c_set_pin,
    c_set_pin_ex,
    c_close_all_sessions,
    c_close_all_sessions_ex,
    login,
    login_ex,
    ca_openapplicationID_ex,
    ca_openapplicationID,
    ca_closeapplicationID,
    ca_closeapplicationID_ex,
    ca_restart,
    ca_restart_ex,
    ca_setapplicationID,
    ca_setapplicationID_ex,
    c_get_slot_list,
    c_get_slot_list_ex,
    c_get_slot_info,
    c_get_slot_info_ex,
    c_get_info,
    c_get_info_ex,
)
from pycryptoki.sign_verify import c_sign, c_sign_ex, c_verify, c_verify_ex
from pycryptoki.token_management import (
    c_init_token,
    c_init_token_ex,
    c_get_mechanism_list,
    c_get_mechanism_list_ex,
    c_get_mechanism_info,
    c_get_mechanism_info_ex,
    get_token_by_label,
    get_token_by_label_ex,
    ca_get_token_policies_ex,
    ca_get_token_policies,
)

MAX_LOG_SIZE = 5242880


class PycryptokiService(rpyc.SlaveService):
    """This is the core service to expose over RPYC.

    If you're working with pointers, you'll need to create the pointer in a function here
    rather than passing in a pointer from the client (pointers getting pickled makes no sense).
    """

    @staticmethod
    def test_conn():
        """
        Test Function used to validate that custom functions are properly exposed over
        RPYC. Specifically not using something like conn.ping() to verify exposed functions.
        """
        return True

    @staticmethod
    def test_attrs(attributes):
        """
        Function used for validating that dicts can be used across rpyc pipes.
        """
        attrs = Attributes(attributes)
        attrs.get_c_struct()

    # attribute transforms
    to_byte_array = staticmethod(to_byte_array)
    to_char_array = staticmethod(to_char_array)
    to_bool = staticmethod(to_bool)
    to_long = staticmethod(to_long)
    to_ck_date = staticmethod(to_ck_date)
    to_subattributes = staticmethod(to_sub_attributes)

    # encryption.py
    c_wrap_key = staticmethod(c_wrap_key)
    c_wrap_key_ex = staticmethod(c_wrap_key_ex)
    c_unwrap_key = staticmethod(c_unwrap_key)
    c_unwrap_key_ex = staticmethod(c_unwrap_key_ex)
    c_encrypt = staticmethod(c_encrypt)
    c_encrypt_ex = staticmethod(c_encrypt_ex)
    c_decrypt = staticmethod(c_decrypt)
    c_decrypt_ex = staticmethod(c_decrypt_ex)

    # sign_verify.py
    c_sign = staticmethod(c_sign)
    c_sign_ex = staticmethod(c_sign_ex)
    c_verify = staticmethod(c_verify)
    c_verify_ex = staticmethod(c_verify_ex)

    # token_management.py
    c_init_token = staticmethod(c_init_token)
    c_init_token_ex = staticmethod(c_init_token_ex)
    c_get_mechanism_list = staticmethod(c_get_mechanism_list)
    c_get_mechanism_list_ex = staticmethod(c_get_mechanism_list_ex)
    c_get_mechanism_info = staticmethod(c_get_mechanism_info)
    c_get_mechanism_info_ex = staticmethod(c_get_mechanism_info_ex)
    ca_get_token_policies = staticmethod(ca_get_token_policies)
    ca_get_token_policies_ex = staticmethod(ca_get_token_policies_ex)

    # session_management.py
    c_initialize = staticmethod(c_initialize)
    c_initialize_ex = staticmethod(c_initialize_ex)
    c_finalize = staticmethod(c_finalize)
    c_finalize_ex = staticmethod(c_finalize_ex)
    c_open_session = staticmethod(c_open_session)
    c_open_session_ex = staticmethod(c_open_session_ex)
    login = staticmethod(login)
    login_ex = staticmethod(login_ex)
    c_get_session_info = staticmethod(c_get_session_info)
    c_get_session_info_ex = staticmethod(c_get_session_info_ex)
    c_get_token_info = staticmethod(c_get_token_info)
    c_get_token_info_ex = staticmethod(c_get_token_info_ex)
    c_close_session = staticmethod(c_close_session)
    c_close_session_ex = staticmethod(c_close_session_ex)
    c_logout = staticmethod(c_logout)
    c_logout_ex = staticmethod(c_logout_ex)
    c_set_pin = staticmethod(c_set_pin)
    c_set_pin_ex = staticmethod(c_set_pin_ex)
    c_init_pin = staticmethod(c_init_pin)
    c_init_pin_ex = staticmethod(c_init_pin_ex)
    ca_factory_reset = staticmethod(ca_factory_reset)
    ca_factory_reset_ex = staticmethod(ca_factory_reset_ex)
    get_token_by_label = staticmethod(get_token_by_label)
    get_token_by_label_ex = staticmethod(get_token_by_label_ex)
    ca_close_secure_token = staticmethod(ca_close_secure_token)
    ca_close_secure_token_ex = staticmethod(ca_close_secure_token_ex)
    ca_open_secure_token = staticmethod(ca_open_secure_token)
    ca_open_secure_token_ex = staticmethod(ca_open_secure_token_ex)
    c_close_all_sessions = staticmethod(c_close_all_sessions)
    c_close_all_sessions_ex = staticmethod(c_close_all_sessions_ex)
    ca_openapplicationID_ex = staticmethod(ca_openapplicationID_ex)
    ca_openapplicationID = staticmethod(ca_openapplicationID)
    ca_closeapplicationID_ex = staticmethod(ca_closeapplicationID_ex)
    ca_closeapplicationID = staticmethod(ca_closeapplicationID)
    ca_setapplicationID_ex = staticmethod(ca_setapplicationID_ex)
    ca_setapplicationID = staticmethod(ca_setapplicationID)
    ca_open_application_id_v2 = staticmethod(ca_open_application_id_v2)
    ca_open_application_id_v2_ex = staticmethod(ca_open_application_id_v2_ex)
    ca_close_application_id_v2 = staticmethod(ca_close_application_id_v2)
    ca_close_application_id_v2_ex = staticmethod(ca_close_application_id_v2_ex)
    ca_get_application_id = staticmethod(ca_get_application_id)
    ca_get_application_id_ex = staticmethod(ca_get_application_id_ex)
    ca_restart_ex = staticmethod(ca_restart_ex)
    ca_restart = staticmethod(ca_restart)
    c_get_slot_list = staticmethod(c_get_slot_list)
    c_get_slot_list_ex = staticmethod(c_get_slot_list_ex)
    c_get_slot_info = staticmethod(c_get_slot_info)
    c_get_slot_info_ex = staticmethod(c_get_slot_info_ex)
    c_get_info = staticmethod(c_get_info)
    c_get_info_ex = staticmethod(c_get_info_ex)

    # object_attr_lookup.py
    c_find_objects = staticmethod(c_find_objects)
    c_find_objects_ex = staticmethod(c_find_objects_ex)
    c_get_attribute_value = staticmethod(c_get_attribute_value)
    c_get_attribute_value_ex = staticmethod(c_get_attribute_value_ex)
    c_set_attribute_value = staticmethod(c_set_attribute_value)
    c_set_attribute_value_ex = staticmethod(c_set_attribute_value_ex)

    # misc.py
    c_generate_random = staticmethod(c_generate_random)
    c_generate_random_ex = staticmethod(c_generate_random_ex)
    c_seed_random = staticmethod(c_seed_random)
    c_seed_random_ex = staticmethod(c_seed_random_ex)
    c_digest = staticmethod(c_digest)
    c_digest_ex = staticmethod(c_digest_ex)
    c_set_ped_id = staticmethod(c_set_ped_id)
    c_set_ped_id_ex = staticmethod(c_set_ped_id_ex)
    c_get_ped_id = staticmethod(c_get_ped_id)
    c_get_ped_id_ex = staticmethod(c_get_ped_id_ex)
    c_create_object = staticmethod(c_create_object)
    c_create_object_ex = staticmethod(c_create_object_ex)
    c_digest_key = staticmethod(c_digestkey)
    c_digest_key_ex = staticmethod(c_digestkey_ex)

    # key_generator.py
    c_generate_key = staticmethod(c_generate_key)
    c_generate_key_ex = staticmethod(c_generate_key_ex)
    c_generate_key_pair = staticmethod(c_generate_key_pair)
    c_generate_key_pair_ex = staticmethod(c_generate_key_pair_ex)
    c_destroy_object = staticmethod(c_destroy_object)
    c_destroy_object_ex = staticmethod(c_destroy_object_ex)
    c_copy_object = staticmethod(c_copy_object)
    c_copy_object_ex = staticmethod(c_copy_object_ex)

    # backup.py
    ca_extract = staticmethod(ca_extract)
    ca_extract_ex = staticmethod(ca_extract_ex)
    ca_insert = staticmethod(ca_insert)
    ca_insert_ex = staticmethod(ca_insert_ex)
    ca_sim_insert = staticmethod(ca_sim_insert)
    ca_sim_insert_ex = staticmethod(ca_sim_insert_ex)
    ca_sim_extract = staticmethod(ca_sim_extract)
    ca_sim_extract_ex = staticmethod(ca_sim_extract_ex)
    ca_sim_multisign = staticmethod(ca_sim_multisign)
    ca_sim_multisign_ex = staticmethod(ca_sim_multisign_ex)

    # audit_handling.py
    ca_get_time = staticmethod(ca_get_time)
    ca_get_time_ex = staticmethod(ca_get_time_ex)
    ca_init_audit = staticmethod(ca_init_audit)
    ca_init_audit_ex = staticmethod(ca_init_audit_ex)
    ca_time_sync = staticmethod(ca_time_sync)
    ca_time_sync_ex = staticmethod(ca_time_sync_ex)

    # hsm_management.py
    c_performselftest = staticmethod(c_performselftest)
    c_performselftest_ex = staticmethod(c_performselftest_ex)
    ca_settokencertificatesignature = staticmethod(ca_settokencertificatesignature)
    ca_settokencertificatesignature_ex = staticmethod(ca_settokencertificatesignature_ex)
    ca_hainit = staticmethod(ca_hainit)
    ca_hainit_ex = staticmethod(ca_hainit_ex)
    ca_hainitextended = staticmethod(ca_hainitextended)
    ca_hainitextended_ex = staticmethod(ca_hainitextended_ex)
    ca_createloginchallenge = staticmethod(ca_createloginchallenge)
    ca_createloginchallenge_ex = staticmethod(ca_createloginchallenge_ex)
    ca_initializeremotepedvector = staticmethod(ca_initializeremotepedvector)
    ca_initializeremotepedvector_ex = staticmethod(ca_initializeremotepedvector_ex)
    ca_deleteremotepedvector = staticmethod(ca_deleteremotepedvector)
    ca_deleteremotepedvector_ex = staticmethod(ca_deleteremotepedvector_ex)
    ca_mtkrestore = staticmethod(ca_mtkrestore)
    ca_mtkrestore_ex = staticmethod(ca_mtkrestore_ex)
    ca_mtkresplit = staticmethod(ca_mtkresplit)
    ca_mtkresplit_ex = staticmethod(ca_mtkresplit_ex)
    ca_mtkzeroize = staticmethod(ca_mtkzeroize)
    ca_mtkzeroize_ex = staticmethod(ca_mtkzeroize_ex)
    ca_get_hsm_policy_set = staticmethod(ca_get_hsm_policy_set)
    ca_get_hsm_policy_set_ex = staticmethod(ca_get_hsm_policy_set_ex)
    ca_get_hsm_capability_set = staticmethod(ca_get_hsm_capability_set)
    ca_get_hsm_capability_set_ex = staticmethod(ca_get_hsm_capability_set_ex)
    ca_get_hsm_policy_setting = staticmethod(ca_get_hsm_policy_setting)
    ca_get_hsm_policy_setting_ex = staticmethod(ca_get_hsm_policy_setting_ex)
    ca_get_hsm_capability_setting = staticmethod(ca_get_hsm_capability_setting)
    ca_get_hsm_capability_setting_ex = staticmethod(ca_get_hsm_capability_setting_ex)
    ca_set_hsm_policy = staticmethod(ca_set_hsm_policy)
    ca_set_hsm_policy_ex = staticmethod(ca_set_hsm_policy_ex)
    ca_set_destructive_hsm_policy = staticmethod(ca_set_destructive_hsm_policy)
    ca_set_destructive_hsm_policy_ex = staticmethod(ca_set_destructive_hsm_policy_ex)
    ca_set_hsm_policies = staticmethod(ca_set_hsm_policies)
    ca_set_hsm_policies_ex = staticmethod(ca_set_hsm_policies_ex)
    ca_set_destructive_hsm_policies = staticmethod(ca_set_destructive_hsm_policies)
    ca_set_destructive_hsm_policies_ex = staticmethod(ca_set_destructive_hsm_policies_ex)

    # partition_management.py
    ca_create_container = staticmethod(ca_create_container)
    ca_create_container_ex = staticmethod(ca_create_container_ex)
    ca_delete_container_with_handle = staticmethod(ca_delete_container_with_handle)
    ca_delete_container_with_handle_ex = staticmethod(ca_delete_container_with_handle_ex)
    ca_set_container_policy = staticmethod(ca_set_container_policy)
    ca_set_container_policy_ex = staticmethod(ca_set_container_policy_ex)
    ca_get_container_capability_set = staticmethod(ca_get_container_capability_set)
    ca_get_container_capability_set_ex = staticmethod(ca_get_container_capability_set_ex)
    ca_get_container_capability_setting = staticmethod(ca_get_container_capability_setting)
    ca_get_container_capability_setting_ex = staticmethod(ca_get_container_capability_setting_ex)
    ca_get_container_handle = staticmethod(ca_get_container_handle)
    ca_get_container_handle_ex = staticmethod(ca_get_container_handle_ex)
    ca_get_container_list = staticmethod(ca_get_container_list)
    ca_get_container_list_ex = staticmethod(ca_get_container_list_ex)
    ca_get_container_name = staticmethod(ca_get_container_name)
    ca_get_container_name_ex = staticmethod(ca_get_container_name_ex)
    ca_get_container_policy_set = staticmethod(ca_get_container_policy_set)
    ca_get_container_policy_set_ex = staticmethod(ca_get_container_policy_set_ex)
    ca_get_container_policy_setting = staticmethod(ca_get_container_policy_setting)
    ca_get_container_policy_setting_ex = staticmethod(ca_get_container_policy_setting_ex)
    ca_get_container_status = staticmethod(ca_get_container_status)
    ca_get_container_status_ex = staticmethod(ca_get_container_status_ex)
    ca_get_container_storage_information = staticmethod(ca_get_container_storage_information)
    ca_get_container_storage_information_ex = staticmethod(ca_get_container_storage_information_ex)
    ca_set_container_policies = staticmethod(ca_set_container_policies)
    ca_set_container_policies_ex = staticmethod(ca_set_container_policies_ex)
    ca_set_container_size = staticmethod(ca_set_container_size)
    ca_set_container_size_ex = staticmethod(ca_set_container_size_ex)
    ca_init_token = staticmethod(ca_init_token)
    ca_init_token_ex = staticmethod(ca_init_token_ex)
    ca_init_role_pin = staticmethod(ca_init_role_pin)
    ca_init_role_pin_ex = staticmethod(ca_init_role_pin_ex)

    # key_management.py
    ca_generatemofn = staticmethod(ca_generatemofn)
    ca_generatemofn_ex = staticmethod(ca_generatemofn_ex)
    ca_modifyusagecount = staticmethod(ca_modifyusagecount)
    ca_modifyusagecount_ex = staticmethod(ca_modifyusagecount_ex)

    # key_usage.py
    ca_clonemofn = staticmethod(ca_clonemofn)
    ca_clonemofn_ex = staticmethod(ca_clonemofn_ex)
    ca_duplicatemofn = staticmethod(ca_duplicatemofn)
    ca_duplicatemofn_ex = staticmethod(ca_duplicatemofn_ex)
    c_derive_key = staticmethod(c_derive_key)
    c_derive_key_ex = staticmethod(c_derive_key_ex)

    # CA extensions
    ca_destroy_multiple_objects = staticmethod(ca_destroy_multiple_objects)
    ca_destroy_multiple_objects_ex = staticmethod(ca_destroy_multiple_objects_ex)
    ca_get_object_handle = staticmethod(ca_get_object_handle)
    ca_get_object_handle_ex = staticmethod(ca_get_object_handle_ex)
    ca_get_session_info = staticmethod(ca_get_session_info)
    ca_get_session_info_ex = staticmethod(ca_get_session_info_ex)
    ca_derive_key_and_wrap = staticmethod(ca_derive_key_and_wrap)
    ca_derive_key_and_wrap_ex = staticmethod(ca_derive_key_and_wrap_ex)
    ca_get_cv_firmware_version = staticmethod(ca_get_cv_firmware_version)
    ca_get_cv_firmware_version_ex = staticmethod(ca_get_cv_firmware_version_ex)

    ca_read_all_utilization_counters = staticmethod(ca_read_all_utilization_counters)
    ca_read_all_utilization_counters_ex = staticmethod(ca_read_all_utilization_counters_ex)
    ca_read_utilization_metrics = staticmethod(ca_read_utilization_metrics)
    ca_read_utilization_metrics_ex = staticmethod(ca_read_utilization_metrics_ex)
    ca_read_and_reset_utilization_metrics = staticmethod(ca_read_and_reset_utilization_metrics)
    ca_read_and_reset_utilization_metrics_ex = staticmethod(
        ca_read_and_reset_utilization_metrics_ex
    )

    ca_assign_key = staticmethod(ca_assign_key)
    ca_assign_key_ex = staticmethod(ca_assign_key_ex)
    ca_set_authorization_data = staticmethod(ca_set_authorization_data)
    ca_set_authorization_data_ex = staticmethod(ca_set_authorization_data_ex)
    ca_authorize_key = staticmethod(ca_authorize_key)
    ca_authorize_key_ex = staticmethod(ca_authorize_key_ex)
    ca_increment_failed_auth_count = staticmethod(ca_increment_failed_auth_count)
    ca_increment_failed_auth_count_ex = staticmethod(ca_increment_failed_auth_count_ex)
    ca_reset_authorization_data = staticmethod(ca_reset_authorization_data)
    ca_reset_authorization_data_ex = staticmethod(ca_reset_authorization_data_ex)

    ca_bip32_import_public_key = staticmethod(ca_bip32_import_public_key)
    ca_bip32_import_public_key_ex = staticmethod(ca_bip32_import_public_key_ex)
    ca_bip32_export_public_key = staticmethod(ca_bip32_export_public_key)
    ca_bip32_export_public_key_ex = staticmethod(ca_bip32_export_public_key_ex)

    ca_stc_register = staticmethod(ca_stc_register)
    ca_stc_register_ex = staticmethod(ca_stc_register_ex)
    ca_stc_deregister = staticmethod(ca_stc_deregister)
    ca_stc_deregister_ex = staticmethod(ca_stc_deregister_ex)
    ca_stc_get_pub_key = staticmethod(ca_stc_get_pub_key)
    ca_stc_get_pub_key_ex = staticmethod(ca_stc_get_pub_key_ex)
    ca_stc_get_clients_list = staticmethod(ca_stc_get_clients_list)
    ca_stc_get_clients_list_ex = staticmethod(ca_stc_get_clients_list_ex)
    ca_stc_get_client_info = staticmethod(ca_stc_get_client_info)
    ca_stc_get_client_info_ex = staticmethod(ca_stc_get_client_info_ex)
    ca_stc_get_part_pub_key = staticmethod(ca_stc_get_part_pub_key)
    ca_stc_get_part_pub_key_ex = staticmethod(ca_stc_get_part_pub_key_ex)
    ca_stc_get_admin_pub_key = staticmethod(ca_stc_get_admin_pub_key)
    ca_stc_get_admin_pub_key_ex = staticmethod(ca_stc_get_admin_pub_key_ex)
    ca_stc_get_pid = staticmethod(ca_stc_get_pid)
    ca_stc_get_pid_ex = staticmethod(ca_stc_get_pid_ex)
    ca_stc_get_admin_pid = staticmethod(ca_stc_get_admin_pid)
    ca_stc_get_admin_pid_ex = staticmethod(ca_stc_get_admin_pid_ex)
    ca_stc_set_cipher_algorithm = staticmethod(ca_stc_set_cipher_algorithm)
    ca_stc_set_cipher_algorithm_ex = staticmethod(ca_stc_set_cipher_algorithm_ex)
    ca_stc_get_cipher_algorithm = staticmethod(ca_stc_get_cipher_algorithm)
    ca_stc_get_cipher_algorithm_ex = staticmethod(ca_stc_get_cipher_algorithm_ex)
    ca_stc_clear_cipher_algorithm = staticmethod(ca_stc_clear_cipher_algorithm)
    ca_stc_clear_cipher_algorithm_ex = staticmethod(ca_stc_clear_cipher_algorithm_ex)
    ca_stc_set_digest_algorithm = staticmethod(ca_stc_set_digest_algorithm)
    ca_stc_set_digest_algorithm_ex = staticmethod(ca_stc_set_digest_algorithm_ex)
    ca_stc_get_digest_algorithm = staticmethod(ca_stc_get_digest_algorithm)
    ca_stc_get_digest_algorithm_ex = staticmethod(ca_stc_get_digest_algorithm_ex)
    ca_stc_clear_digest_algorithm = staticmethod(ca_stc_clear_digest_algorithm)
    ca_stc_clear_digest_algorithm_ex = staticmethod(ca_stc_clear_digest_algorithm_ex)
    ca_stc_set_key_life_time = staticmethod(ca_stc_set_key_life_time)
    ca_stc_set_key_life_time_ex = staticmethod(ca_stc_set_key_life_time_ex)
    ca_stc_get_key_life_time = staticmethod(ca_stc_get_key_life_time)
    ca_stc_get_key_life_time_ex = staticmethod(ca_stc_get_key_life_time_ex)
    ca_stc_set_key_activation_time_out = staticmethod(ca_stc_set_key_activation_time_out)
    ca_stc_set_key_activation_time_out_ex = staticmethod(ca_stc_set_key_activation_time_out_ex)
    ca_stc_get_key_activation_time_out = staticmethod(ca_stc_get_key_activation_time_out)
    ca_stc_get_key_activation_time_out_ex = staticmethod(ca_stc_get_key_activation_time_out_ex)
    ca_stc_set_max_sessions = staticmethod(ca_stc_set_max_sessions)
    ca_stc_set_max_sessions_ex = staticmethod(ca_stc_set_max_sessions_ex)
    ca_stc_get_max_sessions = staticmethod(ca_stc_get_max_sessions)
    ca_stc_get_max_sessions_ex = staticmethod(ca_stc_get_max_sessions_ex)
    ca_stc_set_sequence_window_size = staticmethod(ca_stc_set_sequence_window_size)
    ca_stc_set_sequence_window_size_ex = staticmethod(ca_stc_set_sequence_window_size_ex)
    ca_stc_get_sequence_window_size = staticmethod(ca_stc_get_sequence_window_size)
    ca_stc_get_sequence_window_size_ex = staticmethod(ca_stc_get_sequence_window_size_ex)
    ca_stc_is_enabled = staticmethod(ca_stc_is_enabled)
    ca_stc_is_enabled_ex = staticmethod(ca_stc_is_enabled_ex)
    ca_stc_get_state = staticmethod(ca_stc_get_state)
    ca_stc_get_state_ex = staticmethod(ca_stc_get_state_ex)
    ca_stc_get_channel_id = staticmethod(ca_stc_get_channel_id)
    ca_stc_get_channel_id_ex = staticmethod(ca_stc_get_channel_id_ex)
    ca_stc_get_cipher_id = staticmethod(ca_stc_get_cipher_id)
    ca_stc_get_cipher_id_ex = staticmethod(ca_stc_get_cipher_id_ex)
    ca_stc_get_digest_id = staticmethod(ca_stc_get_digest_id)
    ca_stc_get_digest_id_ex = staticmethod(ca_stc_get_digest_id_ex)
    ca_stc_get_current_key_life = staticmethod(ca_stc_get_current_key_life)
    ca_stc_get_current_key_life_ex = staticmethod(ca_stc_get_current_key_life_ex)
    ca_stc_get_cipher_ids = staticmethod(ca_stc_get_cipher_ids)
    ca_stc_get_cipher_ids_ex = staticmethod(ca_stc_get_cipher_ids_ex)
    ca_stc_get_cipher_name_by_id = staticmethod(ca_stc_get_cipher_name_by_id)
    ca_stc_get_cipher_name_by_id_ex = staticmethod(ca_stc_get_cipher_name_by_id_ex)
    ca_stc_get_digest_ids = staticmethod(ca_stc_get_digest_ids)
    ca_stc_get_digest_ids_ex = staticmethod(ca_stc_get_digest_ids_ex)
    ca_stc_get_digest_name_by_id = staticmethod(ca_stc_get_digest_name_by_id)
    ca_stc_get_digest_name_by_id_ex = staticmethod(ca_stc_get_digest_name_by_id_ex)


def server_launch(service, ip, port, config):
    """
    Target for the multiprocessing Pycryptoki service.

    :param service:
    :param ip:
    :param port:
    :param config:
    :return:
    """
    t = ThreadedServer(service, hostname=ip, port=port, protocol_config=config)
    t.start()


def create_server_subprocess(target, args, logger):
    """
    Create the subprocess, set it as a daemon, setup a signal handler
    in case the parent process is killed, the child process should also be killed, then return
    the subprocess.

    :param target: Target function to run in a subprocess
    :param args: Args to pass to the function
    :return: `multiprocessing.Process`
    """
    server = multiprocessing.Process(target=target, args=args)
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
    handler.setFormatter(logging.Formatter("%(asctime)s:%(name)s:%(levelname)s: %(message)s"))
    logger.addHandler(handler)
    return logger


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument(
        "-i",
        "--ip_address",
        dest="i",
        help="pycryptoki daemon IP address",
        metavar="<IP address>",
        default="localhost",
        action="store",
    )
    parser.add_argument(
        "-p",
        "--port",
        dest="p",
        help="pycryptoki daemon IP port",
        metavar="<number>",
        default=8001,
        action="store",
        type=int,
    )
    parser.add_argument(
        "-f",
        "--forked",
        dest="forked",
        help="Fork the daemon from the parent process so we can recover from " "segfaults",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "-l",
        "--loglevel",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="DEBUG",
        action="store",
        help="Log level.",
    )
    parser.add_argument(
        "-lf",
        "--logfile",
        action="store",
        dest="logfile",
        help="Specifies a logfile to output to. Will perform log rotation based "
        "on file size. If specified, will NOT output to stdout.",
    )
    args = parser.parse_args()
    ip = args.i
    port = args.p

    logger = configure_logging(args.logfile)
    logger.info("Pycryptoki Version: %s", pkg_resources.get_distribution("pycryptoki").version)
    logger.info("Pycryptoki Daemon ip={}, port={}, PID={}".format(ip, port, os.getpid()))

    server_config = {
        "allow_public_attrs": True,
        "allow_all_attrs": True,
        "allow_getattr": True,
        "allow_setattr": True,
        "allow_delattr": True,
    }

    server_kwargs = dict(
        target=server_launch, args=(PycryptokiService, ip, port, server_config), logger=logger
    )

    if args.forked:
        logger.info("Starting PycryptokiServer in a separate process...")
        server = create_server_subprocess(**server_kwargs)
        if server.exitcode is not None and not server.is_alive():
            logger.error("Failed to start PycryptokiServer!")
            exit(-1)

        while True:
            if server.exitcode not in (1, None, -15) and not server.is_alive():
                logger.error(
                    "PycryptokiServer died w/ exit code %s! Possible segfault", server.exitcode
                )
                logger.info("Restarting Pycryptoki server")
                server.terminate()
                server = create_server_subprocess(**server_kwargs)

            time.sleep(0.5)

    else:
        server_launch(PycryptokiService, ip, port, server_config)
