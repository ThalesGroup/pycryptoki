"""
This is the rpy
"""

import logging
from optparse import OptionParser
from _ctypes import pointer
from ctypes import cast
import ctypes

import rpyc
import pycryptoki

from pycryptoki.backup import ca_open_secure_token, ca_close_secure_token, \
    ca_open_secure_token_ex, ca_close_secure_token_ex, ca_extract, ca_extract_ex, \
    ca_insert, ca_insert_ex
from pycryptoki.encryption import c_encrypt, c_encrypt_ex, c_decrypt, \
    c_decrypt_ex, c_wrap_key, c_wrap_key_ex, c_unwrap_key, c_unwrap_key_ex
from pycryptoki.key_generator import c_destroy_object, c_destroy_object_ex, \
    c_generate_key_pair, c_generate_key_pair_ex, c_generate_key, c_generate_key_ex, \
    c_derive_key, c_derive_key_ex, c_copy_object_ex, c_copy_object
from pycryptoki.misc import c_generate_random, c_generate_random_ex, \
    c_seed_random, c_seed_random_ex, c_digest, c_digest_ex, c_set_ped_id, \
    c_set_ped_id_ex, c_get_ped_id, c_get_ped_id_ex, c_create_object, \
    c_create_object_ex, c_digestkey, c_digestkey_ex
from pycryptoki.object_attr_lookup import c_find_objects, c_find_objects_ex, \
    c_get_attribute_value, c_get_attribute_value_ex, c_set_attribute_value, c_set_attribute_value_ex
from pycryptoki.policy_management import ca_set_hsm_policy, ca_set_hsm_policy_ex, \
    ca_set_destructive_hsm_policy, ca_set_destructive_hsm_policy_ex, \
    ca_set_container_policy, ca_set_container_policy_ex
from pycryptoki.session_management import c_initialize, c_initialize_ex, \
    c_finalize, c_finalize_ex, c_open_session, c_open_session_ex, \
    c_get_session_info, c_get_session_info_ex, c_get_token_info, \
    c_get_token_info_ex, c_close_session, c_close_session_ex, c_logout, c_logout_ex, \
    c_init_pin, c_init_pin_ex, ca_factory_reset, ca_factory_reset_ex, c_set_pin, \
    c_set_pin_ex, c_close_all_sessions, c_close_all_sessions_ex, ca_create_container, \
    ca_create_container_ex, login, login_ex, ca_openapplicationID_ex, ca_openapplicationID, ca_closeapplicationID_ex, \
    ca_closeapplicationID, ca_restart, ca_restart_ex, ca_delete_container_with_handle_ex, \
    ca_delete_container_with_handle, ca_setapplicationID, ca_setapplicationID_ex
from pycryptoki.sign_verify import c_sign, c_sign_ex, c_verify, c_verify_ex
from pycryptoki.token_management import c_init_token, c_init_token_ex, \
    c_get_mechanism_list, c_get_mechanism_list_ex, c_get_mechanism_info, \
    c_get_mechanism_info_ex, get_token_by_label, get_token_by_label_ex
from pycryptoki.audit_handling import ca_get_time, ca_get_time_ex, ca_init_audit, \
    ca_init_audit_ex, ca_time_sync, ca_time_sync_ex
from pycryptoki.cryptoki import CK_ULONG, CK_VOID_PTR
from pycryptoki.key_generator import _get_mechanism
from pycryptoki.hsm_management import c_performselftest, c_performselftest_ex, \
    ca_settokencertificatesignature, ca_settokencertificatesignature_ex, \
    ca_hainit, ca_hainit_ex, ca_createloginchallenge, ca_createloginchallenge_ex, \
    ca_initializeremotepedvector, ca_initializeremotepedvector_ex, \
    ca_deleteremotepedvector, ca_deleteremotepedvector_ex, ca_mtkrestore, \
    ca_mtkrestore_ex, ca_mtkresplit, ca_mtkresplit_ex, ca_mtkzeroize, ca_mtkzeroize_ex
from pycryptoki.key_management import ca_generatemofn, ca_generatemofn_ex, \
    ca_modifyusagecount, ca_modifyusagecount_ex
from pycryptoki.key_usage import ca_clonemofn, ca_clonemofn_ex, \
    ca_duplicatemofn, ca_duplicatemofn_ex

from pycryptoki.cryptoki import *


logger = logging.getLogger(__name__)


class PycryptokiService(rpyc.SlaveService):
    """
    This is the core service to expose to the daemon.
    Add in a static method preceded by 'exposed_' and it'll be visible to anything
    connecting to the daemon.

    If you're working with pointers, you'll need to create the pointer in a function here
    rather than passing in a pointer from the client (pointers getting pickled makes no sense).

    """
    def _rpyc_getattr(self, name):
        if name.startswith("exposed_"):
            name = name
        elif name in pycryptoki.cryptoki.__all__:
            return getattr(pycryptoki.cryptoki, name)
        else:
            name = "exposed_" + name
        return getattr(self, name)

    #encryption.py
    exposed_c_wrap_key = staticmethod(c_wrap_key)
    exposed_c_wrap_key_ex = staticmethod(c_wrap_key_ex)
    exposed_c_unwrap_key = staticmethod(c_unwrap_key)
    exposed_c_unwrap_key_ex = staticmethod(c_unwrap_key_ex)
    exposed_c_encrypt = staticmethod(c_encrypt)
    exposed_c_encrypt_ex = staticmethod(c_encrypt_ex)
    exposed_c_decrypt = staticmethod(c_decrypt)
    exposed_c_decrypt_ex = staticmethod(c_decrypt_ex)

    #sign_verify.py
    exposed_c_sign = staticmethod(c_sign)
    exposed_c_sign_ex = staticmethod(c_sign_ex)
    exposed_c_verify = staticmethod(c_verify)
    exposed_c_verify_ex = staticmethod(c_verify_ex)

    #token_management.py
    exposed_c_init_token = staticmethod(c_init_token)
    exposed_c_init_token_ex = staticmethod(c_init_token_ex)
    exposed_c_get_mechanism_list = staticmethod(c_get_mechanism_list)
    exposed_c_get_mechanism_list_ex = staticmethod(c_get_mechanism_list_ex)
    exposed_c_get_mechanism_info = staticmethod(c_get_mechanism_info)
    exposed_c_get_mechanism_info_ex = staticmethod(c_get_mechanism_info_ex)

    #session_management.py
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
    exposed_ca_create_container = staticmethod(ca_create_container)
    exposed_ca_create_container_ex = staticmethod(ca_create_container_ex)
    exposed_ca_openapplicationID_ex = staticmethod(ca_openapplicationID_ex)
    exposed_ca_openapplicationID = staticmethod(ca_openapplicationID)
    exposed_ca_closeapplicationID_ex = staticmethod(ca_closeapplicationID_ex)
    exposed_ca_closeapplicationID = staticmethod(ca_closeapplicationID)
    exposed_ca_setapplicationID_ex = staticmethod(ca_setapplicationID_ex)
    exposed_ca_setapplicationID = staticmethod(ca_setapplicationID)
    exposed_ca_restart_ex = staticmethod(ca_restart_ex)
    exposed_ca_restart = staticmethod(ca_restart)
    exposed_ca_delete_container_with_handle = staticmethod(ca_delete_container_with_handle)
    exposed_ca_delete_container_with_handle_ex = staticmethod(ca_delete_container_with_handle_ex)

    #policy_management.py
    exposed_ca_set_hsm_policy = staticmethod(ca_set_hsm_policy)
    exposed_ca_set_hsm_policy_ex = staticmethod(ca_set_hsm_policy_ex)
    exposed_ca_set_destructive_hsm_policy = staticmethod(ca_set_destructive_hsm_policy)
    exposed_ca_set_destructive_hsm_policy_ex = staticmethod(ca_set_destructive_hsm_policy_ex)
    exposed_ca_set_container_policy = staticmethod(ca_set_container_policy)
    exposed_ca_set_container_policy_ex = staticmethod(ca_set_container_policy_ex)

    #object_attr_lookup.py
    exposed_c_find_objects = staticmethod(c_find_objects)
    exposed_c_find_objects_ex = staticmethod(c_find_objects_ex)
    exposed_c_get_attribute_value = staticmethod(c_get_attribute_value)
    exposed_c_get_attribute_value_ex = staticmethod(c_get_attribute_value_ex)
    exposed_c_set_attribute_value = staticmethod(c_set_attribute_value)
    exposed_c_set_attribute_value_ex = staticmethod(c_set_attribute_value_ex)

    #misc.py
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

    #key_generator.py
    exposed_c_generate_key = staticmethod(c_generate_key)
    exposed_c_generate_key_ex = staticmethod(c_generate_key_ex)
    exposed_c_generate_key_pair = staticmethod(c_generate_key_pair)
    exposed_c_generate_key_pair_ex = staticmethod(c_generate_key_pair_ex)
    exposed_c_destroy_object = staticmethod(c_destroy_object)
    exposed_c_destroy_object_ex = staticmethod(c_destroy_object_ex)
    exposed_c_copy_object = staticmethod(c_copy_object)
    exposed_c_copy_object_ex = staticmethod(c_copy_object_ex)

    #backup.py
    exposed_ca_extract = staticmethod(ca_extract)
    exposed_ca_extract_ex = staticmethod(ca_extract_ex)
    exposed_ca_insert = staticmethod(ca_insert)
    exposed_ca_insert_ex = staticmethod(ca_insert_ex)

    #audit_handling.py
    exposed_ca_get_time = staticmethod(ca_get_time)
    exposed_ca_get_time_ex = staticmethod(ca_get_time_ex)
    exposed_ca_init_audit = staticmethod(ca_init_audit)
    exposed_ca_init_audit_ex = staticmethod(ca_init_audit_ex)
    exposed_ca_time_sync = staticmethod(ca_time_sync)
    exposed_ca_time_sync_ex = staticmethod(ca_time_sync_ex)

    #hsm_management.py
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

    #key_management.py
    exposed_ca_generatemofn = staticmethod(ca_generatemofn)
    exposed_ca_generatemofn_ex = staticmethod(ca_generatemofn_ex)
    exposed_ca_modifyusagecount = staticmethod(ca_modifyusagecount)
    exposed_ca_modifyusagecount_ex = staticmethod(ca_modifyusagecount_ex)

    #key_usage.py
    exposed_ca_clonemofn = staticmethod(ca_clonemofn)
    exposed_ca_clonemofn_ex = staticmethod(ca_clonemofn_ex)
    exposed_ca_duplicatemofn = staticmethod(ca_duplicatemofn)
    exposed_ca_duplicatemofn_ex = staticmethod(ca_duplicatemofn_ex)

    @staticmethod
    def exposed_c_derive_key_ex(h_session, h_base_key, h_second_key, template, mech_flavor, mech=None):
        """
        #key_generator.py

        Wrapper around the default c_derive_key_ex. Have to do the mechanism creation on the daemon side
        because it involves pointers.
        """
        if mech:
            mech = _get_mechanism(mech)
            c_second_key = CK_ULONG(h_second_key)
            mech.pParameter = cast(pointer(c_second_key), CK_VOID_PTR)
            mech.usParameterLen = ctypes.sizeof(c_second_key)

        return c_derive_key_ex(h_session, h_base_key, template, mech_flavor, mech)

    @staticmethod
    def exposed_c_derive_key(h_session, h_base_key, h_second_key, template, mech_flavor, mech=None):
        """
        #key_generator.py

        Wrapper around the default c_derive_key_ex. Have to do the mechanism creation on the daemon side
        because it involves pointers.
        """
        if mech:
            mech = _get_mechanism(mech)
            c_second_key = CK_ULONG(h_second_key)
            mech.pParameter = cast(pointer(c_second_key), CK_VOID_PTR)
            mech.usParameterLen = ctypes.sizeof(c_second_key)

        return c_derive_key(h_session, h_base_key, template, mech_flavor, mech)


if __name__ == '__main__':
    from rpyc.utils.server import ThreadedServer

    parser = OptionParser()
    parser.add_option("-i", "--ip_address", dest="i",
                      help="pycryptoki daemon IP address", metavar="<IP address>")
    parser.add_option("-p", "--port", dest="p",
                      help="pycryptoki daemon IP port", metavar="<number>")
    (options, args) = parser.parse_args()

    #Default arguments
    ip = options.i if options.i != None else 'localhost'
    port = int(options.p if options.p != None else '8001')
    print "Pycryptoki Daemon ip=" + str(ip) + ", port=" + str(port)

    t = ThreadedServer(PycryptokiService,
                       hostname=ip,
                       port=port,
                       logger=logger,
                       protocol_config={'allow_public_attrs': True,
                                        'allow_all_attrs': True,
                                        'allow_getattr': True,
                                        'allow_setattr': True,
                                        'allow_delattr': True})
    print "Starting Server"
    t.start()














