#!/usr/bin/env python
"""
xmlrpc server daemon that wraps pycryptoki so pycryptoki can be used over
the network
"""
from ConfigParser import ConfigParser
from SimpleXMLRPCServer import SimpleXMLRPCServer
from optparse import OptionParser
import xmlrpclib
from _ctypes import pointer
from ctypes import cast
import ctypes

from pycryptoki.backup import ca_open_secure_token, ca_close_secure_token, \
    ca_open_secure_token_ex, ca_close_secure_token_ex, ca_extract, ca_extract_ex, \
    ca_insert, ca_insert_ex
from pycryptoki.encryption import c_encrypt, c_encrypt_ex, c_decrypt, \
    c_decrypt_ex, c_wrap_key, c_wrap_key_ex, c_unwrap_key, c_unwrap_key_ex
from pycryptoki.key_generator import c_destroy_object, c_destroy_object_ex, \
    c_generate_key_pair, c_generate_key_pair_ex, c_generate_key, c_generate_key_ex, \
    c_derive_key, c_derive_key_ex
from pycryptoki.misc import c_generate_random, c_generate_random_ex, \
    c_seed_random, c_seed_random_ex, c_digest, c_digest_ex, c_set_ped_id, \
    c_set_ped_id_ex, c_get_ped_id, c_get_ped_id_ex, c_create_object, \
    c_create_object_ex
from pycryptoki.object_attr_lookup import c_find_objects, c_find_objects_ex, \
    c_get_attribute_value, c_get_attribute_value_ex, c_set_attribute_value, c_set_attribute_value_ex
from pycryptoki.policy_management import ca_set_container_policy, ca_set_container_policy_ex
from pycryptoki.hsm_management import ca_set_hsm_policy, ca_set_hsm_policy_ex, \
    ca_set_destructive_hsm_policy, ca_set_destructive_hsm_policy_ex
from pycryptoki.session_management import c_initialize, c_initialize_ex, \
    c_finalize, c_finalize_ex, c_open_session, c_open_session_ex, c_get_token_info, \
    c_get_token_info_ex, c_close_session, c_close_session_ex, c_logout, c_logout_ex, \
    c_init_pin, c_init_pin_ex, ca_factory_reset, ca_factory_reset_ex, c_set_pin, \
    c_set_pin_ex, c_close_all_sessions, c_close_all_sessions_ex, ca_create_container, \
    ca_create_container_ex, login, login_ex
from pycryptoki.sign_verify import c_sign, c_sign_ex, c_verify, c_verify_ex
from pycryptoki.token_management import c_init_token, c_init_token_ex, \
    c_get_mechanism_list, c_get_mechanism_list_ex, c_get_mechanism_info, \
    c_get_mechanism_info_ex, get_token_by_label, get_token_by_label_ex
from pycryptoki.audit_handling import ca_get_time, ca_get_time_ex, ca_init_audit, \
    ca_init_audit_ex, ca_time_sync, ca_time_sync_ex
from pycryptoki.key_generator import _get_mechanism
from pycryptoki.cryptoki import CK_ULONG, CK_VOID_PTR

'''
All the functions the server supports
'''
pycryptoki_functions = {"c_wrap_key" : c_wrap_key,
                        "c_wrap_key_ex" : c_wrap_key_ex,
                        "c_unwrap_key" : c_unwrap_key,
                        "c_unwrap_key_ex" : c_unwrap_key_ex,
                        "c_destroy_object" : c_destroy_object,
                        "c_destroy_object_ex" : c_destroy_object_ex,
                        "c_generate_random" : c_generate_random,
                        "c_generate_random_ex" : c_generate_random_ex,
                        "c_seed_random" : c_seed_random,
                        "c_seed_random_ex" : c_seed_random_ex,
                        "c_digest" : c_digest,
                        "c_digest_ex" : c_digest_ex,
                        "c_set_ped_id" : c_set_ped_id,
                        "c_set_ped_id_ex" : c_set_ped_id_ex,
                        "c_get_ped_id" : c_get_ped_id,
                        "c_get_ped_id_ex" : c_get_ped_id_ex,
                        "ca_set_hsm_policy" : ca_set_hsm_policy,
                        "ca_set_hsm_policy_ex" : ca_set_hsm_policy_ex,
                        "ca_set_destructive_hsm_policy" : ca_set_destructive_hsm_policy,
                        "ca_set_destructive_hsm_policy_ex" : ca_set_destructive_hsm_policy_ex,
                        "ca_set_container_policy" : ca_set_container_policy,
                        "ca_set_container_policy_ex" : ca_set_container_policy_ex,
                        "c_initialize" : c_initialize,
                        "c_initialize_ex" : c_initialize_ex,
                        "c_finalize" : c_finalize,
                        "c_finalize_ex" : c_finalize_ex,
                        "c_open_session" : c_open_session,
                        "c_open_session_ex" : c_open_session_ex,
                        "login" : login,
                        "login_ex" : login_ex,
                        "c_get_token_info" : c_get_token_info,
                        "c_get_token_info_ex" : c_get_token_info_ex,
                        "c_close_session" : c_close_session,
                        "c_close_session_ex" : c_close_session_ex,
                        "c_logout" : c_logout,
                        "c_logout_ex" : c_logout_ex,
                        "c_init_pin" : c_init_pin,
                        "c_init_pin_ex" : c_init_pin_ex,
                        "ca_factory_reset" : ca_factory_reset,
                        "ca_factory_reset_ex" : ca_factory_reset_ex,
                        "c_set_pin" : c_set_pin,
                        "c_set_pin_ex" : c_set_pin_ex,
                        "c_close_all_sessions" : c_close_all_sessions,
                        "c_close_all_sessions_ex" : c_close_all_sessions_ex,
                        "ca_create_container" : ca_create_container,
                        "ca_create_container_ex" : ca_create_container_ex,
                        "c_init_token" : c_init_token,
                        "c_init_token_ex" : c_init_token_ex,
                        "c_get_mechanism_list" : c_get_mechanism_list,
                        "c_get_mechanism_list_ex" : c_get_mechanism_list_ex,
                        "c_get_mechanism_info" : c_get_mechanism_info,
                        "c_get_mechanism_info_ex" : c_get_mechanism_info_ex,
                        "get_token_by_label" : get_token_by_label,
                        "get_token_by_label_ex" : get_token_by_label_ex,
                        "ca_close_secure_token" : ca_close_secure_token,
                        "ca_close_secure_token_ex" : ca_close_secure_token_ex,
                        "ca_open_secure_token" : ca_open_secure_token,
                        "ca_open_secure_token_ex" : ca_open_secure_token_ex,
                        "ca_extract" : ca_extract,
                        "ca_extract_ex" : ca_extract_ex,
                        "ca_insert" : ca_insert,
                        "ca_insert_ex" : ca_insert_ex,
                        "c_set_attribute_value" : c_set_attribute_value,
                        "c_set_attribute_value_ex" : c_set_attribute_value_ex,
                        "c_generate_key" : c_generate_key,
                        "c_generate_key_ex" : c_generate_key_ex,
                        "c_generate_key_pair" : c_generate_key_pair,
                        "c_generate_key_pair_ex" : c_generate_key_pair_ex,
                        "c_create_object" : c_create_object,
                        "c_create_object_ex" : c_create_object_ex,
                        "ca_get_time": ca_get_time,
                        "ca_get_time_ex": ca_get_time_ex,
                        "ca_init_audit": ca_init_audit,
                        "ca_init_audit_ex": ca_init_audit_ex,
                        "ca_time_sync": ca_time_sync,
                        "ca_time_sync_ex": ca_time_sync_ex
                        }

'''
Functions with arguments/return values that need specialized
serialization/deserialization
'''
functions_needing_serialization = {
                                   "c_find_objects" : c_find_objects,
                                   "c_find_objects_ex" : c_find_objects_ex,
                                   "c_get_attribute_value" : c_get_attribute_value,
                                   "c_get_attribute_value_ex" : c_get_attribute_value_ex,
                                   "c_sign": c_sign,
                                   "c_sign_ex": c_sign_ex,
                                   "c_encrypt": c_encrypt,
                                   "c_encrypt_ex": c_encrypt_ex,
                                   "c_verify" : c_verify,
                                   "c_verify_ex" : c_verify_ex,
                                   "c_derive_key" : c_derive_key,
                                   "c_derive_key_ex" : c_derive_key_ex,
                                   "c_decrypt_ex" : c_decrypt_ex,
                                   "c_decrypt" : c_decrypt
                                   }


def initialize_server(ip, port):
    """

    :param ip:
    :param port:

    """
    print "Initializing Server"
    server = SimpleXMLRPCServer((ip, port))
    server.logRequests = 0

    #Dynamically add functions to server
    for key, value in pycryptoki_functions.iteritems():
        server.register_function(value, key)

    #For functions that need better serialization, do it
    for key, value in functions_needing_serialization.iteritems():
        server.register_function(eval(key + "_serialize"), key)

    return server


def serialize_dict(dictionary):
    """Helper function to convert a dictionary with <int, value> to <string, value>
    for xmlrpc

    :param dictionary:

    """
    serialized_dictionary = {}
    for key, value in dictionary.iteritems():
        serialized_dictionary[str(key)] = value
    return serialized_dictionary

def c_get_attribute_value_serialize(h_session, h_object, template):
    """returns dictionary with k,v pairs of <string, value> for xmlrpc

    :param h_session:
    :param h_object:
    :param template:

    """
    ret, dictionary = c_get_attribute_value(h_session, h_object, template)
    return ret, serialize_dict(dictionary)

def c_get_attribute_value_ex_serialize(h_session, h_object, template):
    """returns dictionary with k,v pairs of <string, value> for xmlrpc

    :param h_session:
    :param h_object:
    :param template:

    """
    dictionary = c_get_attribute_value_ex(h_session, h_object, template)
    return serialize_dict(dictionary)

def c_find_objects_serialize(h_session, h_object, template):
    """returns dictionary with k,v pairs of <string, value> for xmlrpc

    :param h_session:
    :param h_object:
    :param template:

    """
    ret, dictionary = c_find_objects(h_session, h_object, template)
    return ret, serialize_dict(dictionary)

def c_find_objects_ex_serialize(h_session, h_object, template):
    """returns dictionary with k,v pairs of <string, value> for xmlrpc

    :param h_session:
    :param h_object:
    :param template:

    """
    dictionary = c_find_objects_ex(h_session, h_object, template)
    return serialize_dict(dictionary)

def c_derive_key_serialize(h_session, h_base_key, h_second_key, template, mech_flavor, mech = None):
    """

    :param h_session:
    :param h_base_key:
    :param h_second_key:
    :param template:
    :param mech_flavor:
    :param mech:  (Default value = None)

    """
    if mech:
        mech = _get_mechanism(mech)
        c_second_key = CK_ULONG(h_second_key)
        mech.pParameter = cast(pointer(c_second_key), CK_VOID_PTR)
        mech.usParameterLen = ctypes.sizeof(c_second_key)

    return c_derive_key(h_session, h_base_key, template, mech_flavor, mech)

def c_derive_key_ex_serialize(h_session, h_base_key, h_second_key, template, mech_flavor, mech = None):
    """

    :param h_session:
    :param h_base_key:
    :param h_second_key:
    :param template:
    :param mech_flavor:
    :param mech:  (Default value = None)

    """
    if mech:
        mech = _get_mechanism(mech)
        c_second_key = CK_ULONG(h_second_key)
        mech.pParameter = cast(pointer(c_second_key), CK_VOID_PTR)
        mech.usParameterLen = ctypes.sizeof(c_second_key)

    return c_derive_key_ex(h_session, h_base_key, template, mech_flavor, mech)

def c_sign_serialize(h_session, sign_flavor, data_to_sign, h_key, mech = None):
    """

    :param h_session:
    :param sign_flavor:
    :param data_to_sign:
    :param h_key:
    :param mech:  (Default value = None)

    """
    ret, signature = c_sign(h_session, sign_flavor, data_to_sign, h_key, mech)
    return ret, xmlrpclib.Binary(signature)

def c_sign_ex_serialize(h_session, sign_flavor, data_to_sign, h_key, mech = None):
    """

    :param h_session:
    :param sign_flavor:
    :param data_to_sign:
    :param h_key:
    :param mech:  (Default value = None)

    """
    signature = c_sign_ex(h_session, sign_flavor, data_to_sign, h_key, mech)
    return xmlrpclib.Binary(signature)

def c_encrypt_serialize(h_session, encryption_flavor, h_key, data_to_encrypt, mech = None):
    """

    :param h_session:
    :param encryption_flavor:
    :param h_key:
    :param data_to_encrypt:
    :param mech:  (Default value = None)

    """
    ret, enc_data = c_encrypt(h_session, encryption_flavor, h_key, data_to_encrypt, mech)
    return ret, xmlrpclib.Binary(enc_data)

def c_encrypt_ex_serialize(h_session, encryption_flavor, h_key, data_to_encrypt, mech = None):
    """

    :param h_session:
    :param encryption_flavor:
    :param h_key:
    :param data_to_encrypt:
    :param mech:  (Default value = None)

    """
    enc_data = c_encrypt_ex(h_session, encryption_flavor, h_key, data_to_encrypt, mech)
    return xmlrpclib.Binary(enc_data)

def c_verify_serialize( h_session, h_key, verify_flavor, data_to_verify, signature, mech = None):
    """

    :param h_session:
    :param h_key:
    :param verify_flavor:
    :param data_to_verify:
    :param signature:
    :param mech:  (Default value = None)

    """
    return c_verify(h_session, h_key, verify_flavor, data_to_verify, signature.data, mech)

def c_verify_ex_serialize(h_session, h_key, verify_flavor, data_to_verify, signature, mech = None):
    """

    :param h_session:
    :param h_key:
    :param verify_flavor:
    :param data_to_verify:
    :param signature:
    :param mech:  (Default value = None)

    """
    return c_verify_ex(h_session, h_key, verify_flavor, data_to_verify, signature.data, mech)

def c_decrypt(h_session, decrypt_flavor, h_key, encrypted_data, mech = None):
    """

    :param h_session:
    :param decrypt_flavor:
    :param h_key:
    :param encrypted_data:
    :param mech:  (Default value = None)

    """
    return c_decrypt(h_session, decrypt_flavor, h_key, encrypted_data.data, mech)

def c_decrypt_ex(h_session, decrypt_flavor, h_key, encrypted_data, mech = None):
    """

    :param h_session:
    :param decrypt_flavor:
    :param h_key:
    :param encrypted_data:
    :param mech:  (Default value = None)

    """
    return c_decrypt_ex(h_session, decrypt_flavor, h_key, encrypted_data.data, mech)

if __name__ == '__main__':
    #Setup argument parser
    resources_config_parser = ConfigParser()
    parser = OptionParser()
    parser.add_option("-i", "--ip_address", dest="i",
                      help="pycryptoki daemon IP address", metavar="<IP address>")
    parser.add_option("-p", "--port", dest="p",
                      help="pycryptoki daemon IP port", metavar="<number>")
    (options, args) = parser.parse_args()

    #Default arguments
    ip = options.i if options.i is not None else 'localhost'
    port = int( options.p if options.p is not None else '8001')
    print "Pycryptoki Daemon ip=" + str(ip) + ", port=" + str(port)

    server = initialize_server(ip, port)

    # run until we die
    print "Starting Server"
    server.serve_forever()
