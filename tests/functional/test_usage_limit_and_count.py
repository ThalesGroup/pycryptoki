"""
Created on Aug 15, 2012

@author: root
"""

import logging
import os
from collections import namedtuple

import pytest
from pycryptoki.sign_verify import c_sign_ex, c_sign

from pycryptoki.default_templates import get_default_key_pair_template, get_default_key_template
from pycryptoki.defines import CKM_DES_KEY_GEN, CKM_AES_KEY_GEN, CKM_DES3_KEY_GEN, \
    CKA_USAGE_LIMIT, CKA_USAGE_COUNT, CKM_DES3_ECB, \
    CKM_DES_ECB, CKR_KEY_NOT_ACTIVE, CKM_AES_ECB, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS
from pycryptoki.encryption import c_encrypt, c_encrypt_ex
from pycryptoki.key_generator import c_generate_key_ex, c_destroy_object, c_generate_key_pair_ex
from pycryptoki.object_attr_lookup import c_get_attribute_value_ex, c_set_attribute_value_ex

LOG = logging.getLogger(__name__)

NEW_USAGE_LIMIT = 5

KEY_PARAMS = [
    (CKM_DES_KEY_GEN, CKM_DES_ECB),
    (CKM_AES_KEY_GEN, CKM_AES_ECB),
    (CKM_DES3_KEY_GEN, CKM_DES3_ECB)
]

SymParams = namedtuple("SymParams", ["key", "mechanism"])


LUNA_1145_XFAIL = pytest.mark.xfail(reason="LUNA-1145: CKA_USAGE_LIMIT set 2x "
                                           "causes counting to no longer work")


@pytest.fixture(params=["create", "setattr",
                        LUNA_1145_XFAIL("both"),
                        LUNA_1145_XFAIL("create_then_use")])
def usage_set(request):
    """
    Parameterize tests to set up the CKA_USAGE_LIMIT in various forms:

    1. On creation
    2. After creation, via c_set_attr
    3. On creation, and then set it again
    4. On creation, use the key once, then set it again.
    """
    if request.param == "create_then_use":
        yield request.param, NEW_USAGE_LIMIT + 1
    else:
        yield request.param, NEW_USAGE_LIMIT


@pytest.fixture(params=KEY_PARAMS,
                ids=["DES", "AES", "DES3"])
def sym_key_params(request, auth_session, usage_set):
    """
    Generate a key, setting the usage limit by the method described in
    ``usage_set``

    Return that key handle.
    """
    usage_type, limit = usage_set
    key_gen, mechanism = request.param
    key_template = get_default_key_template(key_gen)
    usage_template = {CKA_USAGE_LIMIT: limit}
    if usage_type in ("create", "both", "create_then_use"):
        key_template.update(usage_template)

    h_key = c_generate_key_ex(auth_session,
                              mechanism=key_gen,
                              template=key_template)
    try:
        if usage_type in ("create_then_use",):
            c_encrypt_ex(auth_session, h_key, b'a' * 2048,
                         mechanism={"mech_type": mechanism})
        if usage_type in ("setattr", "both", "create_then_use"):
            c_set_attribute_value_ex(auth_session,
                                     h_key, usage_template)
        yield SymParams(h_key, mechanism)
    finally:
        c_destroy_object(auth_session, h_key)


def _get_data_file(filename):
    """
    Get absolute path to filename. Uses current directory as basis to find the testdata folder.

    :param str filename: Filename to append
    :return: full path to file
    """
    return os.path.join(os.path.split(os.path.abspath(__file__))[0], "testdata", filename)


@pytest.fixture()
def asym_key(auth_session, usage_set):
    """
    Generate a key pair & set the USAGE limit by some method (on creation or c_setattr, or both)

    :return: private key handle
    """
    usage_type, limit = usage_set
    pubtemp, privtemp = get_default_key_pair_template(CKM_RSA_PKCS_KEY_PAIR_GEN)
    usage_template = {CKA_USAGE_LIMIT: limit}
    if usage_type in ("create", "both", "create_then_use"):
        privtemp.update(usage_template)

    pubkey, privkey = c_generate_key_pair_ex(auth_session, CKM_RSA_PKCS_KEY_PAIR_GEN, pubtemp,
                                             privtemp)
    try:
        if usage_type == "create_then_use":

            with open(_get_data_file('sha1pkcs_plain.der'), 'rb') as df:
                data = df.read()
            c_sign_ex(auth_session, privkey, data, CKM_RSA_PKCS)

        if usage_type in ("setattr", "both", "create_then_use"):
            c_set_attribute_value_ex(auth_session, privkey, usage_template)
        yield privkey
    finally:
        c_destroy_object(auth_session, pubkey)
        c_destroy_object(auth_session, privkey)


class TestUsageLimitAndCount(object):
    """
    Verify Key usage attributes work
    """

    def test_usagelimit_no_use_sym(self, auth_session, sym_key_params, usage_set):
        """Verify that CKA_USAGE_LIMIT is reported correctly by C_GetAttribute
        """
        LOG.info("Test: Verify that user is able to set CKA_USAGE_LIMIT attribute on \
                  an symmetric crypto object")
        _, new_limit = usage_set
        key, _ = sym_key_params
        out_template = c_get_attribute_value_ex(auth_session, key,
                                                template={CKA_USAGE_LIMIT: None})

        usage_val_out = out_template[CKA_USAGE_LIMIT]
        LOG.info("CKA_USAGE_LIMIT reported by C_GetAttributeValue :%s", usage_val_out)
        assert new_limit == usage_val_out, "reported USAGE LIMIT does not match"

    def test_usagelimit_sym(self, auth_session, sym_key_params, usage_set):
        """Test: Verify that CKA_USAGE_COUNT attribute increments as user
                  uses the symmetric crypto object

          Gen key w/ limit set to 5
          Use key 5x
          Verify usage count == 5
        """
        _, new_limit = usage_set
        LOG.info("Test: Verify that CKA_USAGE_COUNT attribute increments as user \
                  uses the symmetric crypto object")

        key, mechanism = sym_key_params

        for _ in range(5):
            c_encrypt_ex(auth_session, key, b'a' * 2048,
                         mechanism={"mech_type": mechanism})

        py_template = c_get_attribute_value_ex(auth_session, key,
                                               template={CKA_USAGE_COUNT: None})

        usage_val_out = py_template[CKA_USAGE_COUNT]
        LOG.info("CKA_USAGE_COUNT reported by C_GetAttributeValue: %s", usage_val_out)

        assert new_limit == usage_val_out, "reported USAGE LIMIT does not match"

    @LUNA_1145_XFAIL
    def test_usagelimit_exceed_sym(self, auth_session, sym_key_params):
        """Test that changing the usage limit works as expected

           Gen key w/ limit = 5
           Set limit = 2
           Use key 2x
           Verify next usage returns CKR_KEY_NOT_ACTIVE
        """
        LOG.info("Verify that crypto operation returns error CKR_KEY_NOT_ACTIVE \
                  if user try to use crypto object more than limit set on CKA_USAGE_LIMIT")
        usage_lim_template = {CKA_USAGE_LIMIT: 2}

        key, mechanism = sym_key_params

        c_set_attribute_value_ex(auth_session,
                                 key, usage_lim_template)

        c_encrypt_ex(auth_session, key, b'a' * 2048, mechanism=mechanism)

        c_encrypt_ex(auth_session, key, b'a' * 2048, mechanism=mechanism)

        return_val, data = c_encrypt(auth_session, key, b'a' * 2048,
                                     mechanism=mechanism)

        py_template = c_get_attribute_value_ex(auth_session, key,
                                               template={CKA_USAGE_COUNT: None})

        usage_val_out = py_template[CKA_USAGE_COUNT]
        LOG.info("CKA_USAGE_COUNT reported by C_GetAttributeValue: %s", usage_val_out)
        assert return_val == CKR_KEY_NOT_ACTIVE, "Key should be inactive -- exceeded usage count!"

    def test_asym_withusage(self, auth_session, asym_key):
        """
        Test that USAGE_LIMIT works with asymmetric keys (private) too.
        """
        key = asym_key
        with open(_get_data_file('sha1pkcs_plain.der'), 'rb') as df:
            data = df.read()

        for _ in range(5):
            c_sign_ex(auth_session, key, data, CKM_RSA_PKCS)

        return_val, data = c_sign(auth_session, key, data, CKM_RSA_PKCS)
        py_template = c_get_attribute_value_ex(auth_session, key,
                                               template={CKA_USAGE_COUNT: None})

        usage_val_out = py_template[CKA_USAGE_COUNT]
        LOG.info("CKA_USAGE_COUNT reported by C_GetAttributeValue: %s", usage_val_out)
        assert return_val == CKR_KEY_NOT_ACTIVE, "Key should be inactive -- exceeded usage count!"
