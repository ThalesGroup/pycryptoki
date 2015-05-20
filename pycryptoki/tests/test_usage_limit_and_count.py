"""
Created on Aug 15, 2012

@author: root
"""

import logging
import os

import pytest

from pycryptoki.attributes import Attributes
from pycryptoki.cryptoki import CK_ULONG, C_SetAttributeValue
from pycryptoki.default_templates import CKM_DES_KEY_GEN_TEMP, CKM_DES3_KEY_GEN_TEMP, \
     CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP, CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP, CKM_AES_KEY_GEN_TEMP
from pycryptoki.defaults import CO_PASSWORD, ADMIN_PARTITION_LABEL
from pycryptoki.defines import CKM_DES_KEY_GEN, CKM_AES_KEY_GEN, CKM_DES3_KEY_GEN, \
    CKA_USAGE_LIMIT, CKA_USAGE_COUNT, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_DES3_ECB, \
    CKM_DES_ECB, CKM_RSA_PKCS, CKR_OK, CKR_KEY_NOT_ACTIVE, CKU_USER, CKM_AES_ECB
from pycryptoki.encryption import c_encrypt, c_encrypt_ex
from pycryptoki.key_generator import c_generate_key_ex, c_generate_key_pair_ex
from pycryptoki.session_management import login_ex
from pycryptoki.object_attr_lookup import c_get_attribute_value_ex
from pycryptoki.session_management import c_initialize_ex, c_open_session_ex, c_logout_ex, \
        c_close_session_ex, c_finalize
from pycryptoki.test_functions import LunaException
from pycryptoki.tests.setup_for_tests import setup_for_tests
from pycryptoki.token_management import get_token_by_label_ex

logger = logging.getLogger(__name__)

class TestUsageLimitAndCount:
    """ """

    h_session = 0

    def setup(self):
        """ """
        setup_for_tests(True, True, True)
        c_initialize_ex()
        admin_slot = get_token_by_label_ex(ADMIN_PARTITION_LABEL)
        self.h_session = c_open_session_ex(slot_num=admin_slot)
        login_ex(self.h_session, admin_slot, CO_PASSWORD, CKU_USER)


    def teardown(self):
        """ """
        c_logout_ex(self.h_session)
        c_close_session_ex(self.h_session)
        c_finalize()

    def test_set_attribute_usage_limit_sym(self):
        """Test: Verify that user is able to set CKA_USAGE_LIMIT attribute on
                  an symmetric crypto object
            Procedure:
            Generate a DES Key
            Use C_SetAttributeValue to set CKA_USAGE_LIMIT to 5
            Use C_getAttributeValue to verify


        """

        logger.info("Test: Verify that user is able to set CKA_USAGE_LIMIT attribute on \
                  an symmetric crypto object")

        CKM_USAGE_CHECK_TEMP = {CKA_USAGE_COUNT : 0,
                    CKA_USAGE_LIMIT :  5}

        h_key = c_generate_key_ex(self.h_session, flavor=CKM_DES_KEY_GEN, template=CKM_DES_KEY_GEN_TEMP)
        logger.info("Called c-generate: Key handle -" + str(h_key))
        usage_limit = 5


        key_attributes = Attributes(CKM_USAGE_CHECK_TEMP)
        us_public_template_size = CK_ULONG(len(CKM_USAGE_CHECK_TEMP))

        return_value = C_SetAttributeValue(self.h_session, h_key, key_attributes.get_c_struct(), us_public_template_size)
        if return_value != CKR_OK: raise LunaException(return_value, 'C_SetAttributeValue', "Setting up limit attribute")

        c_struct = c_get_attribute_value_ex(self.h_session, h_key, template=CKM_USAGE_CHECK_TEMP)
#        print c_struct[CKA_USAGE_LIMIT]
        usage_val_out = CK_ULONG(c_struct[CKA_USAGE_LIMIT]).value
        logger.info("CKA_USAGE_LIMIT reported by C_GetAttributeValue :" + str(int(usage_val_out)))
        assert usage_limit== usage_val_out, "reported USAGE LIMIT does not match"




    def test_usage_limit_attribute_check_sym_des(self):
        """Test: Verify that CKA_USAGE_COUNT attribute increments as user
                  use the symmetric crypto object
            Procedure:
            Generate a DES Key
            Use C_SetAttributeValue to set CKA_USAGE_LIMIT to 2
            Use des key twice for encryption
            Use C_getAttributeValue to verify that CKA_USAGE_COUNT is 2


        """
        logger.info("Test: Verify that CKA_USAGE_COUNT attribute increments as user \
                  use the symmetric crypto object")
        CKM_USAGE_CHECK_TEMP = {CKA_USAGE_COUNT : 0,
                    CKA_USAGE_LIMIT :  2}
        key_attributes = Attributes(CKM_USAGE_CHECK_TEMP)
        us_public_template_size = CK_ULONG(len(CKM_USAGE_CHECK_TEMP))

        usage_count = 2

        h_key = c_generate_key_ex(self.h_session, flavor=CKM_DES_KEY_GEN, template=CKM_DES_KEY_GEN_TEMP)
        logger.info("Called c-generate: Key handle -" + str(h_key))
        return_value = C_SetAttributeValue(self.h_session, h_key, key_attributes.get_c_struct(), us_public_template_size)
        if return_value != CKR_OK: raise LunaException(return_value, 'C_SetAttributeValue', "Setting up limit attribute")

        c_encrypt_ex(self.h_session, CKM_DES_ECB, h_key, 'a' * 2048)

        c_encrypt_ex(self.h_session, CKM_DES_ECB, h_key, 'a' * 2048)


        c_struct = c_get_attribute_value_ex(self.h_session, h_key, template=CKM_USAGE_CHECK_TEMP)


        usage_val_out = CK_ULONG(c_struct[CKA_USAGE_COUNT]).value
        logger.info("CKA_USAGE_COUNT reported by C_GetAttributeValue :" + str(usage_val_out))

        assert usage_count == usage_val_out, "reported USAGE LIMIT does not match"




    def test_usage_limit_attribute_check_sym_aes(self):

        """Test: Verify that CKA_USAGE_COUNT attribute increments as user
                  use the symmetric crypto object
            Procedure:
            Generate a DES Key
            Use C_SetAttributeValue to set CKA_USAGE_LIMIT to 2
            Use aes key twice for encryption
            Use C_getAttributeValue to verify that CKA_USAGE_COUNT is 2


        """
        logger.info("Test: Verify that CKA_USAGE_COUNT attribute increments as user \
                  use the symmetric crypto object")
        CKM_USAGE_CHECK_TEMP = {CKA_USAGE_COUNT : 0,
                    CKA_USAGE_LIMIT :  2}
        key_attributes = Attributes(CKM_USAGE_CHECK_TEMP)
        us_public_template_size = CK_ULONG(len(CKM_USAGE_CHECK_TEMP))

        usage_count = 2

        h_key = c_generate_key_ex(self.h_session, flavor=CKM_AES_KEY_GEN, template=CKM_AES_KEY_GEN_TEMP)
        logger.info("Called c-generate: Key handle -" + str(h_key))
        return_value = C_SetAttributeValue(self.h_session, h_key, key_attributes.get_c_struct(), us_public_template_size)
        if return_value != CKR_OK: raise LunaException(return_value, 'C_SetAttributeValue', "Setting up limit attribute")
        c_encrypt_ex(self.h_session, CKM_AES_ECB, h_key, 'a' * 2048)

        c_encrypt_ex(self.h_session, CKM_AES_ECB, h_key, 'a' * 2048)


        c_struct = c_get_attribute_value_ex(self.h_session, h_key, template=CKM_USAGE_CHECK_TEMP)


        usage_val_out = CK_ULONG(c_struct[CKA_USAGE_COUNT]).value
        logger.info("CKA_USAGE_COUNT reported by C_GetAttributeValue :" + str(usage_val_out))

        assert usage_count == usage_val_out, "reported USAGE LIMIT does not match"



    def test_set_attribute_usage_limit_Assym(self):
        """Test: Verify that user is able to set CKA_USAGE_LIMIT attribute on
                  an assymetric crypto object
            Procedure:
            Generate a RSA key pair
            Use C_SetAttributeValue to set CKA_USAGE_LIMIT to 2 on RSA public key
            Use C_getAttributeValue to verify


        """

        logger.info("Test: Verify that user is able to set CKA_USAGE_LIMIT attribute on \
                  an assymetric crypto object")
        CKM_USAGE_CHECK_TEMP = {CKA_USAGE_COUNT : 0,
                    CKA_USAGE_LIMIT :  2}
        key_attributes = Attributes(CKM_USAGE_CHECK_TEMP)
        us_public_template_size = CK_ULONG(len(CKM_USAGE_CHECK_TEMP))

        h_pbkey, h_prkey = c_generate_key_pair_ex(self.h_session, flavor=CKM_RSA_PKCS_KEY_PAIR_GEN,
                               pbkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP,
                               prkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP,
                               mech=None)
        logger.info("Called c-generate: Public Key handle -" + str(h_pbkey) + "Private Key Handle" + str(h_prkey))
        usage_limit = 2

        return_val = C_SetAttributeValue(self.h_session, h_pbkey, key_attributes.get_c_struct(), us_public_template_size)
        if return_val != CKR_OK: raise LunaException(return_val, 'C_SetAttributeValue', "Setting up attribute")

        c_struct = c_get_attribute_value_ex(self.h_session, h_pbkey, template=CKM_USAGE_CHECK_TEMP)
        usage_val_out = CK_ULONG(c_struct[CKA_USAGE_LIMIT]).value
        logger.info("CKA_USAGE_LIMIT reported by C_GetAttributeValue :" + str(usage_val_out))
        assert usage_limit == usage_val_out, "reported USAGE LIMIT does not match"





    def test_usage_limit_attribute_check_Assym(self):
        """Test: Verify that CKA_USAGE_COUNT attribute increments as user
                  use the assymetric crypto object
            Procedure:
            Generate a RSA Key pair
            Use C_SetAttributeValue to set CKA_USAGE_LIMIT to 2
            Use RSA public key twice for encryption
            Use C_getAttributeValue to verify that CKA_USAGE_COUNT is 2


        """

        logger.info("Test: Verify that CKA_USAGE_COUNT attribute increments as user \
                  use the assymetric crypto object")

        CKM_USAGE_CHECK_TEMP = {CKA_USAGE_COUNT : 0,
                    CKA_USAGE_LIMIT :  2}
        usage_count = 2
        key_attributes = Attributes(CKM_USAGE_CHECK_TEMP)
        us_public_template_size = CK_ULONG(len(CKM_USAGE_CHECK_TEMP))

        h_pbkey, h_prkey = c_generate_key_pair_ex(self.h_session, flavor=CKM_RSA_PKCS_KEY_PAIR_GEN,
                               pbkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP,
                               prkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP, mech=None)


        logger.info("Called c-generate: Public Key handle -" + str(h_pbkey) + "Private Key Handle" + str(h_prkey))

        return_value = C_SetAttributeValue(self.h_session, h_pbkey, key_attributes.get_c_struct(), us_public_template_size)
        if return_value != CKR_OK: raise LunaException(return_value, 'C_SetAttributeValue', "Setting up limit attribute")
        c_encrypt_ex(self.h_session, CKM_RSA_PKCS, h_pbkey, 'a' * 20)

        c_encrypt_ex(self.h_session, CKM_RSA_PKCS, h_pbkey, 'a' * 20)


        c_struct = c_get_attribute_value_ex(self.h_session, h_pbkey, template=CKM_USAGE_CHECK_TEMP)

        usage_val_out = CK_ULONG(c_struct[CKA_USAGE_COUNT]).value
        logger.info("CKA_USAGE_COUNT reported by C_GetAttributeValue :" + str(usage_val_out))
        assert usage_count == usage_val_out, "reported USAGE LIMIT does not match"


    def test_set_attribute_usage_count_check_error_CKR_KEY_NOT_ACTIVE_3des(self):

        """Test: Verify that crypto operation returns error CKR_KEY_NOT_ACTIVE
                  if user try to use crypto object more than limit set on CKA_USAGE_LIMIT
            Procedure:
            Generate a 3DES key
            Use C_SetAttributeValue to set CKA_USAGE_LIMIT to 2
            Use RSA public key 3 times for encryption


        """

        logger.info("Verify that crypto operation returns error CKR_KEY_NOT_ACTIVE \
                  if user try to use crypto object more than limit set on CKA_USAGE_LIMIT")
        CKM_USAGE_CHECK_TEMP = {CKA_USAGE_COUNT : 0,
                    CKA_USAGE_LIMIT :  2}
        key_attributes = Attributes(CKM_USAGE_CHECK_TEMP)
        us_public_template_size = CK_ULONG(len(CKM_USAGE_CHECK_TEMP))


        h_key = c_generate_key_ex(self.h_session, flavor=CKM_DES3_KEY_GEN, template=CKM_DES3_KEY_GEN_TEMP)
        logger.info("Called c-generate: Key handle -" + str(h_key))
        return_val = C_SetAttributeValue(self.h_session, h_key, key_attributes.get_c_struct(), us_public_template_size)
        if return_val != CKR_OK: raise LunaException(return_val, 'C_setAttributeValue', "Setting up limit attribute")

        c_encrypt_ex(self.h_session, CKM_DES3_ECB, h_key, 'a' * 2048)

        c_encrypt_ex(self.h_session, CKM_DES3_ECB, h_key, 'a' * 2048)

        return_val = c_encrypt(self.h_session, CKM_DES3_ECB, h_key, 'a' * 2048)
        logger.info("Called C_Encrypt, return code: " + str(return_val))

        c_struct = c_get_attribute_value_ex(self.h_session, h_key, template=CKM_USAGE_CHECK_TEMP)


        usage_val_out = CK_ULONG(c_struct[CKA_USAGE_COUNT]).value
        logger.info("CKA_USAGE_COUNT reported by C_GetAttributeValue :" + str(usage_val_out))

        assert return_val == CKR_KEY_NOT_ACTIVE, "reported error code does not match"




    def test_set_attribute_usage_count_check_error_CKR_KEY_NOT_ACTIVE_rsa(self):

        """Test: Verify that crypto operation returns error CKR_KEY_NOT_ACTIVE
                  if user try to use crypto object more than limit set on CKA_USAGE_LIMIT
            Procedure:
            Generate a RSA Key pair
            Use C_SetAttributeValue to set CKA_USAGE_LIMIT to 2
            Use RSA public key 3 times for encryption


        """

        CKM_USAGE_CHECK_TEMP = {CKA_USAGE_COUNT : 0,
                    CKA_USAGE_LIMIT :  2}

        key_attributes = Attributes(CKM_USAGE_CHECK_TEMP)
        us_public_template_size = CK_ULONG(len(CKM_USAGE_CHECK_TEMP))



        h_pbkey, h_prkey = c_generate_key_pair_ex(self.h_session, flavor=CKM_RSA_PKCS_KEY_PAIR_GEN,
                               pbkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP,
                               prkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP,
                               mech=None)

        logger.info("Called c-generate: Public Key handle -" + str(h_pbkey) + "Private Key Handle" + str(h_prkey))

        return_value = C_SetAttributeValue(self.h_session, h_pbkey, key_attributes.get_c_struct(), us_public_template_size)
        if return_value != CKR_OK: raise LunaException(return_value, 'C_SetAttributeValue', "Setting up limit attribute")

        c_encrypt_ex(self.h_session, CKM_RSA_PKCS, h_pbkey, 'a' * 20)

        c_encrypt_ex(self.h_session, CKM_RSA_PKCS, h_pbkey, 'a' * 20)

        return_val = c_encrypt(self.h_session, CKM_RSA_PKCS, h_pbkey, 'a' * 20)
        logger.info("Called C_Encrypt, return code: " + str(return_val))
        c_struct = c_get_attribute_value_ex(self.h_session, h_pbkey, template=CKM_USAGE_CHECK_TEMP)

        usage_val_out = CK_ULONG(c_struct[CKA_USAGE_COUNT]).value
        assert return_val == CKR_KEY_NOT_ACTIVE, "reported error code does not match"



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-s', os.path.abspath(__file__)])

