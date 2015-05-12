from ctypes import *
from datetime import datetime
import math
from pycryptoki.defaults import ADMIN_PARTITION_LABEL, CO_PASSWORD, AUDITOR_PASSWORD, AUDITOR_LABEL
from pycryptoki.defines import CKF_SERIAL_SESSION,CKM_DES_KEY_GEN, CKU_USER,  \
    CKA_END_DATE, CKU_AUDIT, CKF_AUDIT_SESSION
from pycryptoki.defines import CKA_CLASS, CKO_SECRET_KEY, CKA_KEY_TYPE, CKK_DES, CKA_TOKEN, \
    CKA_SENSITIVE, CKA_PRIVATE, CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, \
    CKA_WRAP, CKA_UNWRAP, CKA_DERIVE, CKA_VALUE_LEN, CKA_EXTRACTABLE, CKA_LABEL, \
    CKA_MODIFIABLE, CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT, CKA_PRIME, CKA_SUBPRIME, CKA_BASE, \
    CKK_AES, CKM_DES_ECB, CKU_SO, CKR_KEY_NOT_ACTIVE, CKM_RSA_PKCS_KEY_PAIR_GEN, \
    CKM_RSA_PKCS, CKM_AES_ECB, CKM_AES_KEY_GEN, CKM_DSA_KEY_PAIR_GEN, CKM_DSA_SHA1
from pycryptoki.default_templates import dsa_prime_1024_160, dsa_sub_prime_1024_160, dsa_base_1024_160
from pycryptoki.key_generator import c_generate_key_ex, c_generate_key_pair_ex
from pycryptoki.session_management import c_initialize_ex, login, c_finalize, c_open_session_ex, login_ex, \
     c_logout_ex, c_close_session_ex
from pycryptoki.tests.setup_for_tests import setup_for_tests
from pycryptoki.token_management import get_token_by_label_ex
from pycryptoki.attributes import date_attrb
from pycryptoki.dictionary_handling import CDict
from pycryptoki.encryption import c_encrypt, c_encrypt_ex
from pycryptoki.audit_handling import ca_init_audit_ex, ca_time_sync_ex, ca_get_time_ex 
from pycryptoki.sign_verify import c_sign_ex, c_sign    
import logging
import os
import pytest

logger = logging.getLogger(__name__)
class TestCKAStartEndDate():

    h_session = 0
    admin_slot = 0
    
    def setup(self):
        setup_for_tests(True, True, True)
        c_initialize_ex()
        self.admin_slot = get_token_by_label_ex(ADMIN_PARTITION_LABEL)
        self.h_session = c_open_session_ex(slot_num=self.admin_slot)
        login_ex(self.h_session, self.admin_slot, CO_PASSWORD, CKU_USER)


    def teardown(self):
        c_logout_ex(self.h_session)
        c_close_session_ex(self.h_session)
        c_finalize()
        

    def test_symmetric_key_expiry_des(self):
        """ 
        Test: Verify that user is not able to use the symmetric object after date specified in 
                    CKA_END_DATE attribute
            Procedure:
            Generate a DES Key des1
            Use des1 in encrypt operation. Should work fine
            Using audit role, change the date of HSM to 12/31/2013
            Use des1 in encrypt operation 
            """
            
        logger.info("Test: Verify that user is not able to use the symmetric object after date specified in \
                    CKA_END_DATE attribute") 
         
        end_d = date_attrb
        end_d['year'] = "2013"
        end_d['month'] = "12"
        end_d['day'] = "31"

        CKM_KEY_GEN_TEMP = {CKA_CLASS : CKO_SECRET_KEY, 
                            CKA_KEY_TYPE :  CKK_DES,
                            CKA_TOKEN :     True,
                            CKA_SENSITIVE : True,
                            CKA_PRIVATE :   True,
                            CKA_ENCRYPT :   True,
                            CKA_DECRYPT :   True,
                            CKA_SIGN :      True,
                            CKA_VERIFY :    True,
                            CKA_WRAP :      True,
                            CKA_UNWRAP :    True, 
                            CKA_DERIVE :    True,
                            CKA_VALUE_LEN : 8,
                            CKA_EXTRACTABLE :True,
                            CKA_LABEL :     "DES Key",
                            CKA_END_DATE : CDict(end_d)}


        
        h_key = c_generate_key_ex(self.h_session, flavor=CKM_DES_KEY_GEN, template=CKM_KEY_GEN_TEMP)
        logger.info("Called c-generate: Key handle -" + str(h_key))


        
        c_encrypt_ex(self.h_session, CKM_DES_ECB, h_key, "a" * 512)

        c_logout_ex(self.h_session)
        c_close_session_ex(self.h_session)
        
        ca_init_audit_ex(self.admin_slot, AUDITOR_PASSWORD, AUDITOR_LABEL)
   
        h_session2 = c_open_session_ex(slot_num=self.admin_slot, flags = (CKF_SERIAL_SESSION | CKF_AUDIT_SESSION))
        login_ex(h_session2, self.admin_slot, AUDITOR_PASSWORD, CKU_AUDIT)
 
        dt = datetime(2014, 1 , 31)
        epoch = datetime.utcfromtimestamp(0)        
        delta = dt - epoch
        hsm_dt = delta.total_seconds()
        hsm_new_date = int(hsm_dt)
        
        ca_time_sync_ex(h_session2, hsm_new_date)
 
        hsm_time = ca_get_time_ex(h_session2)

        c_logout_ex(h_session2)
        c_close_session_ex(h_session2)
                
        h_session = c_open_session_ex(slot_num=self.admin_slot)
        login_ex(h_session, self.admin_slot, CO_PASSWORD, CKU_USER)
        
        return_val = c_encrypt(h_session, CKM_DES_ECB, h_key, "This is some data to sign ..   ")
   
        assert return_val == CKR_KEY_NOT_ACTIVE, "return value should be CKR_KEY_NOT_ACTIVE"
        c_logout_ex(h_session)
        c_close_session_ex(h_session)


    def test_symmetric_key_expiry_aes(self):
        """ 
        Test: Verify that user is not able to use the symmetric aes object after date specified in 
                    CKA_END_DATE attribute
            Procedure:
            Generate a AES key aes1
            Use aes1 in encrypt operation. Should work fine
            Using audit role, change the date of HSM to 12/31/2013
            Use aes1 in encrypt operation 
            """
            
        logger.info("Test: Verify that user is not able to use the symmetric aes object after date specified in \
                    CKA_END_DATE attribute") 
        end_d = date_attrb
        end_d['year'] = "2013"
        end_d['month'] = "12"
        end_d['day'] = "31"

        CKM_KEY_GEN_TEMP = {CKA_CLASS : CKO_SECRET_KEY, 
                            CKA_KEY_TYPE :  CKK_AES,
                            CKA_TOKEN :     True,
                            CKA_SENSITIVE : True,
                            CKA_PRIVATE :   True,
                            CKA_ENCRYPT :   True,
                            CKA_DECRYPT :   True,
                            CKA_SIGN :      True,
                            CKA_VERIFY :    True,
                            CKA_WRAP :      True,
                            CKA_UNWRAP :    True, 
                            CKA_DERIVE :    True,
                            CKA_VALUE_LEN : 16,
                            CKA_EXTRACTABLE :True,
                            CKA_LABEL :     "AES Key",
                            CKA_END_DATE : CDict(end_d)}


        
        h_key = c_generate_key_ex(self.h_session, flavor=CKM_AES_KEY_GEN, template=CKM_KEY_GEN_TEMP)
        logger.info("Called c-generate: Key handle -" + str(h_key))

        
        c_encrypt_ex(self.h_session, CKM_AES_ECB, h_key, "This is some data to sign ..   ")
   
        c_logout_ex(self.h_session)
        c_close_session_ex(self.h_session)
        
        ca_init_audit_ex(self.admin_slot, AUDITOR_PASSWORD, AUDITOR_LABEL)
   
        h_session2 = c_open_session_ex(slot_num=self.admin_slot, flags = (CKF_SERIAL_SESSION | CKF_AUDIT_SESSION))
        login_ex(h_session2, self.admin_slot, AUDITOR_PASSWORD, CKU_AUDIT)
 
        dt = datetime(2014, 1 , 31)
        epoch = datetime.utcfromtimestamp(0)        
        delta = dt - epoch
        hsm_dt = delta.total_seconds()
        hsm_new_date = int(hsm_dt)
        ca_time_sync_ex(h_session2, hsm_new_date)

        hsm_time = ca_get_time_ex(h_session2)

        c_logout_ex(h_session2)
        c_close_session_ex(h_session2)
                
        h_session = c_open_session_ex(slot_num=self.admin_slot)
        login_ex(h_session, self.admin_slot, CO_PASSWORD, CKU_USER)
        
        return_val = c_encrypt(h_session, CKM_AES_ECB, h_key, "This is some data to sign ..   ")
        logger.info("Called C_Encrypt, return code: " + str(return_val))  
        assert return_val == CKR_KEY_NOT_ACTIVE, "Expected return code is CKR_KEY_NOT_ACTIVE"


    def test_asymmetric_key_expiry_rsa(self):
        """ 
        Test: Verify that user is not able to use the rsa asymmetric object after date specified in 
                    CKA_END_DATE attribute
            Procedure:
            Generate a rsa Key rsa1
            Use des1 in encrypt operation. Should work fine
            Using audit role, change the date of HSM to 12/31/2013
            Use rsa1 in encrypt operation 
            """
            
        logger.info("Test: Verify that user is not able to use the rsa asymmetric object after date specified in \
                    CKA_END_DATE attribute") 
        end_d = date_attrb
        end_d['year'] = "2013"
        end_d['month'] = "12"
        end_d['day'] = "31"

        CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP = {CKA_TOKEN : True,
                                          CKA_PRIVATE : True,
                                          CKA_MODIFIABLE : True,
                                          CKA_ENCRYPT : True,
                                          CKA_VERIFY : True,
                                          CKA_WRAP : True,
                                          CKA_MODULUS_BITS : 1024, #long 0 - MAX_RSA_KEY_NBITS
                                          CKA_PUBLIC_EXPONENT : 3, #byte
                                          CKA_END_DATE : CDict(end_d),
                                          CKA_LABEL : "RSA Public Key"}

        CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP = {CKA_TOKEN : True,
                                          CKA_PRIVATE : True,
                                          CKA_SENSITIVE : True,
                                          CKA_MODIFIABLE : True,
                                          CKA_EXTRACTABLE : True,
                                          CKA_DECRYPT : True,
                                          CKA_SIGN : True,
                                          CKA_UNWRAP : True,
                                          CKA_END_DATE : CDict(end_d),
                                          CKA_LABEL : "RSA Private Key"}


        
        h_pbkey, h_prkey = c_generate_key_pair_ex(self.h_session, flavor=CKM_RSA_PKCS_KEY_PAIR_GEN, 
                               pbkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP, 
                               prkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP,
                               mech=None)
        logger.info("Called c-generate: Public Key handle -" + str(h_pbkey) + "Private Key Handle" + str(h_prkey))
        
        c_encrypt_ex(self.h_session, CKM_RSA_PKCS, h_pbkey, "This is some data to sign ..   ")
    
        c_logout_ex(self.h_session)
        c_close_session_ex(self.h_session)
        
        ca_init_audit_ex(self.admin_slot, AUDITOR_PASSWORD, AUDITOR_LABEL)
           
        h_session2 = c_open_session_ex(slot_num=self.admin_slot, flags = (CKF_SERIAL_SESSION | CKF_AUDIT_SESSION))
        login(h_session2, self.admin_slot, AUDITOR_PASSWORD, CKU_AUDIT)
 
        dt = datetime(2014, 1 , 31)
        epoch = datetime.utcfromtimestamp(0)        
        delta = dt - epoch
        hsm_dt = delta.total_seconds()
        hsm_new_date = int(hsm_dt)
        ca_time_sync_ex(h_session2, hsm_new_date)
        
        hsm_time = ca_get_time_ex(h_session2)
#        print datetime.fromtimestamp(float(hsm_time.value))
        c_logout_ex(h_session2)
        c_close_session_ex(h_session2)
                
        h_session = c_open_session_ex(slot_num=self.admin_slot)
        login_ex(h_session, self.admin_slot, CO_PASSWORD, CKU_USER)
        
        return_val = c_encrypt(h_session, CKM_RSA_PKCS, h_pbkey, "This is some data to sign ..   ")
        logger.info("Called C_Encrypt, return code: " + str(return_val))  
        assert return_val == CKR_KEY_NOT_ACTIVE, "Expected return code is CKR_KEY_NOT_ACTIVE"


    def test_asymmetric_key_expiry_dsa(self):
        """ 
        Test: Verify that user is not able to use the dsa asymmetric object after date specified in 
                    CKA_END_DATE attribute
            Procedure:
            Generate a DSA Key dsa1
            Use dsa11 in encrypt operation. Should work fine
            Using audit role, change the date of HSM to 12/31/2013
            Use dsa1 in encrypt operation 
            """
            
        logger.info("Test: Verify that user is not able to use the dsa asymmetric object after date specified in \
                    CKA_END_DATE attribute") 
        end_d = date_attrb
        end_d['year'] = "2013"
        end_d['month'] = "12"
        end_d['day'] = "31"

        CKM_DSA_KEY_PAIR_GEN_PUBTEMP_1024_160 = {CKA_TOKEN : True,
                                CKA_PRIVATE : True,
                                CKA_ENCRYPT : True,
                                CKA_VERIFY : True,
                                CKA_WRAP : True,
                                CKA_PRIME : dsa_prime_1024_160,
                                CKA_SUBPRIME : dsa_sub_prime_1024_160,
                                CKA_BASE : dsa_base_1024_160,
                                CKA_END_DATE : CDict(end_d),
                                CKA_LABEL : "DSA 1024_160 Public Key"}

        CKM_DSA_KEY_PAIR_GEN_PRIVTEMP = {CKA_TOKEN : True,
                                CKA_PRIVATE : True,
                                CKA_SENSITIVE : True,
                                CKA_DECRYPT : True,
                                CKA_SIGN : True,
                                CKA_UNWRAP : True,
                                CKA_EXTRACTABLE : True,
                                CKA_END_DATE : CDict(end_d),
                                CKA_LABEL : "DSA Public Key"}


        
        h_pbkey, h_prkey = c_generate_key_pair_ex(self.h_session, flavor=CKM_DSA_KEY_PAIR_GEN, 
                               pbkey_template=CKM_DSA_KEY_PAIR_GEN_PUBTEMP_1024_160, 
                               prkey_template=CKM_DSA_KEY_PAIR_GEN_PRIVTEMP,
                               mech=None)
        logger.info("Called c-generate: Public Key handle -" + str(h_pbkey) + "Private Key Handle" + str(h_prkey))
        
        c_sign_ex(self.h_session, CKM_DSA_SHA1, "Some data to sign", h_prkey)
        
       
           
        c_logout_ex(self.h_session)
        c_close_session_ex(self.h_session)
        
        ca_init_audit_ex(self.admin_slot, AUDITOR_PASSWORD, AUDITOR_LABEL)
        
        h_session2 = c_open_session_ex(slot_num=self.admin_slot, flags = (CKF_SERIAL_SESSION | CKF_AUDIT_SESSION))
        login_ex(h_session2, self.admin_slot, AUDITOR_PASSWORD, CKU_AUDIT)
 
        dt = datetime(2014, 1 , 31)
        epoch = datetime.utcfromtimestamp(0)        
        delta = dt - epoch
        hsm_dt = delta.total_seconds()
        hsm_new_date = int(hsm_dt)
        ca_time_sync_ex(h_session2, hsm_new_date)
        
        hsm_time = ca_get_time_ex(self.h_session)
#        print datetime.fromtimestamp(float(hsm_time.value))
        c_logout_ex(h_session2)
        c_close_session_ex(h_session2)
                
        h_session = c_open_session_ex(slot_num=self.admin_slot)
        login_ex(h_session, self.admin_slot, CO_PASSWORD, CKU_USER)
        
        return_val, sig = c_sign(h_session, CKM_DSA_SHA1, "Some data to sign", h_prkey)
        logger.info("Called C_Sign, return code: " + str(return_val))  
        assert return_val == CKR_KEY_NOT_ACTIVE, "Expected return code is CKR_KEY_NOT_ACTIVE"

        
        

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    pytest.cmdline.main(args=['-v', os.path.abspath(__file__)])
    
     