from pycryptoki.default_templates import CKM_DES_KEY_GEN_TEMP, \
    CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP, CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP
from pycryptoki.defaults import ADMIN_PARTITION_LABEL, MANUFACTURER_ID, MODEL
from pycryptoki.defines import CKM_DES_KEY_GEN, CKM_RSA_PKCS_KEY_PAIR_GEN, \
    CKR_OK
from pycryptoki.key_generator import c_generate_key_ex, c_generate_key_pair_ex
from pycryptoki.return_values import ret_vals_dictionary
from pycryptoki.session_management import c_open_session_ex, c_get_token_info_ex, \
    c_open_session, c_close_session
from pycryptoki.test_functions import verify_object_attributes
from pycryptoki.token_management import get_token_by_label_ex, \
    c_get_mechanism_list_ex, c_get_mechanism_info_ex
import logging
import sys
import threading
import time


logger = logging.getLogger(__name__)

CREATE_AND_REMOVE_KEYS = 2
OPEN_AND_CLOSE_SESSIONS = 3
GET_TOKEN_INFO = 4
GET_MECHANISM_INFO = 5


class TestThread(threading.Thread):
    '''
    A member of the threading class which, when given the proper parameters, will
    perform some functions on the HSM in it's own thread. If one of the tests fails it will be reported when all the
    threads finish.
    '''
    def __init__(self, queue, thread_name, token_label, thread_type, max_time = 60): #60 seconds
        '''
        @param queue: The queue that the threads will be placed into, this is required to signal
        to the queue that the task is done
        @param thread_name: The name of the thread for debug printing purposes
        @param token_label: The token label to perform multithreaded operations on
        @param thread_type: The a numeric value specifyingoperation the thread will do, see the variables 
        described above the TestThread class declaration ex. GET_TOKEN_INFO
        @param max_time: The amount of time to spend doing the test in seconds
        '''
        
        self.thread_name = thread_name
        self.thread_type = thread_type
        self.max_time = max_time
        self.queue = queue
        self.token_label = token_label
        threading.Thread.__init__(self)
        
    def run(self):
        '''
        Called by the inheirited threading class to run the actual thread
        '''
        logger.debug("Starting thread " + self.thread_name + " type " + str(self.thread_type))
        self._return = True
        
        try:
            #For a given amount of time run the operations in a separate thread
            start_time = time.time()
            while ((time.time() - start_time) < self.max_time) and ((not self.starting_slot >= self.ending_slot) or (self.starting_slot == -1 and self.ending_slot == -1)):
                if self.thread_type == CREATE_AND_REMOVE_KEYS:
                    self.create_and_remove_keys()
                elif self.thread_type == OPEN_AND_CLOSE_SESSIONS:
                    self.open_and_close_sessions()
                elif self.thread_type == GET_TOKEN_INFO:
                    self.get_token_info()
                elif self.thread_type == GET_MECHANISM_INFO:
                    self.get_mechanism_info()
                else:
                    raise Exception("Unknown thread type " + str(self.thread_type))

            logger.debug("Exiting thread " + self.thread_name + " type " + str(self.thread_type))
        except Exception as e:
            self._return = e
            self.queue.task_done()
            print sys.exc_info()[0]
            raise
            return
    
        if (self._return == True):
            self._return = True
            self.queue.task_done()
    
    def get_token_info(self):
        '''
        Test that will get the token info and verify that the fields have been
        set to something other than null
        '''
        slot = get_token_by_label_ex(self.token_label)
        token_info = c_get_token_info_ex(slot)
        
        assert token_info['label'] == ADMIN_PARTITION_LABEL
        assert token_info['manufacturerID'] == MANUFACTURER_ID
        assert token_info['model'] == MODEL
        assert token_info['serialNumber'] != 0
        assert token_info['flags'] != 0
        assert token_info['ulTotalPrivateMemory'] == 0
        assert token_info['ulSessionCount'] != 0
        assert token_info['ulRwSessionCount'] != 0
        assert token_info['ulMaxPinLen'] != 0
        assert token_info['ulMinPinLen'] != 0
#        token_info['hardwareVersion'] = c_token_info.hardwareVersion
#        token_info['firmwareVersion'] = c_token_info.firmwareVersion
    
    def create_and_remove_keys(self):
        '''
        Test that will create a bunch of keys and verify the attributes on
        those keys
        '''
        slot = get_token_by_label_ex(self.token_label)
        h_session = c_open_session_ex(slot)
        
        logger.debug(self.thread_name + " Generating keys")
        key_handle = c_generate_key_ex(h_session, CKM_DES_KEY_GEN, CKM_DES_KEY_GEN_TEMP)
        key_handle_public, key_handle_private = c_generate_key_pair_ex(h_session, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP, CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP)
        
        logger.debug(self.thread_name + " Verifying keys")
        verify_object_attributes(h_session, key_handle, CKM_DES_KEY_GEN_TEMP)
        verify_object_attributes(h_session, key_handle_public, CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP)
        verify_object_attributes(h_session, key_handle_private, CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP)
    
    def open_and_close_sessions(self):
        '''
        Test that will open and close sessions repeatedly
        '''
        slot = get_token_by_label_ex(self.token_label)
        
        ret, h_session = c_open_session(slot)
        assert ret_vals_dictionary[ret] == ret_vals_dictionary[CKR_OK]
        
        ret = c_close_session(h_session)
        assert ret_vals_dictionary[ret] == ret_vals_dictionary[CKR_OK]
    
    def get_mechanism_info(self):
        '''
        Test that will get the mechanism info repeatedly and verify it is non null
        '''
        slot = get_token_by_label_ex(self.token_label)
        mechanism_list = c_get_mechanism_list_ex(slot)

        assert len(mechanism_list) > 0, "The mechanism list should have a non zero length"
        for mechanism in mechanism_list:
            mech_info = c_get_mechanism_info_ex(slot, mechanism)
            assert (mech_info.ulMinKeySize > 0 or mech_info.ulMaxKeySize > 0 or mech_info.flags > 0) and mech_info.ulMinKeySize <= mech_info.ulMaxKeySize, "Verifing that all fields are not 0 should be good enough for now"
    
