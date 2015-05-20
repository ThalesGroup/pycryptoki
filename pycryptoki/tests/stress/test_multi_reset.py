from ctypes import *
from pycryptoki.cryptoki import CK_SLOT_ID, CA_GetObjectUID, \
    CA_GetUserContainerNumber, CA_GetObjectHandle, \
    CK_ULONG, CK_BYTE
from pycryptoki.default_templates import CKM_DES_KEY_GEN_TEMP, \
    CKM_DES2_KEY_GEN_TEMP, CKM_DES3_KEY_GEN_TEMP, CKM_CAST3_KEY_GEN_TEMP, \
    CKM_GENERIC_SECRET_KEY_GEN_TEMP, \
    CKM_CAST5_KEY_GEN_TEMP, CKM_RC2_KEY_GEN_TEMP, CKM_RC4_KEY_GEN_TEMP, \
    CKM_RC5_KEY_GEN_TEMP, CKM_AES_KEY_GEN_TEMP, CKM_SEED_KEY_GEN_TEMP, \
    CKM_ARIA_KEY_GEN_TEMP, CKM_DH_PKCS_PARAMETER_GEN_TEMP
from pycryptoki.defines import CKM_DES_KEY_GEN, CKM_DES2_KEY_GEN, \
    CKM_DES3_KEY_GEN, CKM_CAST3_KEY_GEN, CKM_GENERIC_SECRET_KEY_GEN, \
    CKM_CAST5_KEY_GEN, CKM_RC2_KEY_GEN, CKM_RC4_KEY_GEN, CKM_RC5_KEY_GEN, \
    CKM_AES_KEY_GEN, CKM_SEED_KEY_GEN, \
    CKM_ARIA_KEY_GEN, CKM_DH_PKCS_PARAMETER_GEN, CKR_OK, \
    CKR_DEVICE_ERROR, CK_CRYPTOKI_ELEMENT
from pycryptoki.defaults import DEFAULT_PASSWORD, DEFAULT_LABEL
from pycryptoki.defines import CKF_SERIAL_SESSION, CKF_RW_SESSION, \
    CKF_SO_SESSION
from pycryptoki.key_generator import  c_destroy_object, c_generate_key
from pycryptoki.session_management import c_initialize, c_finalize, \
    c_close_all_sessions_ex, ca_factory_reset_ex, c_open_session_ex, login_ex, \
    c_get_token_info_ex, c_init_pin_ex, c_logout_ex, c_close_session_ex, c_finalize_ex
from pycryptoki.token_management import  get_token_by_label_ex, c_init_token_ex
from pycryptoki.test_functions import verify_object_attributes, verify_object_exists
from pycryptoki.utils.common_utils import setLogFile
from pycryptoki.tests.stress.vreset_thread import ResetThread
from pycryptoki.defaults import DEFAULT_UTILS_PATH, FORMAT
from random import randint
import logging
import os
import threading
import argparse
import sys


#Global Scope
logger = logging.getLogger(__name__)

class MultiResetDuringKeyGen:
    """ """
    def __init__(self, slot):
        self.slot = slot
        self.h_session = 0
        #Setup events
        self.trigger = threading.Event()
        self.complete = threading.Event()
        #Keygen options - 13 options randomly selected
        self.keytype_and_template_list = [(CKM_AES_KEY_GEN, CKM_AES_KEY_GEN_TEMP),
                             (CKM_DES_KEY_GEN,  CKM_DES_KEY_GEN_TEMP),
                             (CKM_DES3_KEY_GEN, CKM_DES3_KEY_GEN_TEMP),
                             (CKM_DES2_KEY_GEN, CKM_DES2_KEY_GEN_TEMP),
                             (CKM_CAST3_KEY_GEN, CKM_CAST3_KEY_GEN_TEMP),
                             (CKM_GENERIC_SECRET_KEY_GEN, CKM_GENERIC_SECRET_KEY_GEN_TEMP),
                             (CKM_CAST5_KEY_GEN, CKM_CAST5_KEY_GEN_TEMP),
                             (CKM_RC2_KEY_GEN, CKM_RC2_KEY_GEN_TEMP),
                             (CKM_RC4_KEY_GEN, CKM_RC4_KEY_GEN_TEMP),
                             (CKM_RC5_KEY_GEN, CKM_RC5_KEY_GEN_TEMP),
                             (CKM_SEED_KEY_GEN, CKM_SEED_KEY_GEN_TEMP),
                             (CKM_ARIA_KEY_GEN, CKM_ARIA_KEY_GEN_TEMP),
                             (CKM_DH_PKCS_PARAMETER_GEN, CKM_DH_PKCS_PARAMETER_GEN_TEMP)]

    def close_off(self):
        """ """
        c_logout_ex(self.h_session)
        c_close_session_ex(self.h_session)
        c_finalize_ex()

    def getDefltLabel(self):
        """ """
        label = DEFAULT_LABEL+str(self.slot)
        return label

    def gen_verify_clean(self, vdevice, upath):
        """This method is the core of the test case.
        The purpose being to continually generate keys until a random reset causes a DEVICE_ERROR to be returned
        at which point we capture the exception generated, and verify the objects that were created.
        Once a certain number of keys (currently set to 20000) are generated we delete and repeat the process

        :param vdevice:
        :param upath:

        """
        cntNum = CK_ULONG()
        generated_objects = []
        logger.info("--- Starting Test ---")
        rthread = ResetThread(self.trigger, self.complete,vdevice, upath, logger)
        ret = CA_GetUserContainerNumber(CK_SLOT_ID(self.slot),byref(cntNum))
        logger.info("Container Number:[%s]" % str(cntNum))
        if ret != CKR_OK:
            rthread.join(1)
            logger.info("Error: could not get container number[%s]" % str(cntNum))
            exit(-1)
        rthread.start()
        self.trigger.set()
        self.complete.clear()
        for outer in range (1, 1000):
            logger.info("**** Iteration: %d *****" % outer)
            for num in range (1, 20000):
                # Creation stage
                ouid = (CK_BYTE*12)()
                try:
                    type_of_keygen = randint(0,12)
                    #Generate random key type with associated template
                    gen_ret, hdl = c_generate_key(self.h_session, self.keytype_and_template_list[type_of_keygen][0], self.keytype_and_template_list[type_of_keygen][1])
                    if gen_ret == CKR_DEVICE_ERROR:
                        raise Exception('keygen')
                    ouid_ret = CA_GetObjectUID(CK_SLOT_ID(self.slot),cntNum,CK_ULONG(CK_CRYPTOKI_ELEMENT),CK_ULONG(hdl),ouid)
                    if ouid_ret == CKR_DEVICE_ERROR:
                        raise Exception('ouid')
                    if ouid_ret == CKR_OK and gen_ret == CKR_OK:
                        self.trigger.set()
                        #Store off the object OUID and the template used for keygen
                        generated_objects.append((ouid,self.keytype_and_template_list[type_of_keygen][1]))
                        logger.debug("Entry Info: hdl[%d]:num[%d]:ouid[%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x]" %
                                    (hdl,num,ouid[0],ouid[1],ouid[2],ouid[3],ouid[4],ouid[5],ouid[6],
                                     ouid[7],ouid[8], ouid[9], ouid[10], ouid[11]))
                except Exception as e:
                    self.trigger.clear()
                    msg = e.args[0]
                    logger.info("Exception:[%s] on entry [%d]" % (msg,num))
                    if msg != 'keygen' and msg != 'ouid':
                        rthread.join(1)
                        logger.info("Unexpected exception:[%s] - exiting!" % msg)
                        exit(-1)
                    if msg == 'keygen':
                        logger.info("Create: Keygen errored out with DEVICE_ERROR on entry [%d]:hdl[%d]" % (num,hdl))
                    if msg == 'ouid':
                        logger.info("Create: OUID lookup errored out with DEVICE_ERROR on entry [%d]:hdl[%d]" % (num,hdl))
                    logger.info("Waiting to verify %d objects" % len(generated_objects))
                    self.complete.wait()
                    self.complete.clear()
                    self.h_session = c_open_session_ex(self.slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
                    login_ex(self.h_session, self.slot, DEFAULT_PASSWORD, 1)
                    logger.info("Start verification of %d objects" % len(generated_objects))
                    ret = CA_GetUserContainerNumber(CK_SLOT_ID(self.slot),byref(cntNum))
                    logger.info("Container Number:[%s]" % str(cntNum))
                    if ret != CKR_OK:
                        rthread.join(1)
                        logger.info("Error: could not get container number[%s]" % str(cntNum))
                        exit(-1)
                    '''
                    Verify object that are generated
                    TODO: Make this set of operations more intensive.
                    For example:
                          Encrypt/Decrypt data blob on alternating vreset iterations.
                          Create EC keys, keypairs etc
                    '''
                    for kouid, temp in generated_objects:

                        key = CK_ULONG()
                        oType = CK_ULONG()
                        ret = CA_GetObjectHandle(CK_SLOT_ID(self.slot), cntNum,
                                          kouid, byref(oType),
                                          byref(key))
                        if ret != CKR_OK:
                            logger.debug("Verify: Error: could not get handle[%d] for ouid[%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x]"
                                        % (key.value,kouid[0],kouid[1],kouid[2],kouid[3],kouid[4],kouid[5],kouid[6],
                                           kouid[7],kouid[8], kouid[9], kouid[10], kouid[11]))
                            rthread.join(1)
                            sys.exc_clear()
                            exit(-1)
                        logger.debug("Verify: handle[%d] for ouid[%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x]"
                                        % (key.value,kouid[0],kouid[1],kouid[2],kouid[3],kouid[4],kouid[5],kouid[6],
                                           kouid[7],kouid[8], kouid[9], kouid[10], kouid[11]))
                        verify_object_exists(self.h_session, key.value, True)
                        verify_object_attributes(self.h_session, key.value, temp)
                    logger.info("Completed verification of %d objects" % len(generated_objects))
                    # Clear the memory of the exception
                    sys.exc_clear()
                    continue
            #Clean-up the objects for this iteration
            self.trigger.clear()
            delcount = 0
            store_count = len(generated_objects)
            #Delete objects which are generated
            while len(generated_objects):
                key = CK_ULONG()
                oType = CK_ULONG()
                douid, temp = generated_objects.pop()
                try:
                    gethdl_ret = CA_GetObjectHandle(CK_SLOT_ID(self.slot), cntNum,
                                              douid, byref(oType),
                                              byref(key))
                    if gethdl_ret == CKR_DEVICE_ERROR:
                        raise Exception('get_hdl')
                    dest_ret = c_destroy_object(self.h_session, key.value)
                    if dest_ret == CKR_DEVICE_ERROR:
                        raise Exception('destroy')
                    if dest_ret == CKR_OK and gethdl_ret == CKR_OK:
                        delcount+=1
                except Exception as e:
                    self.trigger.clear()
                    msg = e.args[0]
                    logger.info("Exception:[%s] on entry [%d]" % (msg,delcount))
                    if msg != 'get_hdl' and msg != 'destroy':
                        rthread.join(1)
                        logger.info("Unexpected exception:[%s] - exiting!" % msg)
                        exit(-1)
                    if msg == 'get_hdl':
                        logger.info("Delete: Error: could not get handle[%d] for ouid[%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x]"
                                    % (key.value, douid[0],douid[1],douid[2],douid[3],douid[4],douid[5],douid[6],
                                       douid[7],douid[8], douid[9], douid[10], douid[11]))
                    if msg == 'destroy':
                        logger.info("Delete: Error: failed to delete entry [%d] with ouid[%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x]"
                                    % (key.value, douid[0],douid[1],douid[2],douid[3],douid[4],douid[5],douid[6],
                                       douid[7],douid[8], douid[9], douid[10], douid[11]))
                    self.complete.wait()
                    self.complete.clear()
                    self.h_session = c_open_session_ex(CK_SLOT_ID(self.slot), CKF_SERIAL_SESSION | CKF_RW_SESSION)
                    login_ex(self.h_session, self.slot, DEFAULT_PASSWORD, 1)
                    ret = CA_GetUserContainerNumber(CK_SLOT_ID(self.slot),byref(cntNum))
                    logger.debug("Container Number:[%s]" % str(cntNum))
                    if ret != CKR_OK:
                        rthread.join(1)
                        logger.info("Error: could not get container number[%s]" % str(cntNum))
                        exit(-1)
                    # Clear the memory of the exception
                    sys.exc_clear()
                    continue
            logger.info("Deleted: %d of %d Objects" % (delcount,store_count))
            self.trigger.set()
        rthread.join(1)
        logger.info("--- Ending Test ---")

    def setup_for_test(self, initialize_admin_token, initialize_users, slot):
        """A common setup for the configurable roles tests

        :param initialize_admin_token: Whether or not to initialize the admin partition
        :param initialize_users: Whether or not to initialize the PIN's of the users
        :param slot: Token slot to target

        """
        c_initialize()

        #Factory Reset
        logger.info(slot)
        # NOTE: This is required always.
        c_close_all_sessions_ex(slot)
        ca_factory_reset_ex(slot)

        #Initialize the Token
        session_flags = (CKF_SERIAL_SESSION | CKF_RW_SESSION | CKF_SO_SESSION)
        if initialize_admin_token:
            h_session = c_open_session_ex(slot, session_flags)
            c_init_token_ex(slot, DEFAULT_PASSWORD, self.getDefltLabel() )
        c_finalize()
        c_initialize()
        if initialize_users and initialize_admin_token:
            islot = get_token_by_label_ex(self.getDefltLabel())
            logger.info("Slot by Label:" + str(islot))
            c_close_all_sessions_ex(islot)
            self.h_session = c_open_session_ex(islot, session_flags)
            logger.info("Session Handle:" + str(self.h_session))
            login_ex(self.h_session, islot, DEFAULT_PASSWORD, 0)
            logger.info(c_get_token_info_ex(islot))
            c_init_pin_ex(self.h_session, DEFAULT_PASSWORD)
            c_logout_ex(self.h_session)
            c_close_all_sessions_ex(islot)
            self.h_session = c_open_session_ex(islot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
            login_ex(h_session, islot, DEFAULT_PASSWORD, 1)
            logger.info(c_get_token_info_ex(islot))

'''
Get the command line args provided as input for test application/case
'''
def get_cmd_args():
    """ """
    parser = argparse.ArgumentParser()
    parser.add_argument("--tslot", help="This is the token slot we wish to target ",
                    type=int, default=1)
    parser.add_argument("--vdevice", metavar='device',
                        help="Target device we want to use i.e. viper0 or viper1",
                        default="/dev/viper0")
    parser.add_argument("--upath", metavar='path',
                        help="Path to where the utils are stored: vrest, dumpit",
                        default=DEFAULT_UTILS_PATH)
    parser.add_argument("--logfile", help="name of log to store output",
                        default=setLogFile())
    args = parser.parse_args()
    print args
    # Check if basic dependencies are present
    populated_dev_path = args.vdevice
    try:
        os.stat(populated_dev_path)
    except OSError as e:
        print "Startup: Exception: Device node [%s] not present in [%s] - [%s]" % (args.vdevice,populated_dev_path, e.args)
        exit(-1)
    valid_vreset_path = args.upath + "/vreset"
    try:
        os.stat(valid_vreset_path)
    except OSError as e:
        print "Startup: Exception: Invalid utils path [%s] or vreset not present [%s]"  % (args.upath, e.args)
        exit(-1)
    valid_dumpit_path = args.upath + "/dumpit"
    try:
        os.stat(valid_dumpit_path)
    except OSError as e:
        print "Startup: Exception:  Invalid utils path [%s] or dumpit not present[%s]"  % (args.upath, e.args)
        exit(-1)
    return args

'''
 Setup logging structure
 '''
def config_logging(args):
    """

    :param args:

    """
    print args
    logging.basicConfig(format=FORMAT,filename=args.logfile,level=logging.DEBUG,)

    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # set a format for logging
    formatter = logging.Formatter(FORMAT)
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    logging.getLogger('').addHandler(console)

'''
PyTest Entry Point:
NOTE: In order to enable console output to the py.test when running this test provide the following in setup.cfg
    # content of setup.cfg
    [pytest]
    addopts = -s
'''
def test_gen_verify_clean():
    """ """
    args = get_cmd_args()
    config_logging(args)
    Reset = MultiResetDuringKeyGen(args.tslot)
    Reset.setup_for_test(True, True, args.tslot)
    Reset.gen_verify_clean(args.vdevice, args.upath)
    Reset.close_off()

'''
Application Entry Point:
Call directly from the command line:
    python <filename> <options>
'''
if __name__ == '__main__':
    test_gen_verify_clean()







