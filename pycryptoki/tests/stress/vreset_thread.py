import os
import threading
import time
import subprocess
from random import randint 

# Reset Thread class - wanted to be able to stop thread on error        
class ResetThread(threading.Thread):
    '''
    Input parameters for this class are:
        trigger: the event to initiate the reset operation - thread waits on this event
        complete: the  event to tell the external world that the reset has complete
        device: the target device node to reset
        upath: the path to the driver utils i.e. vreset and dumpit
    '''
    def __init__(self, trigger, complete, device, upath, logger):
        super(ResetThread, self).__init__()
        self.trigger = trigger
        self.complete = complete
        self.stoprequest = threading.Event()
        self.count = 0
        self.device = device
        self.upath = upath
        self.logger = logger
        
    def run(self):
        while not self.stoprequest.isSet():
            self.count += 1
            self.trigger.wait()
            delay = randint(1,20)
            time.sleep(delay)
            self.logger.info("Trigger vreset: %d on device [%s]" % (self.count, self.device))
            cmd = self.upath  + "/vreset " + self.device
            val = os.system(cmd)
            if val == 0:
                self.complete.set()
            else:
                self.complete.clear()
                self.logger.info("-----Vreset Failed: [%d] on device [%s]-------" % (val,self.device)) 
                proc_dump = subprocess.Popen([self.upath + str("/dumpit"), self.device], stdout=subprocess.PIPE, shell=True)
                (dump_out, dump_err) = proc_dump.communicate()
                self.logger.debug("DUMPIT OUTPUT: stdout")
                self.logger.debug(dump_out) 
                self.logger.debug("DUMPIT ERROR: stderr")
                self.logger.debug(dump_err)
                tail_proc = subprocess.Popen([str("tail -n 100 "), str("/var/log/messages")], stdout=subprocess.PIPE, shell=True)
                (tail_out, tail_err) = tail_proc.communicate()
                self.logger.debug("TAIL OUTPUT: stdout")
                self.logger.debug(tail_out) 
                self.logger.debug("TAIL ERROR: stderr")
                self.logger.debug(tail_err)
    def join(self, timeout=None):
        self.stoprequest.set()
        super(ResetThread, self).join(timeout)