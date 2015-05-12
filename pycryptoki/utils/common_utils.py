import datetime
#Utility to set a default logfile name
def setLogFile():
    dt = str(datetime.datetime.now()).strip()
    logname = "./test_" + dt + ".log"
    return logname
