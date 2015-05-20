"""
  This allows for configuration of the designated test/testdir
   - Currently this adds custom command args (see below) to py.test interface for this test/directory
"""

from pycryptoki.defaults import DEFAULT_UTILS_PATH
from pycryptoki.utils.common_utils import setLogFile


def pytest_addoption(parser):
    parser.addoption("--tslot", help="This is the token slot we wish to target ",
                    type=int, default=1)
    parser.addoption("--vdevice", metavar='device',
                        help="Target device we want to use i.e. /dev/viper0 or /dev/viper1",
                        default="/dev/viper0")
    parser.addoption("--upath", metavar='path',
                        help="Path to where the utils are stored: vrest, dumpit",
                        default=DEFAULT_UTILS_PATH)
    parser.addoption("--logfile", help="name of log to store output",
                        default=setLogFile())

def pytest_funcarg__logfile(request):
    return request.config.option.logfile

def pytest_funcarg__vdevice(request):
    return request.config.option.vdevice

def pytest_funcarg__upath(request):
    return request.config.option.upath

def pytest_funcarg__tslot(request):
        return request.config.option.tslot
