"""
Helper functions to get us access to the PKCS11 library.
"""
import logging
import os
import re
import struct
import sys
from ctypes import CDLL

from six.moves import configparser

from .defaults import CHRYSTOKI_DLL_FILE, CHRYSTOKI_CONFIG_FILE
from .exceptions import LunaException

LOG = logging.getLogger(__name__)

IS_64B = 8 * struct.calcsize("P") == 64

CRYSTOKI_CONF_DLL = "CHRYSTOKI_CONF_DLL"


class CryptokiConfigException(LunaException):
    """
    Exception raised when we fail to determine the PKCS11 library location
    """
    pass


def parse_chrystoki_conf():
    """Parse the crystoki.ini/Chrystoki.conf file to find the library .so/.dll file so that
    we can use it.
    """

    env_conf_path = os.environ.get("ChrystokiConfigurationPath")
    conf_path = None
    if CHRYSTOKI_DLL_FILE is not None:
        # Use this value for the location of the DLL
        dll_path = CHRYSTOKI_DLL_FILE
        LOG.debug("Using DLL Path from defaults.py: %s", dll_path)
        return dll_path
    elif CHRYSTOKI_CONFIG_FILE is not None:
        conf_path = CHRYSTOKI_CONFIG_FILE
        LOG.debug("Using Chrystoki.conf location from defaults.py: %s", conf_path)
    elif env_conf_path is not None:
        if 'win' in sys.platform:
            env_conf_path = env_conf_path.replace('\\\\', '~').replace('~', '\\') + 'crystoki.ini'
        else:
            env_conf_path = os.path.join(env_conf_path, 'Chrystoki.conf')
        conf_path = env_conf_path

        LOG.debug("Using Chrystoki.conf location from environment variable "
                  "ChrystokiConfigurationPath: %s", conf_path)

    if conf_path is None:
        conf_path = '/etc/Chrystoki.conf'
        LOG.warning("No DLL Path or Chyrstoki.conf path set in defaults.py "
                    "looking up DLL path in %s", conf_path)

    LOG.debug("Searching %s for Chrystoki DLL path...", conf_path)

    dll_path = _search_for_dll_in_chrystoki_conf(conf_path)

    LOG.info("Using DLL at location: %s", dll_path)

    return dll_path


def _search_for_dll_in_chrystoki_conf(conf_path):
    """Parses the chrystoki configuration file for the section that specifies the location
    of the DLL and returns the DLL location.

    :param str conf_path: The path to the configuration file
    :returns: The path to the chrystoki DLL
    :rtype: str
    """
    if 'win' in sys.platform:
        try:
            config = configparser.ConfigParser()
            config.read(conf_path)

            dll_path = config.get("Chrystoki2", "LibNT")
        except ValueError:
            LOG.exception("Failed to read DLL from crystoki.ini.")
            raise CryptokiConfigException("Failed to read DLL location crystoki.ini file!")
        else:
            if not os.path.isfile(dll_path):
                raise CryptokiConfigException("Cryptoki DLL does not exist at path {}! Check your "
                                              "crystoki.ini file.".format(dll_path))
    else:
        with open(conf_path) as conf_file:
            chrystoki_conf_text = conf_file.read()
        chrystoki2_segments = re.findall(r"\s*Chrystoki2\s*=\s*\{([^\}]*)", chrystoki_conf_text)

        if len(chrystoki2_segments) > 1:
            raise CryptokiConfigException("Found %d Chrystoki2 sections in the config file: "
                                          "%s" % (len(chrystoki2_segments), conf_path))
        elif len(chrystoki2_segments) < 1:
            raise CryptokiConfigException("Found no Chrystoki2 section in the config file:"
                                          " %s" % conf_path)

        chrystoki2 = chrystoki2_segments[0].split('\n')
        dll_path = ""
        for line in chrystoki2:
            is_64bits = sys.maxsize > 2 ** 32
            if is_64bits:
                lib_unix_line = re.findall(r"^\s*Lib(?:UNIX64|HPUX)\s*=\s*([^\n]+)", line)
            else:
                lib_unix_line = re.findall(r"^\s*Lib(?:UNIX|HPUX)\s*=\s*([^\n]+)", line)

            if len(lib_unix_line) > 1:
                raise CryptokiConfigException("Found more than one"
                                              " LibUNIX pattern on the same line")
            elif len(lib_unix_line) == 1:
                if dll_path != "":
                    raise CryptokiConfigException("Found more than one instance of"
                                                  " LibUNIX in the file.")
                dll_path = lib_unix_line[0].strip().strip(';').strip().strip("'").strip('"')

        if dll_path == "":
            raise CryptokiConfigException("Error finding LibUNIX declaration in configuration file:"
                                          " %s" % conf_path)

    return dll_path


class CryptokiDLLException(Exception):
    """Custom exception class used to print an error when a call to the Cryptoki DLL failed.
    The late binding makes debugging a little bit more difficult because function calls
    have to pass through an additional layer of abstraction. This custom exception prints
    out a quick message detailing exactly what function failed.


    """

    def __init__(self, additional_info, orig_error):
        self.msg = additional_info
        self.original_error = orig_error

    def __str__(self):
        return self.msg + "\n" + str(self.original_error)


class CryptokiDLLSingleton(object):
    """A singleton class which holds an instance of the loaded cryptoki DLL object."""
    _instance_map = {}
    loaded_dll_library = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance_map.get(CRYSTOKI_CONF_DLL):
            new_instance = super(CryptokiDLLSingleton, cls).__new__(cls, *args, **kwargs)

            dll_path = parse_chrystoki_conf()
            new_instance.dll_path = dll_path
            if 'win' in sys.platform and IS_64B:
                import ctypes
                new_instance.loaded_dll_library = ctypes.WinDLL(dll_path)
            else:
                new_instance.loaded_dll_library = CDLL(dll_path)
            cls._instance_map[CRYSTOKI_CONF_DLL] = new_instance
        return cls._instance_map[CRYSTOKI_CONF_DLL]

    def get_dll(self):
        """Get the loaded library (parsed from crystoki.ini/Chrystoki.conf)"""
        if self.loaded_dll_library is None or self.loaded_dll_library == "":
            raise CryptokiConfigException(
                "DLL path not found:\n"
                "1. Is the Luna HSM Client installed?\n"
                "2. Can python read the Luna HSM Client config file?\n"
                "3. Is there a LibUNIX/LibNT field in the Luna HSM Client config file")
        return self.loaded_dll_library

    @classmethod
    def from_path(cls, path):
        if not cls._instance_map.get(path):
            new_instance = super(CryptokiDLLSingleton, cls).__new__(cls)
            cls._instance_map[path] = new_instance
            new_instance.dll_path = path
            if 'win' in sys.platform and IS_64B:
                import ctypes
                new_instance.loaded_dll_library = ctypes.WinDLL(path)
            else:
                new_instance.loaded_dll_library = CDLL(path)
        return cls._instance_map[path]


def log_args(funcname, args):
    """Log function name & arguments for a cryptoki ctypes call.
    
    :param str funcname: Function name
    :param tuple args: Arguments to be passed to ctypes function.
    """
    log_msg = "Cryptoki call: {}({})".format(funcname,
                                             ", ".join(str(arg) for arg in args))
    LOG.debug(log_msg)


def make_late_binding_function(function_name):
    """A function factory for creating a function that will bind to the cryptoki
    DLL only when the function is called.

    :param function_name:

    """

    def luna_function(*args):
        """

        :param *args:
        :param **kwargs:

        """
        late_binded_function = getattr(CryptokiDLLSingleton().get_dll(), function_name)
        late_binded_function.restype = luna_function.restype
        late_binded_function.argtypes = luna_function.argtypes

        log_args(function_name, args)
        try:
            return_value = late_binded_function(*args)
            return return_value
        except Exception as e:
            raise CryptokiDLLException("Call to '{}({})' "
                                       "failed.".format(function_name,
                                                        ", ".join([str(arg) for arg in args])), e)

    luna_function.__name__ = function_name
    return luna_function
