from ctypes import CDLL
import os
import re
import sys

from pycryptoki.defaults import CHRYSTOKI_DLL_FILE, CHRYSTOKI_CONFIG_FILE


def parse_chrystoki_conf():
    """The autogeneration of cryptoki.py now prepends a method which sets the DLL's path to
    be called every time cryptoki.py is imported. This method parses Cryptoki's configuration
    file in python for the DLL's location. While originally it was desired to reuse the C code
    which parses Cryptoki.conf this was not possible because Pycryptoki can only call functions
    on the dll, you cannot do something like instantiate a class and then call a function on that class.

    ex: ckdemo does:
    ChrystokiConfiguration conf;
    char* libName = conf.LibraryFileName();

    Option 1:
    Create a new api function and make it visible in the DLL. It's not very good to put functions
    that are customer visible in the API that are going to be used for testing tools. In addition
    it would be necessary to store a copy of the DLL in the pycryptoki package and load this DLL
    every time pycryptoki is run. This is therefore not a great option.

    Option 2:
    Write a short program in C++ that compiles against luna's source code. Then python can call
    this file to get the output. This would work however it create a dependency that portions of
    pycryptoki must be compiled, in addition when distributing pycryptoki to the testing team it
    would be necessary to distribute platform dependent code.

    Creating a compilation dependency between pycryptoki and the C code is not a good idea since
    it will be necessary to make a C program in the setup for pycryptoki which increases the
    complexity of the setup.

    Option 3:
    Parse the file in python.

    This option was chosen because it was fairly easy to do and supported across all platforms.
    It is also the simplest approach. The disadvantage to this is the configuration file may be
    parsed differently in C than in python. Therefore lot of error checking was added to the parsing
    process as well as printing of which DLL was found in each run of the Cryptoki library..


    """

    env_conf_path = os.environ.get("ChrystokiConfigurationPath")
    conf_path = None
    if CHRYSTOKI_DLL_FILE is not None:
        # Use this value for the location of the DLL
        dll_path = CHRYSTOKI_DLL_FILE
        print "Using DLL Path from defaults.py:" + dll_path
        return dll_path
    elif CHRYSTOKI_CONFIG_FILE is not None:
        conf_path = CHRYSTOKI_CONFIG_FILE
        print "Using Chrystoki.conf location from defaults.py: " + conf_path
    elif env_conf_path is not None:
        if 'win' in sys.platform:
            env_conf_path = env_conf_path.replace('\\\\', '~').replace('~', '\\') + 'crystoki.ini'
        else:
            env_conf_path = os.path.join(env_conf_path, 'Chrystoki.conf')
        conf_path = env_conf_path

        print "Using Chrystoki.conf location from environment variable ChrystokiConfigurationPath: " + conf_path

    if conf_path is None:
        conf_path = '/etc/Chrystoki.conf'
        print "No DLL Path or Chyrstoki.conf path set in defaults.py looking up DLL path in  " + str(conf_path)

    print "Searching " + str(conf_path) + " for Chrystoki DLL path..."

    chrystoki_conf_text = _get_chrystoki_conf_file_text(conf_path)

    dll_path = _search_for_dll_in_chrystoki_conf(conf_path, chrystoki_conf_text)

    print "Using DLL at location: " + dll_path

    return dll_path


def _search_for_dll_in_chrystoki_conf(conf_path, chrystoki_conf_text):
    """Parses the chrystoki configuration file for the section that specifies the location
    of the DLL and returns the DLL location.

    :param conf_path: The path to the configuration file
    :param chrystoki_conf_text: The output of the read in chrystoki configuration file
    :returns: The path to the chrystoki DLL

    """
    if 'win' in sys.platform:
        chrystoki2_segments = re.findall("\s*\[Chrystoki2\]\s*([^\r\n]*)", chrystoki_conf_text)

        if len(chrystoki2_segments) > 1:
            print chrystoki2_segments
            raise Exception(
                "Found " + len(chrystoki2_segments) + "Chrystoki2 sections in the config file: " + str(conf_path))
        elif len(chrystoki2_segments) < 1:
            print chrystoki2_segments
            raise Exception("Found no Chrystoki2 section in the config file: " + str(conf_path))

        chrystoki2 = chrystoki2_segments[0].split('\n')
        dll_path = ""
        for line in chrystoki2:
            lib_nt_line = re.findall("^\s*LibNT\s*=\s*([^\n]+)", line)

            if len(lib_nt_line) > 1:
                raise Exception("Found more than one LibNT pattern on the same line")
            elif len(lib_nt_line) == 1:
                if dll_path != "":
                    raise Exception("Found more than one instance of LibNT in the file.")
                dll_path = lib_nt_line[0].strip().strip(';').strip().strip("'").strip('"')

        if dll_path == "":
            raise Exception("Error finding LibNT declaration in configuration file: " + str(conf_path))
    else:
        chrystoki2_segments = re.findall("\s*Chrystoki2\s*=\s*\{([^\}]*)", chrystoki_conf_text)

        if len(chrystoki2_segments) > 1:
            print chrystoki2_segments
            raise Exception(
                "Found " + len(chrystoki2_segments) + "Chrystoki2 sections in the config file: " + str(conf_path))
        elif len(chrystoki2_segments) < 1:
            print chrystoki2_segments
            raise Exception("Found no Chrystoki2 section in the config file: " + str(conf_path))

        chrystoki2 = chrystoki2_segments[0].split('\n')
        dll_path = ""
        for line in chrystoki2:
            is_64bits = sys.maxsize > 2 ** 32
            if is_64bits:
                lib_unix_line = re.findall("^\s*LibUNIX64\s*=\s*([^\n]+)", line)
            else:
                lib_unix_line = re.findall("^\s*LibUNIX\s*=\s*([^\n]+)", line)

            if len(lib_unix_line) > 1:
                raise Exception("Found more than one LibUNIX pattern on the same line")
            elif len(lib_unix_line) == 1:
                if dll_path != "":
                    raise Exception("Found more than one instance of LibUNIX in the file.")
                dll_path = lib_unix_line[0].strip().strip(';').strip().strip("'").strip('"')

        if dll_path == "":
            raise Exception("Error finding LibUNIX declaration in configuration file: " + str(conf_path))

    return dll_path


def _get_chrystoki_conf_file_text(conf_path):
    """Reads in the chrystoki configuration and returns the text in the file

    :param conf_path:

    """

    try:
        chrystoki_conf_file = open(conf_path, "r")
        chrystoki_conf_text = chrystoki_conf_file.read()
    except IOError:
        raise Exception("Could not find/read Chrystoki configuration file at path " + str(conf_path))
    return chrystoki_conf_text


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

    _instance = None
    loaded_dll_library = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(CryptokiDLLSingleton, cls).__new__(cls, *args, **kwargs)

            dll_path = parse_chrystoki_conf()
            cls._instance.dll_path = dll_path
            if 'win' in sys.platform:
                import ctypes

                cls._instance.loaded_dll_library = ctypes.WinDLL(dll_path)
            else:
                cls._instance.loaded_dll_library = CDLL(dll_path)
        return cls._instance

    def get_dll(self):
        """ """
        if self.loaded_dll_library is None or self.loaded_dll_library == "":
            raise Exception(
                "DLL path never found:\n1. Is the cryptoki client installed?\n2. Can python read /etc/Chrystoki.conf?\n3. Is there a LibUNIX= field in /etc/Chrystoki.conf")
        return self.loaded_dll_library


def make_late_binding_function(function_name):
    """A function factory for creating a function that will bind to the cryptoki
    DLL only when the function is called.

    :param function_name:

    """

    def luna_function(*args, **kwargs):
        """

        :param *args:
        :param **kwargs:

        """
        late_binded_function = eval("CryptokiDLLSingleton().get_dll()." + function_name)
        late_binded_function.restype = luna_function.restype
        late_binded_function.argtypes = luna_function.argtypes

        try:
            return_value = late_binded_function(*args, **kwargs)
            return return_value
        except Exception as e:
            raise CryptokiDLLException("Call to '" + function_name + str(args) + str(kwargs) + "' failed.", e)

    return luna_function
