"""
Contains both a local and remote pycryptoki client
"""
import logging

import rpyc

from pycryptoki.daemon.pycryptoki_daemon import pycryptoki_functions, \
    functions_needing_serialization
from pycryptoki.session_management import c_finalize, c_initialize_ex, c_initialize

log = logging.getLogger(__name__)


class RemotePycryptokiClient:
    """Class to handle connecting to a remote Pycryptoki RPYC daemon.

    After instantiation, you can use it directly to make calls to a remote
    cryptoki library via RPYC (no need to do any imports or anything like that, just
    use the direct pycryptoki call like c\_initialize_ex() )

    :param ip: IP Address of the client the remote daemon is running on.
    :param port: What Port the daemon is running on.
    """

    def __init__(self, ip=None, port=None):
        self.ip = ip
        self.port = port
        self.started = False
        self.start()

    def kill(self):
        """
        Close out the local RPYC connection.
        """
        # maybe we should be reloading cryptoki dll?
        if self.started and not self.connection.closed:
            log.info("Stopping remote pycryptoki connection.")
            self.connection.close()
            self.started = False

    def start(self):
        """
        Start the connection to the remote RPYC daemon.
        """
        if not self.started:
            log.info("Starting remote pycryptoki connection")
            self.connection = rpyc.classic.connect(self.ip, port=self.port)
            self.server = self.connection.root
            self.started = True

    def cleanup(self):
        """ """
        pass

    def __getattr__(self, name):
        """
        This is the python default attribute handler, if an attribute
        is not found it's probably a pycryptoki call that we forward
        automagically to the server
        """
        if not self.started:
            self.start()
        if hasattr(self.server, name):
            def wrapper(*args, **kwargs):
                """

                :param *args:
                :param **kwargs:

                """
                log.info("Running remote pycryptoki command: "
                         "{0}(args={1}, kwargs={2})".format(name, args, kwargs))
                return getattr(self.server, name)(*args, **kwargs)

            return wrapper
        else:
            raise AttributeError(name)


class LocalPycryptokiClient(object):
    """Class forwards calls to pycryptoki to local client but looks identical to remote
    client


    """

    def __init__(self):
        """Nothing really to do"""
        pass

    def __getattr__(self, name):
        """
        Function that overrides python attribute lookup; automagically calls
        functions in pycryptoki if they're listed in the daemon
        """
        log.info("Running local pycryptoki command: {0}".format(name))
        if pycryptoki_functions.has_key(name):
            if 'c_initialize' in name:
                return object.__getattribute__(self, name)
            return pycryptoki_functions[name]
        elif functions_needing_serialization.has_key(name):
            return functions_needing_serialization[name]
        else:
            return object.__getattribute__(self, name)

    def c_initialize_ex(self):
        """ """
        c_finalize()
        return c_initialize_ex()

    def c_initialize(self):
        """ """
        c_finalize()
        return c_initialize()

    def kill(self):
        """ """
        # nothing to do here, maybe we should unload and reload the dll
        pass

    def cleanup(self):
        """ """
        # nothing to do here
        pass


def deserialize_dict(dictionary):
    """Helper function to convert a dictionary with <string, value> to <int, value>
    for xmlrpc

    :param dictionary:

    """
    deserialized_dictionary = {}
    for key, value in dictionary.iteritems():
        deserialized_dictionary[int(key)] = value
    return deserialized_dictionary
