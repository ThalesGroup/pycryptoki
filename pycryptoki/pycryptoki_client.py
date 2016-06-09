"""
Contains both a local and remote pycryptoki client
"""
import logging
import socket
from functools import wraps

import rpyc
import time

from rpyc.core.protocol import PingError

from .daemon import rpyc_pycryptoki

log = logging.getLogger(__name__)


# from https://github.com/saltycrane/retry-decorator/blob/master/decorators.py
def retry(ExceptionToCheck, tries=4, delay=3, backoff=2, logger=None):
    """Retry calling the decorated function using an exponential backoff.

    http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
    original from: http://wiki.python.org/moin/PythonDecoratorLibrary#Retry

    :param ExceptionToCheck: the exception to check. may be a tuple of
        exceptions to check
    :type ExceptionToCheck: Exception or tuple
    :param tries: number of times to try (not retry) before giving up
    :type tries: int
    :param delay: initial delay between retries in seconds
    :type delay: int
    :param backoff: backoff multiplier e.g. value of 2 will double the delay
        each retry
    :type backoff: int
    :param logger: logger to use. If None, print
    :type logger: logging.Logger instance
    """

    def deco_retry(f):

        @wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 1:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck, e:
                    msg = "%s, Retrying in %d seconds..." % (str(e), mdelay)
                    if logger:
                        logger.warning(msg)
                    else:
                        print msg
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)

        return f_retry  # true decorator

    return deco_retry


def connection_test(func):
    """
    Decorator to check that the underlying rpyc connection is alive before
    sending commands across it.

    :param func:
    :return:
    """
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        """
        Inner closure.
        """
        if not self.started:
            self.start()

        return func(self, *args, **kwargs)

    return wrapper


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
        self.connection = None
        self.server = None

    def kill(self):
        """
        Close out the local RPYC connection.
        """
        # maybe we should be reloading cryptoki dll?
        if self.started and not self.connection.closed:
            log.info("Stopping remote pycryptoki connection.")
            self.connection.close()

    @retry((socket.error, EOFError, PingError), logger=log)
    def start(self):
        """
        Start the connection to the remote RPYC daemon.
        """
        if not self.started:
            log.info("Starting remote pycryptoki connection")
            self.connection = rpyc.classic.connect(self.ip, port=self.port)
            self.connection.ping()
            self.server = self.connection.root

    def cleanup(self):
        """ """
        pass

    @property
    def started(self):
        """
        Check if the RPYC connection is alive.

        :return: boolean
        """
        try:
            return (self.connection is not None and
                    self.server is not None and
                    self.connection.ping() is None)
        except (PingError, EOFError):
            self.connection = None
            self.server = None
            return False

    @connection_test
    def __getattr__(self, name):
        """
        This is the python default attribute handler, if an attribute
        is not found it's probably a pycryptoki call that we forward
        automagically to the server
        """
        if hasattr(self.server, name):
            def wrapper(*args, **kwargs):
                """
                Closer to allow us to log the full args & keyword argument list
                of all calls.
                """
                masked_args = args
                masked_kwargs = kwargs
                if any(x in name for x in ("login", "create_container")):
                    masked_args = tuple("*" for _ in args)
                    masked_kwargs = {key: "*" for key, _ in kwargs.items()}

                masked_args = ["{:.10}".format(str(arg)) for arg in masked_args]
                masked_kwargs = ["{:.10}".format(str(kwarg)) for kwarg in masked_kwargs]
                log.info("Running remote pycryptoki command: "
                         "{0}(args={1}, kwargs={2})".format(name, masked_args, masked_kwargs))
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
        return getattr(rpyc_pycryptoki, name)

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
