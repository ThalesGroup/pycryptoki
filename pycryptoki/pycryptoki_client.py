from __future__ import print_function

from rpyc.utils.classic import SlaveService
from six import string_types, binary_type

from pycryptoki.string_helpers import _decode, _coerce_mech_to_str, pformat_pyc_args

"""
Contains both a local and remote pycryptoki client
"""
import inspect
import logging
import socket
from functools import wraps

import rpyc
import time

from rpyc.core.protocol import PingError

from .daemon import rpyc_pycryptoki
from .lookup_dicts import ATTR_NAME_LOOKUP, ret_vals_dictionary

LOG = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 300

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
                except ExceptionToCheck as e:
                    msg = "%s, Retrying in %d seconds..." % (str(e), mdelay)
                    if logger:
                        logger.warning(msg)
                    else:
                        print(msg)
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


def log_args(funcname, arg_dict):
    """
    This will run through each of the key, value pairs of the argument spec passed into
    pycryptoki and perform the following checks:

        * if key is a template, format the template data through a dict lookup
        * if key is password, set the log data to be '*'
        * if value is longer than 40 characters, abbreviate it.

    :param arg_dict:
    :return:
    """
    log_msg = "Remote pycryptoki command: {}()".format(funcname)
    if arg_dict:
        log_msg += " with args:"
    formatted_args = pformat_pyc_args(arg_dict)
    log_list = [log_msg] + ["\t{}".format(x) for x in formatted_args]
    LOG.debug("\n".join(log_list))


class RemotePycryptokiClient(object):
    """Class to handle connecting to a remote Pycryptoki RPYC daemon.

    After instantiation, you can use it directly to make calls to a remote
    cryptoki library via RPYC (no need to do any imports or anything like that, just
    use the direct pycryptoki call like client.c_initialize_ex() )

    :param ip: IP Address of the client the remote daemon is running on.
    :param port: What Port the daemon is running on.
    """

    def __init__(self, ip=None, port=None, timeout=300):
        self.ip = ip
        self.port = port
        self.default_timeout = timeout
        self.connection = None
        self.server = None

    def kill(self):
        """
        Close out the local RPYC connection.
        """
        # maybe we should be reloading cryptoki dll?
        if self.started and not self.connection.closed:
            LOG.info("Stopping remote pycryptoki connection.")
            self.connection.close()

    @retry((socket.error, EOFError, PingError), logger=LOG)
    def start(self):
        """
        Start the connection to the remote RPYC daemon.
        """
        if not self.started:
            LOG.info("Starting remote pycryptoki connection")
            self.connection = rpyc.utils.factory.connect(
                host=self.ip,
                port=self.port,
                service=SlaveService,
                config={"sync_request_timeout": self.default_timeout},
            )
            self.connection.ping()
            self.server = self.connection.root

    @property
    def timeout(self):
        """
        Get the underlying connection timeout value.
        """
        if self.connection:
            # Possible issue here, on RPYC 3.4.x, this timeout is a class-var (SYNC_REQUEST_TIMEOUT)
            # I don't know if I want to update it, because we haven't really seen any issues of
            # timeouts on 3.4.x. It's possible that there's some backend changes to how commands
            # are dispatched on 4.x that makes the timeout come into play more...
            return self.connection._config.get("sync_request_timeout") or getattr(
                self.connection, "SYNC_REQUEST_TIMEOUT", None
            )
        else:
            return None

    @timeout.setter
    def timeout(self, value):
        """
        Set the underlying connection's timeout value. Useful if you're doing something like
        DH param generation which can take a long time... or doing an 8k RSA keygen on a G5.
        """
        self.connection._config["sync_request_timeout"] = value

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
            return (
                self.connection is not None
                and self.server is not None
                and self.connection.ping() is None
            )
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
                will_raise = False
                if name.endswith("_ex"):
                    func = getattr(self.server, name.rsplit("_ex", 1)[0])
                    will_raise = True
                else:
                    func = getattr(self.server, name)
                nice_args = inspect.getcallargs(func, *args, **kwargs)

                log_args(name, nice_args)

                remote_func = getattr(self.server, name)
                ret = remote_func(*args, **kwargs)
                # Two major calling types for pycryptoki:
                # 1. with _ex appended, which will raise an exception if retcode != 0
                # 2. without _ex, which will return either just the retcode, or a tuple where the
                #    first item is the retcode.
                # We can assume the calls that could raise an exception will *also* log the retcode.
                if not will_raise:
                    retcode = ret
                    if isinstance(ret, tuple):
                        retcode = ret[0]
                    LOG.debug(
                        "Remote call '%s' returned %s (%s)",
                        name,
                        ret_vals_dictionary.get(retcode, "Unknown"),
                        retcode,
                    )
                return ret

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
        LOG.info("Running local pycryptoki command: {0}".format(name))
        return getattr(rpyc_pycryptoki, name)

    def kill(self):
        """ """
        # nothing to do here, maybe we should unload and reload the dll
        pass

    def cleanup(self):
        """ """
        # nothing to do here
        pass
