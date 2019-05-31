"""
Utility functions for user convenience. Differs from:

    - common_utils.py -- used by pycryptoki modules to ease cryptoki operations
    - cryptoki_helpers.py -- used to bootstrap pycryptoki

"""

from pycryptoki.defines import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
)
from pycryptoki.exceptions import LunaException
from pycryptoki.session_management import (
    c_initialize_ex,
    c_open_session_ex,
    login_ex,
    c_logout_ex,
    c_close_session_ex,
    c_finalize_ex,
    c_get_session_info_ex
)


class CryptokiInitialized(object):
    """Initialized context"""

    def __enter__(self):
        """Initialize cryptoki"""
        c_initialize_ex()

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """Finalize cryptoki"""
        c_finalize_ex()


class Session(object):
    """Opened session"""

    def __init__(self, slot, flags=CKF_SERIAL_SESSION | CKF_RW_SESSION, initialized=False):
        """
        Cryptoki can optionally already be initialized.

        :param slot: slot number
        :param flags: session flags
        :param initialized: whether cryptoki has already been initialized
        """
        self.slot = slot
        self.flags = flags
        self.manage_init = not initialized
        self.session = None

    def __enter__(self):
        """Open the session."""
        return self.open()

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """Close the session."""
        self.close()

    def open(self):
        """
        Open the session, initializing cryptoki if necessary.

        :return: session handle
        """
        if self.manage_init:
            c_initialize_ex()
        try:
            self.session = c_open_session_ex(self.slot, self.flags)
            return self.session
        except:
            if self.manage_init:
                c_finalize_ex()
            raise

    def close(self):
        """Close the session. Finalize if we initialized."""
        c_close_session_ex(self.session)
        if self.manage_init:
            c_finalize_ex()


class AuthenticatedSession(object):
    """Session which has a user authenticated; C_Login is run"""

    def __init__(self, password, user, session=None, slot=None):
        """
        A session can optionally already be open. Otherwise open one on entry.
        It is an error to omit both session and slot.

        :param password: user password
        :param user: user
        :param session: session handle of an already open session
        :param slot: slot number
        """
        if session is None and slot is None:
            raise LunaException("A slot ID or a session handle must be specified!")

        self.password = password
        self.user = user
        self.session = session  # Session handle
        self.slot = slot
        self._session = None    # Session object

    def __enter__(self):
        """
        Log in to a session. Open a session if one was not given.

        :return: session handle
        """
        if self.session is None:
            self._session = Session(self.slot)
            self.session = self._session.open()
        else:
            self.slot = c_get_session_info_ex(self.session)['slotID']
        try:
            login_ex(self.session, self.slot, self.password, self.user)
            return self.session
        except:
            if self._session:
                self._session.close()
            raise

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """
        Log out of the session. Close the session if we opened it.
        """
        c_logout_ex(self.session)
        if self._session:
            self._session.close()
