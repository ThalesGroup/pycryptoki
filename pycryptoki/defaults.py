"""
A file containing commonly used strings or other data similar to a config file
"""

# The location of the cryptoki file, if specified as None the environment variable
# ChrystokiConfigurationPath will be used or it will revert to using /etc/Chrystoki.conf
import os

CHRYSTOKI_CONFIG_FILE = None

# The location of the DLL file, if not specified it will try to look up the file in
# the Chrystoki config file specified be the variable CHRYSTOKI_CONFIG_FILE
CHRYSTOKI_DLL_FILE = None

ADMIN_PARTITION_LABEL = b'no label'
AUDITOR_LABEL = b'auditorlabel'

ADMINISTRATOR_USERNAME = b'Administrator'
ADMINISTRATOR_PASSWORD = b'1q@W3e$R'

AUDITOR_USERNAME = b'Auditor'
AUDITOR_PASSWORD = b'W3e$R'

CO_USERNAME = b'Crypto Officer'
CO_PASSWORD = b'userpin'

DEFAULT_USERNAME = b'default_user'
DEFAULT_LABEL = b'default_label'
DEFAULT_PASSWORD = b'userpin'

DEFAULT_UTILS_PATH = '/usr/safenet/lunaclient/sbin'
FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

user_credentials = {ADMINISTRATOR_USERNAME: ADMINISTRATOR_PASSWORD,
                    AUDITOR_USERNAME: AUDITOR_PASSWORD,
                    CO_USERNAME: CO_PASSWORD,
                    DEFAULT_USERNAME: DEFAULT_PASSWORD}

DES3_KEY_SIZE = 120

MANUFACTURER_ID = b"SafeNet Inc."
MODEL = b"Luna K6"

ADMIN_SLOT = int(os.environ.get("ADMIN_SLOT", 1))
