"""
Lookup dictionary for converting CK_ULONG return codes into
their string equivalents -- backwards compatibility
"""
import warnings

warnings.warn("Deprecated! Use 'pycryptoki.lookup_dicts' instead", DeprecationWarning)

# Backwards compatibility for now...
from .lookup_dicts import ret_vals_dictionary
