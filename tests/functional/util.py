"""
Utility functions for testing
"""
from pycryptoki.defines import CKA_TOKEN


def get_session_template(default_template):
    """
    Set CKA_TOKEN to false on a template, so that it will be cleaned up on the
    session close.
    """
    default_template.copy()
    default_template[CKA_TOKEN] = False
    return default_template
