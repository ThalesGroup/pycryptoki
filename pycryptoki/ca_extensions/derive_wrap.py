"""
derive and wrap extended method
"""
import logging
from ctypes import c_ubyte, string_at

from pycryptoki.defines import CKR_OK
from pycryptoki.common_utils import AutoCArray
from pycryptoki.attributes import Attributes
from pycryptoki.cryptoki import CA_DeriveKeyAndWrap, CK_OBJECT_HANDLE, CK_ULONG
from pycryptoki.mechanism import parse_mechanism
from pycryptoki.exceptions import make_error_handle_function

LOG = logging.getLogger(__name__)


def ca_derive_key_and_wrap(h_session, derive_mechanism, h_base_key, derive_template,
                           wrapping_key, wrap_mechanism, output_buffer=2048):
    """
    Derive a key from the base key and wrap it off the HSM using the wrapping key

    :param int h_session: The session to use
    :param int h_base_key: The base key
    :param dict derive_template: A python template of attributes to set on derived key
    :param derive_mechanism: See the :py:func:`~pycryptoki.mechanism.parse_mechanism` function
        for possible values.
    :param int wrapping_key: The wrapping key based on the encryption flavor
    :param wrap_mechanism: See the :py:func:`~pycryptoki.mechanism.parse_mechanism` function
        for possible values.
    :param output_buffer: The size of the wrapped key, defaulted to a cert size
    :returns: (Retcode, python bytestring representing wrapped key)
    :rtype: tuple
    """
    # derive key parameters preparation
    derive_mech = parse_mechanism(derive_mechanism)
    c_template = Attributes(derive_template).get_c_struct()
    # wrapping key parameter preparation
    wrap_mech = parse_mechanism(wrap_mechanism)
    # derive key and wrap function requires the size and in that way is
    # inconsistent with wrap function
    size = CK_ULONG(output_buffer)
    wrapped_key = AutoCArray(ctype=c_ubyte,
                             size=size)

    ret = CA_DeriveKeyAndWrap(h_session, derive_mech, CK_OBJECT_HANDLE(h_base_key),
                              c_template, CK_ULONG(len(derive_template)),
                              wrap_mech, CK_OBJECT_HANDLE(wrapping_key),
                              wrapped_key.array, wrapped_key.size)

    if ret != CKR_OK:
        return ret, None

    return ret, string_at(wrapped_key.array, wrapped_key.size.contents.value)


ca_derive_key_and_wrap_ex = make_error_handle_function(ca_derive_key_and_wrap)
