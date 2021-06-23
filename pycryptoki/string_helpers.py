import binascii

from six import integer_types, binary_type, string_types

from pycryptoki.lookup_dicts import ATTR_NAME_LOOKUP
from .conversions import to_hex, from_bytestring
from .cryptoki import CK_MECHANISM

PYC_MAX_ARG_LENGTH = 40


def _decode(value):
    """
    Attempt to convert a bytestring into something more readable. Assumes hex first, if that fails and non-standard
    characters are in the bytestring ( e.g. ``\x12``), convert to hex.

    Anything converted to hex will be returned as UTF-8; anything that is left 'as-is', will stay bytestring.
    """
    try:
        binascii.unhexlify(value)
        # value is already valid hex, return it.
        return value.decode("utf-8", "ignore")
    except (binascii.Error, TypeError):
        if "\\x" in repr(value):
            return to_hex(from_bytestring(value)).decode("utf-8", "ignore")
        return value


def _coerce_mech_to_str(mech):
    """
    Similar to the ``parse_mechanism`` function, but instead of creating the C mechanism structures,
    we want to print out the mechanism in a nicer way.

    :param mech: Dict, Mechanism class, or integer
    :return: String display of a mechanism.
    """
    from .mechanism import Mechanism

    if isinstance(mech, dict):
        mech = Mechanism(**mech)
    elif isinstance(mech, CK_MECHANISM):
        mech = mech
    elif isinstance(mech, integer_types):
        mech = Mechanism(mech_type=mech)
    elif isinstance(mech, Mechanism):
        pass

    return str(mech)


def _trunc(val, val_len=None):
    msg = str(val)
    if val_len is None:
        try:
            val_len = len(val)
        except TypeError:
            val_len = len(msg)

    if len(msg) > PYC_MAX_ARG_LENGTH:
        msg = "%s[...] (len: %s)" % (
            msg[:PYC_MAX_ARG_LENGTH],
            val_len,
        )
    return msg


def pformat_pyc_args(func_args):
    """
    Convert a dictionary of funcargs: funcvalues into a nicely formatted string.

    This will resolve template dictionary keys to CKA_ names, convert bytestring to
    hex, mask passwords, and truncate args over ``PYC_MAX_ARG_LENGTH`` to that size.

    :param func_args: dictionary
    :return: formatted string.
    """
    log_list = []
    for key, value in func_args.items():
        if "template" in key and isinstance(value, dict):
            # Means it's a template, so let's perform a lookup on all of the objects within
            # this.
            log_list.append("%s: " % key)
            # Sorted so we get the same order every time for testing purposes.
            for template_key, template_value in sorted(value.items(), key=lambda x: x[0]):
                log_list.append(
                    "\t%s: %s"
                    % (
                        ATTR_NAME_LOOKUP.get(template_key, "0x%08x" % template_key),
                        _trunc(_decode(template_value)),
                    )
                )
        elif "password" in key:
            log_list.append("%s: *" % key)
        elif "mechanism" in key:
            log_list.append("%s: " % key)
            nice_mech = _coerce_mech_to_str(value).splitlines()
            log_list.extend(["\t%s" % x for x in nice_mech])
        else:
            log_val = value
            val_len = None
            # Note: we get the length of value before we decode/truncate it.
            if isinstance(value, (binary_type, string_types)):
                if isinstance(value, binary_type):
                    log_val = _decode(value)
                val_len = len(value)
            else:
                log_val = str(value)

            msg = "\t%s: %s" % (key, _trunc(log_val, val_len))

            log_list.append(msg)

    return log_list
