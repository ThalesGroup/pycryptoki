from six import integer_types, binary_type, string_types

from pycryptoki.lookup_dicts import ATTR_NAME_LOOKUP
from .conversions import to_hex, from_bytestring
from .cryptoki import CK_MECHANISM

PYC_MAX_ARG_LENGTH = 40


def _decode(value):
    """
    Attempts to convert invalid bytestring data to hex while preserving regular text.

    It does this by attempting to decode the string to unicode (using utf8), and on failure
    converting to hex. There are some corner cases where bytestring data is still valid unicode.

    :param value: Bytestring that should be converted to either unicode or hex.
    :return: string.
    """
    try:
        ret = value.decode("utf-8", "strict")
    except UnicodeDecodeError:
        ret = to_hex(from_bytestring(value)).decode("utf-8", "backslashreplace")
    except Exception:
        ret = value
    return ret


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
            log_list.append("\t%s: " % key)
            # Sorted so we get the same order every time for testing purposes.
            for template_key, template_value in sorted(value.items(), key=lambda x: x[0]):
                log_list.append(
                    "\t\t%s: %s"
                    % (ATTR_NAME_LOOKUP.get(template_key, "0x%08x" % template_key), template_value)
                )
        elif "password" in key:
            log_list.append("\t%s: *" % key)
        elif "mechanism" in key:
            log_list.append("\t%s: " % key)
            nice_mech = _coerce_mech_to_str(value).splitlines()
            log_list.extend(["\t\t%s" % x for x in nice_mech])
        else:
            log_val = value
            if isinstance(value, (binary_type, string_types)):
                if isinstance(value, binary_type):
                    log_val = _decode(value)
            else:
                log_val = str(value)

            if len(log_val) > PYC_MAX_ARG_LENGTH:
                msg = "\t%s: %s[...]%s" % (
                    key,
                    log_val[: PYC_MAX_ARG_LENGTH // 2],
                    log_val[-PYC_MAX_ARG_LENGTH // 2 :],
                )
            else:
                msg = "\t\t%s: %s" % (key, log_val)

            log_list.append(msg)

    return "\n".join(log_list)
