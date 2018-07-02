from six import integer_types

from .conversions import to_hex, from_bytestring
from .cryptoki import CK_MECHANISM


def _decode(value):
    """
    Attempts to convert invalid bytestring data to hex while preserving regular text.

    It does this by attempting to decode the string to unicode (using utf8), and on failure
    converting to hex. There are some corner cases where bytestring data is still valid unicode.

    :param value: Bytestring that should be converted to either unicode or hex.
    :return: string.
    """
    try:
        ret = value.decode('utf-8', 'strict')
    except UnicodeDecodeError:
        ret = to_hex(from_bytestring(value)).decode('utf-8', 'backslashreplace')
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
