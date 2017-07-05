"""
PKCS11 Interface to the following functions:

* c_generate_random
* c_seed_random
* c_digest
* c_digestkey
* c_create_object
* c_set_ped_id (CA_ function)
* c_get_ped_id (CA_ function)
"""
from _ctypes import POINTER
from ctypes import create_string_buffer, cast, byref, string_at, c_ubyte

from six import integer_types

from pycryptoki.conversions import from_bytestring
from .attributes import Attributes, to_char_array, to_byte_array
from .common_utils import refresh_c_arrays, AutoCArray
from .cryptoki import C_GenerateRandom, CK_BYTE_PTR, CK_ULONG, \
    C_SeedRandom, C_DigestInit, C_DigestUpdate, C_DigestFinal, C_Digest, C_CreateObject, \
    CA_SetPedId, CK_SLOT_ID, CA_GetPedId, C_DigestKey
from .defines import CKR_OK
from .mechanism import Mechanism, NullMech, parse_mechanism
from .sign_verify import do_multipart_sign_or_digest
from .exceptions import make_error_handle_function


def c_generate_random(h_session, length):
    """Generates a sequence of random numbers

    :param int h_session: Session handle
    :param int length: The length in bytes of the random number sequence
    :returns: (retcode, A string of random data)
    :rtype: tuple
    """

    random_data = create_string_buffer(b"", length)
    data_ptr = cast(random_data, CK_BYTE_PTR)
    ret = C_GenerateRandom(h_session, data_ptr, CK_ULONG(length))

    data = string_at(data_ptr, length)
    return ret, data


c_generate_random_ex = make_error_handle_function(c_generate_random)


def c_seed_random(h_session, seed):
    """Seeds the random number generator

    :param int h_session: Session handle
    :param bytes seed: A python string of some seed
    :returns: retcode
    :rtype: int
    """
    seed_bytes = cast(create_string_buffer(seed), CK_BYTE_PTR)
    if isinstance(seed, (integer_types, float)):
        seed_length = seed
    else:
        seed_length = CK_ULONG(len(seed))
    ret = C_SeedRandom(h_session, seed_bytes, seed_length)
    return ret


c_seed_random_ex = make_error_handle_function(c_seed_random)


def c_digest(h_session, data_to_digest, digest_flavor, mechanism=None):
    """Digests some data

    :param int h_session: Session handle
    :param bytes data_to_digest: The data to digest, either a string or a list of strings.
        If this is a list a multipart operation will be used
    :param int digest_flavor: The flavour of the mechanism to digest (MD2, SHA-1, HAS-160,
        SHA224, SHA256, SHA384, SHA512)
    :param mechanism: See the :py:func:`~pycryptoki.mechanism.parse_mechanism` function
        for possible values. If None will use digest flavor.
    :returns: (retcode, a python string of the digested data)
    :rtype: tuple
    """
    if mechanism is None:
        mech = parse_mechanism(digest_flavor)
    else:
        mech = parse_mechanism(mechanism)

    # Initialize Digestion
    ret = C_DigestInit(h_session, mech)
    if ret != CKR_OK:
        return ret, None

    # if a list is passed out do an digest operation on each string in the list, otherwise just
    # do one digest operation
    is_multi_part_operation = isinstance(data_to_digest, (list, tuple))

    if is_multi_part_operation:
        ret, digested_python_string = do_multipart_sign_or_digest(h_session, C_DigestUpdate,
                                                                  C_DigestFinal,
                                                                  data_to_digest)
    else:
        # Get arguments
        c_data_to_digest, c_digest_data_len = to_byte_array(from_bytestring(data_to_digest))
        c_data_to_digest = cast(c_data_to_digest, POINTER(c_ubyte))

        digested_data = AutoCArray(ctype=c_ubyte)

        @refresh_c_arrays(1)
        def _digest():
            """ Perform the digest operations
            """
            return C_Digest(h_session,
                            c_data_to_digest, c_digest_data_len,
                            digested_data.array, digested_data.size)

        ret = _digest()
        if ret != CKR_OK:
            return ret, None

        # Convert Digested data into a python string
        digested_python_string = string_at(digested_data.array, len(digested_data))

    return ret, digested_python_string


c_digest_ex = make_error_handle_function(c_digest)


def c_digestkey(h_session, h_key, digest_flavor, mechanism=None):
    """Digest a key

    :param int h_session: Session handle
    :param int h_key: Key to digest
    :param int digest_flavor: Digest flavor
    :param mechanism: See the :py:func:`~pycryptoki.mechanism.parse_mechanism` function
        for possible values. If None will use digest flavor.
    """
    if mechanism is None:
        mech = parse_mechanism(digest_flavor)
    else:
        mech = parse_mechanism(mechanism)

    # Initialize Digestion
    ret = C_DigestInit(h_session, mech)
    if ret != CKR_OK:
        return ret

    ret = C_DigestKey(h_session, h_key)

    return ret


c_digestkey_ex = make_error_handle_function(c_digestkey)


def c_create_object(h_session, template):
    """Creates an object based on a given python template

    :param int h_session: Session handle
    :param dict template: The python template which the object will be based on
    :returns: (retcode, the handle of the object)
    :rtype: tuple
    """
    c_template = Attributes(template).get_c_struct()
    new_object_handle = CK_ULONG()
    ret = C_CreateObject(h_session, c_template, CK_ULONG(len(template)), byref(new_object_handle))

    return ret, new_object_handle.value


c_create_object_ex = make_error_handle_function(c_create_object)


def c_set_ped_id(slot, id):
    """Set the PED ID for the given slot.

    :param slot: slot number
    :param id: PED ID to use
    :returns: The result code

    """
    ret = CA_SetPedId(CK_SLOT_ID(slot), CK_ULONG(id))
    return ret


c_set_ped_id_ex = make_error_handle_function(c_set_ped_id)


def c_get_ped_id(slot):
    """Get the PED ID for the given slot.

    :param slot: slot number
    :returns: The result code and ID

    """
    pedId = CK_ULONG()
    ret = CA_GetPedId(CK_SLOT_ID(slot), byref(pedId))
    return ret, pedId.value


c_get_ped_id_ex = make_error_handle_function(c_get_ped_id)
