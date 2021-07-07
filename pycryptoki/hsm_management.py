"""
Methods responsible for pycryptoki 'hsm management' set of commands.
"""
from _ctypes import pointer
from ctypes import byref, create_string_buffer, cast

from .attributes import Attributes, to_byte_array
from .common_utils import AutoCArray, refresh_c_arrays
from .cryptoki import (
    CK_SLOT_ID,
    CK_USER_TYPE,
    CA_SetTokenCertificateSignature,
    CA_HAInit,
    CA_HAInitExtended,
    CA_CreateLoginChallenge,
    CA_InitializeRemotePEDVector,
    CA_DeleteRemotePEDVector,
    CA_MTKRestore,
    CA_MTKResplit,
    CA_MTKZeroize,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_BYTE,
    CK_CHAR_PTR,
    CK_CHAR,
    CA_SetHSMPolicy,
    CK_SESSION_HANDLE,
    CA_SetHSMPolicies,
    CA_SetDestructiveHSMPolicy,
    CA_SetDestructiveHSMPolicies,
    CA_GetHSMCapabilitySet,
    CA_GetHSMCapabilitySetting,
    CA_GetHSMPolicySet,
    CA_GetHSMPolicySetting,
    CA_ResetDevice,
)
from .exceptions import make_error_handle_function


def c_performselftest(slot, test_type, input_data, input_data_len):
    """Test: Performs a self test for specified test type on a given slot.

    :param slot: slot number
    :param test_type: type of test CK_ULONG
    :param input_data: pointer to input data CK_BYTE_PTR
    :param input_data_len: input data length CK_ULONG
    :returns: the result code

        [CK_SLOT_ID, CK_ULONG, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]

    """

    test_type = CK_ULONG(test_type)
    input_length = CK_ULONG(input_data_len)
    input_data = (CK_BYTE * input_data_len)(*input_data)
    output_data = cast(create_string_buffer(b"", input_data_len), CK_BYTE_PTR)
    output_data_len = CK_ULONG()
    try:
        from .cryptoki import CA_PerformSelfTest as selftest
    except ImportError:
        from .cryptoki import C_PerformSelftest as selftest

    ret = selftest(slot, test_type, input_data, input_length, output_data, byref(output_data_len))
    return ret, output_data


c_performselftest_ex = make_error_handle_function(c_performselftest)


def ca_settokencertificatesignature(
    h_session, access_level, customer_id, pub_template, signature, signature_len
):
    """Completes the installation of a certificate on a token.
    The caller must supply a public key and a signature for token certificate.
    The public key is provided through the template; it must contain a key
    type, a modulus and a public exponent.

    :param int h_session: Session handle
    :param access_level: the access level
    :param customer_id: the customer ID
    :param pub_template: the public template
    :param signature: the signature
    :param signature_len: the length in bytes of the signature
    :returns: the result code

    """

    access_level = CK_ULONG(access_level)
    customer_id = CK_ULONG(customer_id)

    key_attributes = Attributes(pub_template)
    pub_template_len = CK_ULONG(len(pub_template))
    signature = (CK_BYTE * signature_len)(*signature)
    signature_length = CK_ULONG(signature_len)
    ret = CA_SetTokenCertificateSignature(
        h_session,
        access_level,
        customer_id,
        key_attributes.get_c_struct(),
        pub_template_len,
        signature,
        signature_length,
    )
    return ret


ca_settokencertificatesignature_ex = make_error_handle_function(ca_settokencertificatesignature)


def ca_hainit(h_session, h_key):
    """Creates a login key pair on the primary token.

    :param int h_session: Session handle
    :param h_key: the login private key
    :returns: the result code

    """
    ret = CA_HAInit(h_session, h_key)

    return ret


ca_hainit_ex = make_error_handle_function(ca_hainit)


def ca_hainitextended(h_session, h_key, pkc, user_types):
    """Creates a login key pair on the primary token.

    :param int h_session: Session handle
    :param h_key: the login private key or 0
    :param pkc: private key PKC or None
    :param user_types: list of pairs (user, tokenType) i.e.
        [(CKU_SO, CKF_ADMIN_TOKEN)]
        [(CKU_USER, 0)]
        or None if revoke is issued
    :returns: the result code

    """
    if pkc is not None:
        pkc_ptr, pkc_len = to_byte_array(pkc)
    else:
        pkc_ptr = None
        pkc_len = 0

    if user_types is not None:
        users_ptr = (CK_ULONG * len(user_types))(*[x[0] for x in user_types])
        tokens_ptr = (CK_ULONG * len(user_types))(*[x[1] for x in user_types])
        number_roles = CK_ULONG(len(user_types))
    else:
        users_ptr = None
        tokens_ptr = None
        number_roles = CK_ULONG(0)
    ret = CA_HAInitExtended(h_session, h_key, pkc_ptr, pkc_len, users_ptr, tokens_ptr, number_roles)
    return ret


ca_hainitextended_ex = make_error_handle_function(ca_hainitextended)


def ca_createloginchallenge(h_session, user_type, challenge):
    """Creates a login challenge for the given user.

    :param int h_session: Session handle
    :param user_type: user type
    :param challenge: challenge
    :returns: the result code

    """

    challenge_length = CK_ULONG(len(challenge))
    challenge = cast(create_string_buffer(challenge), CK_CHAR_PTR)
    output_data_length = CK_ULONG()
    output_data = CK_CHAR()
    ret = CA_CreateLoginChallenge(
        h_session,
        CK_USER_TYPE(user_type),
        challenge_length,
        challenge,
        output_data_length,
        output_data,
    )
    return ret, output_data


ca_createloginchallenge_ex = make_error_handle_function(ca_createloginchallenge)


def ca_initializeremotepedvector(h_session):
    """Initializes a remote PED vector

    :param int h_session: Session handle
    :returns: the result code

    """
    ret = CA_InitializeRemotePEDVector(h_session)
    return ret


ca_initializeremotepedvector_ex = make_error_handle_function(ca_initializeremotepedvector)


def ca_deleteremotepedvector(h_session):
    """Deletes a remote PED vector

    :param int h_session: Session handle
    :returns: the result code

    """
    ret = CA_DeleteRemotePEDVector(h_session)
    return ret


ca_deleteremotepedvector_ex = make_error_handle_function(ca_deleteremotepedvector)


def ca_mtkrestore(slot):
    """Restore the MTK

    :param slot: slot number
    :returns: the result code

    """
    ret = CA_MTKRestore(CK_SLOT_ID(slot))
    return ret


ca_mtkrestore_ex = make_error_handle_function(ca_mtkrestore)


def ca_mtkresplit(slot):
    """Resplit the MTK

    :param slot: slot number
    :returns: the result code

    """
    ret = CA_MTKResplit(CK_SLOT_ID(slot))
    return ret


ca_mtkresplit_ex = make_error_handle_function(ca_mtkresplit)


def ca_mtkzeroize(slot):
    """Zeroize the MTK

    :param slot: slot number
    :returns: the result code

    """
    ret = CA_MTKZeroize(CK_SLOT_ID(slot))
    return ret


ca_mtkzeroize_ex = make_error_handle_function(ca_mtkzeroize)


def ca_set_hsm_policy(h_session, policy_id, policy_val):
    """Sets the HSM policies by calling CA_SetHSMPolicy

    :param int h_session: Session handle
    :param policy_id: The ID of the policy being set
    :param policy_val: The value of the policy being set
    :returns: The result code

    """
    ret = CA_SetHSMPolicy(h_session, CK_ULONG(policy_id), CK_ULONG(policy_val))
    return ret


ca_set_hsm_policy_ex = make_error_handle_function(ca_set_hsm_policy)


def ca_set_hsm_policies(h_session, policies):
    """
    Set multiple HSM policies.

    :param int h_session: Session handle
    :param policies: dict of policy ID ints and value ints
    :return: result code
    """
    h_sess = CK_SESSION_HANDLE(h_session)
    pol_id_list = list(policies.keys())
    pol_val_list = list(policies.values())
    pol_ids = AutoCArray(data=pol_id_list, ctype=CK_ULONG)
    pol_vals = AutoCArray(data=pol_val_list, ctype=CK_ULONG)

    ret = CA_SetHSMPolicies(h_sess, pol_ids.size.contents, pol_ids.array, pol_vals.array)

    return ret


ca_set_hsm_policies_ex = make_error_handle_function(ca_set_hsm_policies)


def ca_set_destructive_hsm_policy(h_session, policy_id, policy_val):
    """Sets the destructive HSM policies by calling CA_SetDestructiveHSMPolicy

    :param int h_session: Session handle
    :param policy_id: The ID of the policy being set
    :param policy_val: The value of the policy being set
    :returns: The result code

    """
    ret = CA_SetDestructiveHSMPolicy(h_session, CK_ULONG(policy_id), CK_ULONG(policy_val))
    return ret


ca_set_destructive_hsm_policy_ex = make_error_handle_function(ca_set_destructive_hsm_policy)


def ca_set_destructive_hsm_policies(h_session, policies):
    """
    Set multiple HSM policies.

    :param int h_session: Session handle
    :param policies: dict of policy ID ints and value ints
    :return: result code
    """
    h_sess = CK_SESSION_HANDLE(h_session)
    pol_id_list = list(policies.keys())
    pol_val_list = list(policies.values())
    pol_ids = AutoCArray(data=pol_id_list, ctype=CK_ULONG)
    pol_vals = AutoCArray(data=pol_val_list, ctype=CK_ULONG)

    ret = CA_SetDestructiveHSMPolicies(h_sess, pol_ids.size.contents, pol_ids.array, pol_vals.array)

    return ret


ca_set_destructive_hsm_policies_ex = make_error_handle_function(ca_set_destructive_hsm_policies)


def ca_get_hsm_capability_set(slot):
    """
    Get the capabilities of the given slot.

    :param int slot: Target slot number
    :return: retcode, {id: val} dict of capabilities (None if command failed)
    """
    slot_id = CK_SLOT_ID(slot)
    cap_ids = AutoCArray()
    cap_vals = AutoCArray()

    @refresh_c_arrays(1)
    def _get_hsm_caps():
        """Closer for retries to work w/ properties"""
        return CA_GetHSMCapabilitySet(
            slot_id, cap_ids.array, cap_ids.size, cap_vals.array, cap_vals.size
        )

    ret = _get_hsm_caps()

    return ret, dict(list(zip(cap_ids, cap_vals)))


ca_get_hsm_capability_set_ex = make_error_handle_function(ca_get_hsm_capability_set)


def ca_get_hsm_capability_setting(slot, capability_id):
    """
    Get the value of a single capability

    :param slot: slot ID of slot to query
    :param capability_id: capability ID
    :return: result code, CK_ULONG representing capability active or not
    """
    slot_id = CK_SLOT_ID(slot)
    cap_id = CK_ULONG(capability_id)
    cap_val = CK_ULONG()
    ret = CA_GetHSMCapabilitySetting(slot_id, cap_id, pointer(cap_val))
    return ret, cap_val.value


ca_get_hsm_capability_setting_ex = make_error_handle_function(ca_get_hsm_capability_setting)


def ca_get_hsm_policy_set(slot):
    """
    Get the policies of the given slot.

    :param int slot: Target slot number
    :return: retcode, {id: val} dict of policies (None if command failed)
    """
    slot_id = CK_SLOT_ID(slot)
    pol_ids = AutoCArray()
    pol_vals = AutoCArray()

    @refresh_c_arrays(1)
    def _ca_get_hsm_policy_set():
        """Closure for retries."""
        return CA_GetHSMPolicySet(
            slot_id, pol_ids.array, pol_ids.size, pol_vals.array, pol_vals.size
        )

    ret = _ca_get_hsm_policy_set()

    return ret, dict(list(zip(pol_ids, pol_vals)))


ca_get_hsm_policy_set_ex = make_error_handle_function(ca_get_hsm_policy_set)


def ca_get_hsm_policy_setting(slot, policy_id):
    """
    Get the value of a single policy

    :param slot: slot ID of slot to query
    :param policy_id: policy ID
    :return: result code, CK_ULONG representing policy active or not
    """
    slot_id = CK_SLOT_ID(slot)
    pol_id = CK_ULONG(policy_id)
    pol_val = CK_ULONG()
    ret = CA_GetHSMPolicySetting(slot_id, pol_id, pointer(pol_val))
    return ret, pol_val.value


ca_get_hsm_policy_setting_ex = make_error_handle_function(ca_get_hsm_policy_setting)


def ca_reset_device(slot, flags=0):
    """resets the hsm device

    :param slot: slot number
    :param flags: flags
    :returns: the result code

    """
    ret = CA_ResetDevice(CK_SLOT_ID(slot), CK_ULONG(flags))
    return ret


ca_reset_device_ex = make_error_handle_function(ca_reset_device)
