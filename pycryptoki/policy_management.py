from pycryptoki.cryptoki import CA_SetContainerPolicy, CK_ULONG
from pycryptoki.test_functions import make_error_handle_function


def ca_set_container_policy(h_session, container_number, policy_id, policy_val):
    """Sets a policy on the container.

    NOTE: With per partition SO this method should generally not be used. Instead
    ca_set_partition_policies should be used

    :param h_session: The session handle of the entity with permission to change the policy
    :param container_number: The container number to set the policy on.
    :param policy_id: The identifier of the policy (ex. CONTAINER_CONFIG_MINIMUM_PIN_LENGTH)
    :param policy_val: The value to set the policy to
    :returns: The result code

    """
    ret = CA_SetContainerPolicy(h_session, CK_ULONG(container_number), CK_ULONG(policy_id), CK_ULONG(policy_val))
    return ret


ca_set_container_policy_ex = make_error_handle_function(ca_set_container_policy)
