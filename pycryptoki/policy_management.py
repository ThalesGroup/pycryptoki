from pycryptoki.cryptoki import CA_SetHSMPolicy, CA_SetContainerPolicy, CK_ULONG, \
    CA_SetDestructiveHSMPolicy
from pycryptoki.test_functions import make_error_handle_function

def ca_set_hsm_policy(h_session, policy_id, policy_val):
    '''
    Sets the HSM policies by calling CA_SetHSMPolicy
    
    @param h_session: The session handle of the administrator setting the HSM policy
    @param policy_id: The ID of the policy being set
    @param policy_val: The value of the policy being set 
    
    @return: The result code
    '''
    ret = CA_SetHSMPolicy(h_session, CK_ULONG(policy_id), CK_ULONG(policy_val))
    return ret
ca_set_hsm_policy_ex = make_error_handle_function(ca_set_hsm_policy)

def ca_set_destructive_hsm_policy(h_session, policy_id, policy_val):
    '''
    Sets the destructive HSM policies by calling CA_SetDestructiveHSMPolicy
    
    @param h_session: The session handle of the administrator setting the HSM policy
    @param policy_id: The ID of the policy being set
    @param policy_val: The value of the policy being set 
    
    @return: The result code
    '''
    ret = CA_SetDestructiveHSMPolicy(h_session, CK_ULONG(policy_id), CK_ULONG(policy_val))
    return ret
ca_set_destructive_hsm_policy_ex = make_error_handle_function(ca_set_destructive_hsm_policy)

def ca_set_container_policy(h_session, container_number, policy_id, policy_val):
    '''
    Sets a policy on the container.
    
    NOTE: With per partition SO this method should generally not be used. Instead 
    ca_set_partition_policies should be used
    
    @param h_session: The session handle of the entity with permission to change the policy
    @param container_number: The container number to set the policy on.
    @param policy_id: The identifier of the policy (ex. CONTAINER_CONFIG_MINIMUM_PIN_LENGTH)
    @param policy_val: The value to set the policy to
    
    @return: The result code
    '''
    ret = CA_SetContainerPolicy(h_session, CK_ULONG(container_number), CK_ULONG(policy_id), CK_ULONG(policy_val))
    return ret
ca_set_container_policy_ex = make_error_handle_function(ca_set_container_policy)

