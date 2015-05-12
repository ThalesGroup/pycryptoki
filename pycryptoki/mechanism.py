from ctypes import c_void_p, cast, pointer, POINTER, sizeof, c_char_p, \
    create_string_buffer
from pycryptoki.cryptoki import CK_AES_CBC_PAD_EXTRACT_PARAMS, CK_MECHANISM, \
    CK_ULONG, CK_ULONG_PTR, CK_AES_CBC_PAD_INSERT_PARAMS, CK_BYTE, CK_BYTE_PTR
from pycryptoki.defines import CKM_AES_CBC_PAD_EXTRACT_DOMAIN_CTRL, \
    CK_CRYPTOKI_ELEMENT, CK_STORAGE_HOST, CKM_AES_CBC_PAD_INSERT_DOMAIN_CTRL


CK_AES_CBC_PAD_EXTRACT_PARAMS_TEMP = {'mechanism' : CKM_AES_CBC_PAD_EXTRACT_DOMAIN_CTRL,
                                      'ulType' : CK_CRYPTOKI_ELEMENT,
                                      'ulHandle' : 5,
                                      'ulDeleteAfterExtract' : 0,
                                      'pBuffer' : 0,
                                      'pulBufferLen' : 0,
                                      'ulStorage' : CK_STORAGE_HOST,
                                      'pedId' : 0,
                                      'pbFileName' : 0,
                                      'ctxID' : 3
                                      }

CK_AES_CBC_PAD_INSERT_PARAMS_TEMP = {'mechanism' : CKM_AES_CBC_PAD_INSERT_DOMAIN_CTRL,
                                      'ulType' : CK_CRYPTOKI_ELEMENT,
                                      'ulContainerState' : 0,
                                      'pBuffer' : 0,
                                      'pulBufferLen' : 0,
                                      'ulStorageType' : CK_STORAGE_HOST,
                                      'pulType' : 0,
                                      'pulHandle' : 0,
                                      'ctxID' : 3,
                                      'pedID' : 3,
                                      'pbFileName' : 0,
                                      'ulStorage' : CK_STORAGE_HOST,
                                      }

supported_parameters = {'CK_AES_CBC_PAD_EXTRACT_PARAMS' : CK_AES_CBC_PAD_EXTRACT_PARAMS,
                        'CK_AES_CBC_PAD_INSERT_PARAMS' : CK_AES_CBC_PAD_INSERT_PARAMS}

def get_c_struct_from_mechanism(python_dictionary, params_type_string):
    '''
    Gets a c struct from a python dictionary representing that struct
    
    @param python_dictionary: The python dictionary representing the C struct,
    see CK_AES_CBC_PAD_EXTRACT_PARAMS_TEMP for an example
    @param params_type_string: A string representing the parameter struct.
    ex. for  CK_AES_CBC_PAD_EXTRACT_PARAMS use the string 'CK_AES_CBC_PAD_EXTRACT_PARAMS'
    @return: A C struct
    '''
    params_type = supported_parameters[params_type_string]
    params = params_type()
    mech = CK_MECHANISM()
    mech.mechanism = python_dictionary['mechanism']
    mech.pParameter = cast(pointer(params), c_void_p)
    mech.usParameterLen = CK_ULONG(sizeof(params_type))
    
    #Automatically handle the simpler fields
    for entry in params_type._fields_:
        key_name = entry[0]
        key_type = entry[1]
        
        if key_type == CK_ULONG:
            setattr(params, key_name, CK_ULONG(python_dictionary[key_name]))
        elif key_type == CK_ULONG_PTR:
            setattr(params, key_name, pointer(CK_ULONG(python_dictionary[key_name])))
        else:
            continue
    
    #Explicitly handle the more complex fields
    if params_type == CK_AES_CBC_PAD_EXTRACT_PARAMS:
        if (len(python_dictionary['pBuffer']) == 0):
            params.pBuffer = None
        else:
            params.pBuffer = (CK_BYTE * len(python_dictionary['pBuffer']))()
        #params.pbFileName = 0 #TODO convert byte pointer to serializable type
        pass
    elif params_type == CK_AES_CBC_PAD_INSERT_PARAMS:
        #params.pbFileName =  TODO
        params.pBuffer = cast(create_string_buffer(python_dictionary['pBuffer']), CK_BYTE_PTR)
        params.ulBufferLen = len(python_dictionary['pBuffer'])
        pass
    else:
        raise Exception("Unsupported parameter type, pycryptoki can be extended to make it work")
    
    return mech

def get_python_dict_from_c_mechanism(c_mechanism, params_type_string):
    '''
    Gets a python dictionary from a c mechanism's struct for serialization
    and easier test case writing
    
    @param c_mechanism: The c mechanism to convert to a python dictionary
    @param params_type_string: A string representing the parameter struct.
    ex. for  CK_AES_CBC_PAD_EXTRACT_PARAMS use the string 'CK_AES_CBC_PAD_EXTRACT_PARAMS'
    
    @return: A python dictionary representing the c struct
    '''
    python_dictionary = {}
    python_dictionary['mechanism'] = c_mechanism.mechanism

    params_type = supported_parameters[params_type_string]
    params_struct = cast(c_mechanism.pParameter, POINTER(params_type)).contents
    
    #Automatically handle the simpler fields
    for entry in params_type._fields_:
        key_name = entry[0]
        key_type = entry[1]
        
        if key_type == CK_ULONG:
            python_dictionary[key_name] = getattr(params_struct, key_name)
        elif key_type == CK_ULONG_PTR:
            python_dictionary[key_name] = getattr(params_struct, key_name).contents.value
        else:
            continue
    
    #Explicitly handle the more complex fields
    if params_type == CK_AES_CBC_PAD_EXTRACT_PARAMS:
        bufferLength = params_struct.pulBufferLen.contents.value
        if params_struct.pBuffer == None:
            bufferString = None
        else:
            char_p_string = cast(params_struct.pBuffer, c_char_p).value
            if char_p_string != None:
                bufferString = char_p_string[0:bufferLength]
            else:
                bufferString = None
        python_dictionary['pBuffer'] = bufferString
        python_dictionary['pbFileName'] = 0 #TODO
    elif params_type == CK_AES_CBC_PAD_INSERT_PARAMS:
        python_dictionary['pbFileName'] = 0 #TODO
        python_dictionary['pBuffer'] = 0 #TODO
    else:
        raise Exception("Unsupported parameter type, pycryptoki can be extended to make it work")

    return python_dictionary

if __name__ == '__main__':
    pass