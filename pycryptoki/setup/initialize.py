"""
Setup script that will automatically generate the cryptoki.py and defines.py files.
This will get your library from your LUNA_LIBRARY environment variable and generate these
files. These files contains the defines that are in the C code and in addition contain the
CTypes formatted structs contained in the C code.

Cryptoki.py contains the CTypes templates for the C Structs that are in the cryptoki C code.
Defines.py is a crude wrapper around a number of header files that uses a bad regular expression to
harvest the defines.

Download gccxml from CVS (note: CVS seems to be blocked on the CVS network,
 you can get this from smb://172.20.11.83/ftp/forMike)
Compile gccxml
1) Recursively run dos2unix on gccxml source tree (find . -name *.* -exec dos2unix {} \;)
2) Create a folder in the same directory as gccxml is
    in called gccxml-build (ex /home/mhughes/gccxml and /home/mhughes/gccxml-build)
3) cd gccxml-build
4) cmake ../gccxml -DCMAKE_INSTALL_PREFIX:PATH=/home/mhughes/gccxml-build
5) make
6) make install
7) Add gccxml folder to your path

Install python
Install python packages needed for ctypes
1) sudo pip install ctypes
2) sudo easy_install ctypeslib==dev

Make sure pycryptoki and pycryptoki/utils are in your PYTHONPATH. In eclipse:
1) Right click on your project
2) Select Properties
3) Select PyDev - PYTHONPATH
4) Add source folder
5) Add pycryptoki and pycryptoki/utils

Set you LUNA_LIBRARY environment variable to the path to your library. It is assumed that your
dll is in the proper path in the library
"""
from ctypeslib import h2xml, xml2py
import argparse
import os
import platform
import re
import stat
import sys

ret_list = []
header_files = [os.path.join("interfaces", "Include", "firmware", "luna2if.h")]
dll_path_var_name = 'DLL_PATH'
cryptoki_filename = os.path.join("..", "cryptoki.py")

def is_nextgen_check(library_path):
    ctlib_path = os.path.join(library_path, 'CoreLibrary', 'ctTokenLib', 'source')
    return os.path.exists(ctlib_path)

def initialize(library_path=None, dll_path=None):
    """
    Creates the cryptoki.py, defines.py and return_values.py files.
    :param library_path: The path to the MKS Components sandbox
    """
    xml_output = 'h2xmlout_tmp.xml'

    library_path = parse_library(library_path, xml_output)
    cryptoki_dll_path = dll_path
    convert_to_python_binding(cryptoki_dll_path, xml_output, cryptoki_filename)
    print "Finished!"

def change_cryptoki_dll_path(new_dll_path):
    if not os.path.exists(cryptoki_filename):
        raise Exception("Error... cryptoki.py not found.")

    print "Removing references to DLL in cryptoki.py to achieve late binding to DLL"

    #Read in the current file
    cryptoki_file = open(cryptoki_filename, "r")
    file_contents = cryptoki_file.read()
    cryptoki_file.close()

    #Create a backup
    try:
        os.remove(cryptoki_filename + ".bak")
    except:
        #Don't care this was only removing the old backup if one existed
        pass

    print "Creating backup: cryptoki.py.bak"
    os.rename(cryptoki_filename, cryptoki_filename + ".bak")

    #Find the previous path
    print re.findall("CDLL\((.*)\)", file_contents)[0]
    current_path = re.findall("CDLL\((.*)\)", file_contents)[0]

    if "win" in platform.system():
        current_path = current_path.replace("\\", '~').replace('~', '\\\\\\\\')

    new_contents = file_contents.replace(current_path, new_dll_path)

    #Remove all references to DLL to load it later
    new_contents = re.sub("_libraries\s*=\s*{}\s*", "", new_contents)
    new_contents = re.sub("_libraries\[DLL_PATH\]\s*=\s*CDLL\(DLL_PATH\)\s*", "", new_contents)

    #Windows needs to have _pack_ = 1 for every single struct, has to be declared before _fields_ is set
    struct_names = re.findall("(\S+)\._fields_\s=\s", new_contents)
    fields = re.compile("\S+\._fields_\s=\s[^\]]*]", re.MULTILINE | re.DOTALL)
    field_declaration = re.findall(fields, new_contents)

    assert len(field_declaration) == len(struct_names)
    for i in range(0, len(field_declaration)):
        add_pack_string = "if 'win' in sys.platform:\n    " + struct_names[i] + "._pack_ = 1\n" + field_declaration[i]

        new_contents = new_contents.replace(field_declaration[i], add_pack_string)

    with open(cryptoki_filename, 'w') as new_file:
        new_file.write(new_contents)


def change_cryptoki_dll_binding():

    print "Replacing ctypes cryptoki function definitions, in " + cryptoki_filename + ", with factory functions for later binding to the DLL"

    #Read in the current file
    cryptoki_file = open(cryptoki_filename, "r")
    file_contents = cryptoki_file.read()
    cryptoki_file.close()

    #Find all of the lines declaring functions on the DLL
    found = re.findall("_libraries\[DLL_PATH\]\.(\S*)", file_contents)

    #Replace all of the functions to have a late binding
    new_contents = file_contents
    for function_name in found:
        new_contents = re.sub("_libraries\[DLL_PATH\]\." + function_name + "\s", "make_late_binding_function('" + function_name + "')\n", new_contents)

    #Write the final contents out
    with open(cryptoki_filename, 'w') as new_file:
        new_file.write(new_contents)

def parse_library(library_path, xml_output):
    defines_filename = os.path.join("..", "defines.py")
    return_vals_filename = os.path.join("..", "return_values.py")

    if library_path is None:
        if not os.environ.has_key('LUNA_LIBRARY'):
            raise Exception("LUNA_LIBRARY environment variable is not set, it needs to be set to the path of your luna source code.")

        library_path = os.environ['LUNA_LIBRARY']
        print "Using LUNA_LIBRARY Environment variable as location of Luna's Library: " + library_path
    else:
        print "Using argument 1 as location of Luna's Library: " + library_path


    #If we are on a next gen branch then throw an error if the library is not compiled because
    #we will be missing an automatically generated header file
    if os.path.exists(os.path.join(library_path, 'CoreLibrary', 'ctToken_lib', 'source')):
        if os.path.exists(os.path.join(library_path, 'interfaces', 'include', 'cryptoki', 'sfnt_ext_list_members.h')):
            raise Exception("Error: sfnt_ext_list_members.h not found. You need to compile the Components library before being able to generate the Python to C Ctypes binding.")

    _parse_headers(xml_output, library_path)

    #Add all of the header files that you would like the script to parse,
    #it should be noted that the script just does simple regular expression matching
    #and is very simple and could break on previously unencountered syntaxes. It is
    #just a hack to make life easier
    token_path = os.path.join("tools", "ekmtest", "token.h")
    if os.path.exists(os.path.join(library_path, token_path)):
        header_files.append(token_path)

    #if it has this library it is next gen
    if is_nextgen_check(library_path):
        header_files.append(os.path.join("interfaces", "Include", "RSA", "pkcs11t.h"))
        header_files.append(os.path.join("CoreLibrary", "includes", "cryptoki_v2.h"))
    else:
        header_files.append(os.path.join("interfaces", "Include", "cryptoki", "RSA", "pkcs11t.h"))
        header_files.append(os.path.join("interfaces", "Include", "cryptoki", "cryptoki_v2.h"))

    _get_defines(library_path, defines_filename, header_files)
    _output_return_values(return_vals_filename, ret_list)
    return library_path

def _parse_headers(xml_output, library_path=None):
    """
    Using h2xml this function parses the cryptoki header file and generates xml
    output which describes the library
    :param xml_output:The filename to output the xml to
    :param library_path:The path to the root of the cryptoki library
    """

    print "Parsing luna source with GCC-XML to generate XML representation of C source"

    if os.path.exists(xml_output):
        os.remove(xml_output)

    #Create a file to pull everything in
    temp_include_filename = 'master_header_file.h'
    if os.path.exists(temp_include_filename):
        os.remove(temp_include_filename)

    ctlib_path = os.path.join(library_path, 'CoreLibrary', 'ctTokenLib', 'source')
    is_nextgen = is_nextgen_check(library_path)

    master_include_file = open(temp_include_filename, 'w')
    if is_nextgen:
        master_include_file.write('#include "' + os.path.join(library_path, 'CoreLibrary', 'pkcs11Utils', 'Utils.h"') + '\n')
    else:
        master_include_file.write('#include "' + os.path.join(library_path, 'CoreLibrary', 'util_vob', 'source', 'Utils.h"') + '\n')
    master_include_file.write('#include "cryptoki.h"\n')
    master_include_file.close()

    args = ['h2xml.py', os.path.join(os.getcwd(), temp_include_filename), '-o', xml_output,
            '-I', os.path.join(library_path, 'interfaces', 'Include'),
            '-I', os.path.join(library_path, 'interfaces', 'Include', 'cryptoki'),
            '-I', os.path.join(library_path, 'CoreLibrary', 'util_vob', 'source')]

    if is_nextgen:
        args.append('-I')
        args.append(ctlib_path)
        args.append('-I')
        args.append(os.path.join(library_path, 'CoreLibrary', 'util_vob', 'Include'))

    if "linux" in sys.platform:
        print "Detected linux OS"
        args.append('-D')
        args.append('OS_LINUX')
    else:
        #Your operating system probably just needs to be added, might not need any special parameters
        raise Exception("Error: Could not generate python to c ctypes library. Unsupported Operating System, a build on linux should work everywhere so just use it.")

    if which("gccxml") is None and which("gccxml.exe") is None:
        raise Exception("No gccxml executable found in path.")

    h2xml.compile_to_xml(args)

    if os.path.exists(temp_include_filename):
        os.remove(temp_include_filename)

def convert_to_python_binding(cryptoki_dll_path, temp_file, output_filename):
    """
    Using xml2py.py in ctypeslib this function generates the python file based
    upon the xml output of h2xml. This python file is the binding between python
    and C.
    :param cryptoki_dll_path: The path to libCryptoki.so
    :param temp_file: The xml output of h2xml.py
    :param output_filename: The filename to output the binding to
    """
    print "Parsing GCC-XML output to generate python code for binding to C, writing to " + output_filename

    if os.path.exists(output_filename):
        os.chmod(output_filename, stat.S_IWRITE)
        os.remove(output_filename)

    args = ['xml2py.py', temp_file, '-l', cryptoki_dll_path, '-o', output_filename]
    xml2py.main(args)

    change_cryptoki_dll_path(dll_path_var_name)
    initial_function = '\nfrom pycryptoki.cryptoki_helpers import make_late_binding_function\nimport sys\n'

    change_cryptoki_dll_binding()

    _prepend_to_file(output_filename, initial_function)

    comment = "This file contains all of the ctypes definitions for the cryptoki library.\n"
    comment += "The ctypes definitions outline the structures for the cryptoki C API.\n"
    _prepend_auto_file_warning(output_filename, comment)

def _store_defines(head_filename, output_filename):
    """
    Converts all of the simple defines (defines to numbers) in a c header file to a
    variable declaration in python and appends these declarations to an output file.

    This is a really hackish way of getting the defines which actually hard codes out
    defines that are formatted wrong and cause errors. Done this way to get it done real
    quick and imports 99% of what is needed.

    :param head_filename: The filename of the header to get the defines from
    :param output_filename: The .py file to append the python style defines in
    """
    print "Getting defines from: " + str(head_filename)

    #Read in file
    head_file = open(head_filename, "r")
    text = head_file.read()

    #Find all the simple defines (defines to numbers)
    regex_list = re.findall(r"#define[ \t\r\f\v]+([A-Z]+[A-Za-z_0-9]+[ \t\r\f\v]+[^~\n]*)[\n]", text)
    #regex_list = re.findall(r"#define[ \t\r\f\v]([\S]+[ \t\r\f\v]*[0-9]+[0-9A-Za-z]*)[\n]", text)

    #Put an equals sign in them so they are properly formatted and append them to the file
    out_file = open(output_filename, "a")
    out_file.write("'''" + head_filename + "'''\n")

    for entry in regex_list:
        if not (entry.find("CK_POINTER") > -1 or entry.find("CK_PTR") > -1
                or entry.find("CK_ENTRY") > -1 or entry.find("C_VERSION") > -1
                or entry.find("LUNA_PARTITION_HDR_HMAC_SIZE") > -1
                or entry.find("FW_VERSION_CONF_ROLES") > -1): #XXX This is to account for function calls, should be accounted for in the regex above
            entry = entry.replace('\t', ' ') #clean up tabs
            entry = entry.replace(' ', '=', 1)
            entry = entry.replace('//', '#')
            entry = entry.replace('/*', '#')
            out_file.write(entry + "\n")

            dict_entry = entry.split('=')
            if 'CKR' in dict_entry[0][0:3]:
                ret_list.append(dict_entry[0])

    #Cleanup
    out_file.close()
    head_file.close()

def _output_return_values(output_filename, ret_list):
    """
    Creates a file which contains a dictionary for looking up
    the String values of the various defines in cryptoki.

    :param output_filename: The filename to output the dictionary to
    :param ret_list: The list of return values generated when getting the
    defines
    """

    print "Creating dictionary of return value strings by scraping Luna's source, writing to: " + output_filename

    if os.path.exists(output_filename):
        os.remove(output_filename)

    ret_vals_file = open(output_filename, "a")
    ret_vals_file.write("from defines import *\n\n")

    ret_vals_file.write("ret_vals_dictionary = { \n")
    for entry in ret_list:
        ret_vals_file.write("\t" + entry + " : '" + entry + "'")
        if not ret_list[len(ret_list) - 1] == entry:
            ret_vals_file.write(',')
        ret_vals_file.write('\n')
    ret_vals_file.write("}")
    ret_vals_file.close()

    comment = "This file contains a dictionary lookup for the readable string values\n"
    comment += "of defines whose variable name starts with CKR_. This convention means they are\n"
    comment += "a return value for the cryptoki C API.\n\n"
    _prepend_auto_file_warning(output_filename, comment)

def _get_defines(path_to_library, out_filename, header_files):
    """
    Gets all of the defines in a set of c files specified in the header_files variable as a list
    of strings. That list is relative to the path_to_library variable. Everything is stored in
    out_filename in python format.
    :param path_to_library: The path to the MKS Components sandbox
    :param out_filename: The .py filename to save the python style defines to
    :param header_files: The header files to harvest the defines from
    """

    print "Scraping Luna's source to convert C defines to python, writing to: " + str(out_filename)
    if os.path.exists(out_filename):
        os.remove(out_filename)

    for header_file in header_files:
        head_filename = os.path.join(path_to_library, header_file)
        _store_defines(head_filename=head_filename, output_filename=out_filename)

    comment = "This file contains defines which have been automatically scraped from the\n"
    comment += "cryptoki API header files. The defines are stored as variables in python.\n"
    comment += "If you add any new defines you can rerun initialize.py to regenerate this file.\n"
    comment += "If you need to scrape another header file add the desired file to the header_files\n"
    comment += "array in initialize.py and rerun initialize.py.\n"
    _prepend_auto_file_warning(out_filename, comment)

def _prepend_auto_file_warning(filename, comment):
    beginning_comment = "'''\n"
    beginning_comment += "THIS FILE WAS CREATED AUTOMATICALLY AND CONTAINS AUTOMATICALLY GENERATED CODE\n"
    beginning_comment += "This file should NOT be checked into MKS or modified in any way, this file was\n"
    beginning_comment += "created by setup/initialize.py. Any changes to this file will be wiped out when\n"
    beginning_comment += "it is regenerated.\n\n"
    beginning_comment = beginning_comment + comment
    beginning_comment += "'''\n\n"

    _prepend_to_file(filename, beginning_comment)

def _prepend_to_file(filename, text_to_prepend):
    with file(filename, 'r') as original: data = original.read()
    with file(filename, 'w') as modified: modified.write(text_to_prepend + data)

def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automatically generates code for the python to cryptoki binding.")
    parser.add_argument('-lib', metavar='<luna_source>', default=None, help="The path to Luna's Components Sandbox.")
    parser.add_argument('-dll', metavar='<dll_path>', required=True, help="The path to libCryptoki2.so.")
    args = parser.parse_args()
    options = vars(args)

    initialize(options['lib'], options['dll'])

