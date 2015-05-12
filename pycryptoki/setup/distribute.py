import argparse
import os
import sys
import initialize

print "PyCryptoki Source Code Distribution"
print "Use -h for argument information."

parser = argparse.ArgumentParser(description="Automatically generates code for the python to cryptoki binding and creates a source tarball in pycryptoki/dist..")
parser.add_argument('-lib', metavar='<luna_source>', default=None, help="The path to Luna's Components Sandbox.")
parser.add_argument('-dll', metavar='<dll_path>', required=True, help="The path to the libCryptoki2.so which will be opened and parsed, this must be the dll corresponding to Luna's components sandbox.")

print "-------------------------------------------------------"
print "  Autogenerating Python Bindings to Cryptoki"
print "-------------------------------------------------------"

args = parser.parse_args()
options = vars(args)

#Create all of the necessary automatically generated source
xml_output = 'h2xmlout_tmp.xml'

if not (options['dll'] == None):
    dll_path = options['dll']
else:
    if "linux" in sys.platform:
        dll_path = '/usr/lib/libCryptoki2.so'
    else:
        raise Exception("Platform not yet supported.")

initialize.initialize(options['lib'], dll_path)

print "-------------------------------------------------------"
print "  Packaging Source Distribution"
print "-------------------------------------------------------"
os.chdir("../../")
os.system('python setup.py sdist')