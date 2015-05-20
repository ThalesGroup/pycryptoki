"""
Script used to automatically generate python code bindings to the cryptoki library
and install the pycryptoki module in the system.
"""
import argparse
from pycryptoki.setup.initialize import initialize
import os
import sys

parser = argparse.ArgumentParser(description="Automatically generates code for the python to cryptoki binding and installs pycryptoki package.")
parser.add_argument('-lib', metavar='<luna_source>', default=None, help="The path to Luna's Components Sandbox.")
parser.add_argument('-dll', metavar='<dll_path>', required=True, help="The path to libCryptoki2.so.")

print "-------------------------------------------------------"
print "  Autogenerating Python Bindings to Cryptoki"
print "-------------------------------------------------------"

options = vars(parser.parse_args())
initialize(options['lib'], options['dll'])

print ""
print "-------------------------------------------------------"
print "  Installing PyCryptoki Python Module"
print "-------------------------------------------------------"
if "linux" in sys.platform:
    os.chdir(os.path.join("..", ".."))
    os.system('sudo python setup.py install')
else:
    raise Exception("Unsupported operating system, you'll have to add support for it.")
