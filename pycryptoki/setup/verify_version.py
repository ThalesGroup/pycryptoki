"""
This function just goes through and imports every file and reports back which files have errors
in them for the purpose of compatibility between python versions.

"""
import os, os.path

def verify_import():
    """ """
    failed_files = ""
    for root, dirs, files in os.walk("../."):
        for f in files:
            fullpath = os.path.join(root, f)
            if fullpath.endswith("py"):
                split_path = fullpath.split('/')
                folder_names = ""
                verify = True
                if len(split_path) > 3:

                    for folder in split_path[2:len(split_path) - 1]:
                        if folder == "setup":
                            verify = False
                        folder_names = folder_names + str(folder) + "."
                if verify:
                    print fullpath
                    cmd = "from pycryptoki." + folder_names + str(f).split(".")[0] + " import *"
                    print "\t" + cmd
                    try:
                        exec cmd
                    except Exception as e:
                        print "\tERROR:"
                        print "\t" + str(e)
                        failed_files = failed_files + str(f) + "\n\t"
    print "\n------SUMMARY------"
    print "Failed:\n\t" + failed_files
if __name__ == '__main__':
    verify_import()
