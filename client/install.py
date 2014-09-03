"""
Plugin installation. 

In cmd, as Administrator, enter:
"<python.exe full path> <client folder full path>\install.py"

A propmt will be given:
"IDA Dir Path?"

Enter the location in which IDA is at your computer, for example:
"C:\Program Files (x86)\IDA 6.3"
"""

# standard library imports
import os
import shutil
import sys

# Should be exactly the same as CALLBACK_FUNCTIONS in install.py.
CALLBACK_FUNCTIONS = [("Information", "Ctrl-Shift-I", "_information"),
                      # interaction with the server
                      ("Submit_Current", "Ctrl-Shift-S", "_submit_one"),
                      ("Request_Current", "Ctrl-Shift-R", "_request_one"),
                      ("Handle_Current", "Ctrl-Shift-H", "_handle_one"),
                      # description browsing
                      ("Next_Public_Description", "Ctrl-Shift-.", "_next"),
                      ("Previous_Public_Description", "Ctrl-Shift-,",
                       "_previous"),
                      ("Restore_User's_Description", "Ctrl-Shift-U",
                       "_restore_user"),
                      ("Merge_Public_Into_User's", "Ctrl-Shift-M", "_merge"),
                      # all-handled callbacks
                      ("Submit_All_Handled", "Ctrl-Shift-Q",
                       "_submit_all_handled"),
                      ("Request_All_Handled", "Ctrl-Shift-W",
                       "_request_all_handled"),
                      # settings
                      ("Settings", "Ctrl-Shift-O", "_settings"),
                      # Debug - add these two tuples to CALLBACK_FUNCTIONS to
                      # enable mass submitting and requesting.
                      # ("Submit_All", "Ctrl-Shift-Z", "_submit_all"),
                      # ("Request_All", "Ctrl-Shift-X", "_request_all"),
                     ]

def is_admin(path):
    hostsFileBackup = file(path).read()
    try:
        filehandle = open(path, 'w')
        filehandle.write(hostsFileBackup)
        filehandle.close()
        return True
    except IOError:
        return False

def copy_tree(src, dst):
    if not os.path.exists(dst):
        os.makedirs(dst)
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            copy_tree(s, d)
        else:
            try:
                shutil.copy2(s, d)
                print 'File ' + d + ' copied.'
            except IOError:
                print 'File "' + d + '" already exists'

def main():
    ida_dir_path = raw_input("IDA Dir Path?")

    if not os.path.exists(ida_dir_path):
        print "Directory does not exist"
        return "Fail"

    ida_plugins_cfg_file_path = os.path.join(ida_dir_path, "plugins",
                                             "plugins.cfg")

    if not os.path.exists(ida_plugins_cfg_file_path):
        print "plugins.cfg does not exist"
        return "Fail"

    if not is_admin(ida_plugins_cfg_file_path):
        print "Not an administrator."
        print ("In cmd, as administrator," +
               "give python.exe this script as an argument.")
        return "Fail"

    install_file_dir_path = os.path.dirname(sys.argv[0])#os.getcwd()

    simplejson_path = os.path.join(install_file_dir_path, "simplejson")
    simplejson_dest = os.path.join(ida_dir_path, "lib", "simplejson")
    copy_tree(simplejson_path, simplejson_dest)

    plugin_path = os.path.join(install_file_dir_path, "Client", "redb_main.py")

    filehandle = open(ida_plugins_cfg_file_path, 'a')

    for i in range(len(CALLBACK_FUNCTIONS)):
        function = CALLBACK_FUNCTIONS[i]
        line_to_be_added = ("\n" +
                            function[0] + # callback name
                            "\t" +
                            plugin_path +
                            "\t" +
                            function[1] + # Shortcut combo
                            "\t" +
                            str(i) +
                            "\tSILENT")
        filehandle.write(line_to_be_added)

    line_to_be_added = "\n"
    filehandle.write(line_to_be_added)
    filehandle.close()

    return "Success"

if __name__ == "__main__":
    print main()
    raw_input("Goodbye")
