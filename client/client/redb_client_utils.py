"""
Utilities for all the other modules.
"""

# standard library imports
import os

# standard library imports
import ConfigParser
import string

# related third party imports
import idc
import idautils
import idaapi

# Constants
PLUGIN_DIR_PATH = os.path.dirname(__file__)
CONFIG_FILE_PATH = os.path.join(PLUGIN_DIR_PATH, 'IdaProject.INI')


#==============================================================================
# Plugin configuration
#==============================================================================
class PluginConfig:
    """
    Configuration management.
    """
    def __init__(self):
        self._path = CONFIG_FILE_PATH

    def get_current_from_ini_file(self):
        parser = ConfigParser.SafeConfigParser()
        parser.read(self._path)

        self.host = parser.get('REDB', 'host')
        self.max_descriptions_returned = \
            int(parser.get('REDB', 'max_descriptions_returned'))

    def change_config(self):
        try:
            self.get_current_from_ini_file()
        except:
            self.host = "<ip>:<port>"
            self.max_descriptions_returned = ">0"

        os.remove(self._path)
        cfgfile = open(self._path, 'w')
        parser = ConfigParser.SafeConfigParser()
        parser.add_section('REDB')

        host = idc.AskStr(self.host,
                          "REDB: Please enter the server's ip and port:")
        if host is not None:
            parser.set('REDB', 'host', host)

        max_descriptions_returned = \
                int(idc.AskStr(str(self.max_descriptions_returned),
                               ("REDB: Please enter the maximum number " + \
                                "of descriptions that you want to be " + \
                                "returned from the server:")))
        if max_descriptions_returned is not None:
            parser.set('REDB', 'max_descriptions_returned',
                       str(max_descriptions_returned))

        parser.write(cfgfile)
        cfgfile.close()


def _parse_config_file():
    """
    Checking user configurations exist upon plugin initialization.
    """
    parse_config = PluginConfig()
    try:
        parse_config.get_current_from_ini_file()
    except:
        parse_config.change_config()

    return parse_config


#==============================================================================
# Comments and function name and Tag management
#==============================================================================
class Extract:
    """
    Extraction of current comments and getting the function name.
    """
    def __init__(self, first_addr):
        self._first_addr = first_addr
        self._func_items = list(idautils.FuncItems(self._first_addr))

    def extract_all(self):
        """
        Extraction of all comments and function name.
        """
        dic = {}
        # Function name
        dic["FunctionName"] = self._extract_func_name()

        # Comments
        dic["RegularComments"] = self._extract_cmnts(0)
        dic["RepeatableComments"] = self._extract_cmnts(1)
        dic["FunctionCommentRegular"] = self._extract_func_cmnt(0)
        dic["FunctionCommentRepeatable"] = self._extract_func_cmnt(1)
        return dic

    def _extract_func_name(self):
        function_name = idc.GetFunctionName(self._first_addr)
        return function_name

    # repeatable: 0 for regular, 1 for repeatable
    def _extract_cmnts(self, repeatable):
        commdict = {}
        for func_item in self._func_items:
            i = int(func_item) - int(self._first_addr)
            comm = idc.GetCommentEx(func_item, repeatable)
            if  (comm != None):
                    commdict[i] = comm
        return commdict

    # repeatable: 0 for regular, 1 for repeatable
    def _extract_func_cmnt(self, repeatable):
        function_cmt = idc.GetFunctionCmt(self._first_addr, repeatable)
        return function_cmt


class Embed:
    """
    Embedding new comments into a function and changing the functions' name.
    """
    def __init__(self, first_addr):
        self._first_addr = first_addr

    def embed_all(self, func_name_and_cmnts):
        """
        Removing all current comments from a function, embedding new ones
        instead and changing the functions' name.
        """
        self._func_name = func_name_and_cmnts["FunctionName"]
        self._reg_cmnts = func_name_and_cmnts["RegularComments"]
        self._rep_cmnts = func_name_and_cmnts["RepeatableComments"]
        self._func_cmnt_reg = func_name_and_cmnts["FunctionCommentRegular"]
        self._func_cmnt_rep = func_name_and_cmnts["FunctionCommentRepeatable"]

        RemoveFuncCmnts(self._first_addr)

        # Function name
        self._embed_func_name(self._func_name)

        # Comments
        self._embed_cmnts(self._reg_cmnts, 0)
        self._embed_cmnts(self._rep_cmnts, 1)

        # Function Comments
        self._embed_func_cmnt(self._func_cmnt_reg, 0)
        self._embed_func_cmnt(self._func_cmnt_rep, 1)

    def merge_all(self, func_name_and_cmnts):
        """
        Embedding comments in addition to current comments and changing the
        functions' name.
        """
        self._func_name = func_name_and_cmnts["FunctionName"]
        self._reg_cmnts = func_name_and_cmnts["RegularComments"]
        self._rep_cmnts = func_name_and_cmnts["RepeatableComments"]
        self._func_cmnt_reg = func_name_and_cmnts["FunctionCommentRegular"]
        self._func_cmnt_rep = func_name_and_cmnts["FunctionCommentRepeatable"]

        # Function name
        self._embed_func_name(self._func_name)

        # Comments
        self._merge_cmnts(self._reg_cmnts, 0)
        self._merge_cmnts(self._rep_cmnts, 1)

        # Function Comments
        current_comment = Extract(self._first_addr)._extract_func_cmnt(0)
        final_comment = (current_comment + "; REDB: " + self._func_cmnt_reg)
        self._embed_func_cmnt(final_comment, 0)

        current_comment = Extract(self._first_addr)._extract_func_cmnt(1)
        final_comment = (current_comment + "; REDB: " + self._func_cmnt_rep)
        self._embed_func_cmnt(final_comment, 1)

    def embed_short(self, func_name_and_cmnts):
        """
        Embedding a short version of the comments as a "function comment".
        """
        self._func_name = func_name_and_cmnts["FunctionName"]
        self._reg_cmnts = func_name_and_cmnts["RegularComments"]
        self._rep_cmnts = func_name_and_cmnts["RepeatableComments"]
        self._func_cmnt_reg = func_name_and_cmnts["FunctionCommentRegular"]
        self._func_cmnt_rep = func_name_and_cmnts["FunctionCommentRepeatable"]

        RemoveFuncCmnts(self._first_addr)

        # Function name
        self._embed_func_name(self._func_name)

        # Comments
        short_comment = ("RegularComments: " + self._reg_cmnts +
                         ", RepeatableComments: " + self._rep_cmnts)

        self._embed_func_cmnt(short_comment, 0)

    def _embed_func_name(self, name):
        idaapi.set_name(self._first_addr, name, idaapi.SN_NOWARN)

    # repeatable: 0 for regular, 1 for repeatable
    def _embed_cmnts(self, comments, repeatable):
        for ea_rel in comments:
            comment = comments[ea_rel]
            ea = int(ea_rel) + self._first_addr
            self._embed_comment(ea, comment, repeatable)

    # repeatable: 0 for regular, 1 for repeatable
    def _merge_cmnts(self, comments, repeatable):
        for ea_rel in comments:
            ea = int(ea_rel) + self._first_addr
            comment = comments[ea_rel]
            current_comment = idc.GetCommentEx(ea, repeatable)

            if current_comment is None:
                current_comment = ""

            final_comment = current_comment + "; REDB: " + comment
            self._embed_comment(ea, final_comment, repeatable)
            idaapi.refresh_idaview_anyway()

    # repeatable: 0 for regular, 1 for repeatable
    def _embed_comment(self, ea, comment, repeatable):
        if repeatable == 0:
            idc.MakeComm(ea, comment)
        else:
            idc.MakeRptCmt(ea, comment)

    def _embed_func_cmnt(self, comment, repeatable):
        idc.SetFunctionCmt(self._first_addr, comment, repeatable)


class RemoveFuncCmnts:
    """
    Removing all current comments.
    """
    def __init__(self, first_addr):
        for func_item in list(idautils.FuncItems(first_addr)):
            idc.MakeComm(func_item, "")
            idc.MakeRptCmt(func_item, "")
        idc.SetFunctionCmt(first_addr, "", 0)
        idc.SetFunctionCmt(first_addr, "", 1)


class Tag:
    """
    Adding a speciel tag in the "function comment".
    """
    def __init__(self, first_addr):
        self._first_addr = first_addr

    def add_tag(self, user=True, index=None, outof=None, mg=None):
        self.remove_tag()

        tag = "[REDB: handled"
        if user:
            tag += ", user's description"
        else:
            tag += (", public description" +
                    " (" + str(index) + "/" + str(outof) + ")" +
                    ", Matching Grade: " + str(mg))
        tag += "]"

        current_comment = Extract(self._first_addr)._extract_func_cmnt(0)
        final_comment = tag
        if current_comment is not None:
            final_comment += current_comment
        Embed(self._first_addr)._embed_func_cmnt(final_comment, 0)
        idaapi.refresh_idaview_anyway()

    # (best effort)
    def remove_tag(self):
        current_comment = Extract(self._first_addr)._extract_func_cmnt(0)
        if string.find(current_comment, "[REDB: handled") == 0:
            last_index = string.find(current_comment, "]")
            final_comment = current_comment[last_index + 1:]
            Embed(self._first_addr)._embed_func_cmnt(final_comment, 0)
            idaapi.refresh_idaview_anyway()


#==============================================================================
# Changing from unicode for compatibility.
#==============================================================================
def _decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for key, value in data.iteritems():
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv


#==============================================================================
# FuncAttributes Utilities
#==============================================================================
#-----------------------------------------------------------------------------
# Operands
#-----------------------------------------------------------------------------
def collect_operands_data(func_item):
    """
    Given an instruction address, returns operands as pairs of type and
    value.
    """
    operands_list = []
    for i in range(6):
        if idc.GetOpType(func_item, i) != 0:
            pair = (idc.GetOpType(func_item, i),
                    idc.GetOperandValue(func_item, i))
            operands_list.append(pair)
    return operands_list


#-----------------------------------------------------------------------------
# Imports and their functions.
#-----------------------------------------------------------------------------
class ImportsAndFunctions:
    def collect_imports_data(self):
        """
        Modules and their functions.
        """
        self._imported_modules = []
        nimps = idaapi.get_import_module_qty()  # number of imports

        for i in xrange(0, nimps):
            name = idaapi.get_import_module_name(i)
            if not name:
                print ("REDB: Failed to get_current_from_ini_file import" +
                       "module name for #%d" % i)
                continue
            module = _ImportModule(name)
            self._imported_modules.append(module)
            idaapi.enum_import_names(i, self._add_single_imported_function)
        return self._imported_modules

    def _add_single_imported_function(self, ea, name, ordinal):
        if not name:
            imported_function = _SingleImportedFunction(ea, ordinal)
        else:
            imported_function = _SingleImportedFunction(ea, ordinal, name)

        self._imported_modules[-1].improted_functions.append(imported_function)

        return True


class _SingleImportedFunction():
    """
    Represents an imported function.
    """
    def __init__(self, addr, ordinal, name='NoName'):
        self.ordinal = ordinal
        self.name = name
        self.addr = addr


class _ImportModule():
    """
    Represents an imported module.
    """
    def __init__(self, name):
        self.name = name
        self.improted_functions = []
        self._addresses = None

    def get_addresses(self):
        """
        Returns addresses of functions imported from this module.
        """
        if self._addresses == None:
            self._addresses = [imported_function.addr for imported_function in
                               self.improted_functions]
        return self._addresses


#-----------------------------------------------------------------------------
# Data
#-----------------------------------------------------------------------------
def instruction_data(func_item):
    """
    Returns an integer representing the instruction.
    """
    func_item_size = idautils.DecodeInstruction(func_item).size
    cmd_data = 0
    for i in idaapi.get_many_bytes(func_item, func_item_size):
        cmd_data = (cmd_data << 8) + ord(i)
    return cmd_data
