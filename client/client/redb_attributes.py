"""
This module contains holds the FuncAttributes class. An instance of this
class is created for each handled function.
"""

# standard library imports
import hashlib
import gc

# related third party imports
import idautils
import idc

# local application/library specific imports
import idaapi
import redb_client_utils

# Constants
ATTRS_COLLECTED_ONCE = {"_first_addr_attr": "_FirstAddr",
                        "_exe_name_attr": "_ExeName",
                        "_exe_md5_attr": "_ExeMd5",
                        "_ins_num_attr": "_InsNum",
                        "_graph_rep_attr": "_GraphRep"}
ATTR_COLLECTED_ITER = {"_func_md5_attr": "_FuncMd5",
                       "_ins_data_list_attr": "_InsDataList",
                       "_ins_type_list_attr": "_InsTypeList",
                       "_ins_type_dict_attr": "_InsTypeDict",
                       "_str_list_attr": "_StrList",
                       "_str_dict_attr": "_StrDict",
                       "_lib_calls_list_attr": "_LibCallsList",
                       "_lib_calls_dict_attr": "_LibCallsDict",
                       "_imm_list_attr": "_ImmList",
                       "_imm_dict_attr": "_ImmediateDict"}

PRIMARY_ATTRS = ["_first_addr_attr",
                 "_exe_name_attr",
                 "_exe_md5_attr",
                 "_func_md5_attr",
                 "_ins_num_attr"]
FILTER_ATTRS = ["_ins_type_dict_attr",
                "_str_dict_attr",
                "_lib_calls_dict_attr",
                "_imm_dict_attr"]
MG_ATTRS = ["_ins_data_list_attr",
            "_ins_type_list_attr",
            "_str_list_attr",
            "_lib_calls_list_attr",
            "_imm_list_attr",
            "_graph_rep_attr"]


#==============================================================================
# FuncAttributes Class
#==============================================================================
class FuncAttributes:
    """
    This class gathers all of the functions' attributes. It holds an instance
    of each attribute class. First it initializes the class and then calls the
    collect and extract functions in turn.
    some of the collect functions are called once, others are called for each
    instruction.

    first_addr -- the functions' first address
    func_items -- the functions' list on instruction addresses
    string_addresses -- addresses of executables' strings
    imported_modules - list of imported modules
    """
    def __init__(self, first_addr, func_items, string_addresses,
                 imported_modules):

        # Data required for Attributes extraction
        self._first_addr = first_addr
        self._func_items = func_items
        self._string_addresses = string_addresses
        self._imported_modules = imported_modules

        # At initalization, self._results is filled with all attributes
        # data.
        self._results = {}

        self._initialize_attributes()
        self._collect_all()
        self._extract_all()
        self._del_all_attr()

        gc.collect()

    def _initialize_attributes(self):
        """
        Initializes attribute classes for attributes in ATTRS_COLLECTED_ONCE
        and ATTR_COLLECTED_ITER.
        """
        init_args = {"func_items": self._func_items,
                     "string_addresses": self._string_addresses,
                     "imported_modules": self._imported_modules}

        for one_attribute in ATTRS_COLLECTED_ONCE:
            one_class_name = ATTRS_COLLECTED_ONCE[one_attribute]
            one_class = globals()[one_class_name]
            setattr(self, one_attribute, one_class(init_args))

        for one_attribute in ATTR_COLLECTED_ITER:
            one_class_name = ATTR_COLLECTED_ITER[one_attribute]
            one_class = globals()[one_class_name]
            setattr(self, one_attribute, one_class(init_args))

    def _collect_all(self):
        """
        Calls the attributes' Collect functions, once for attributes in
        ATTRS_COLLECTED_ONCE and for each instruction in for attributes in
        ATTR_COLLECTED_ITER.
        """
        collect_args = {"first_addr": self._first_addr}
        # Attributes that don't need to iterate instructions.
        for one_attribute in ATTRS_COLLECTED_ONCE.keys():
            getattr(self, one_attribute)._collect_data(collect_args)

        # Attributes which need to iterate instructions. Iterate over
        # instructions, while each attribute extracts data from it.
        for i in range(len(self._func_items)):

            func_item = self._func_items[i]
            ins = idautils.DecodeInstruction(func_item)
            ins_type = ins.itype
            ins_operands = redb_client_utils.collect_operands_data(func_item)

            collect_args["func_item"] = func_item
            collect_args["ins_type"] = ins_type
            collect_args["ins_operands"] = ins_operands

            for one_attribute in ATTR_COLLECTED_ITER.keys():
                getattr(self, one_attribute)._collect_data(collect_args)

    def _extract_all(self):
        """
        Calls the attributes' Extract functions, keeps the results.
        """
        for one_attribute in ATTR_COLLECTED_ITER.keys():
            self._results[one_attribute] = getattr(self,
                                                   one_attribute)._extract()

        for one_attribute in ATTRS_COLLECTED_ONCE.keys():
            self._results[one_attribute] = getattr(self,
                                                   one_attribute)._extract()

    def _del_all_attr(self):
        """
        After saving the results, delete attribute classes.
        """
        for one_attribute in ATTR_COLLECTED_ITER.keys():
            attr = getattr(self, one_attribute)
            del attr

        for one_attribute in ATTRS_COLLECTED_ONCE.keys():
            attr = getattr(self, one_attribute)
            del attr

    def get_filter_attrs(self):
        """
        Returns results of attributes in FILTER_ATTRS.
        """
        attr_dict = {}
        for attribute_name in FILTER_ATTRS:
            attr_dict[attribute_name] = self._results[attribute_name]
        return attr_dict

    def get_primary_attrs(self):
        """
        Returns results of attributes in PRIMARY_ATTRS.
        """
        attr_dict = {}
        for attribute_name in PRIMARY_ATTRS:
            attr_dict[attribute_name] = self._results[attribute_name]
        return attr_dict

    def get_mg_attrs(self):
        """
        Returns results of attributes in MG_ATTRS.
        """
        attr_dict = {}
        for attribute_name in MG_ATTRS:
            attr_dict[attribute_name] = self._results[attribute_name]
        return attr_dict


#==============================================================================
# Attribute Classes
#==============================================================================
class Attribute:
    """ Represents a single attribute. """
    def __init__(self, init_args):
        """ Initializes attribute class with init_args """
        pass

    def _collect_data(self, collect_args):
        """ Collects data necessary for attribute. """
        pass

    def _extract(self):
        """ Return collected data. """
        pass


#==============================================================================
# General attributes
#==============================================================================
class _FirstAddr(Attribute):
    """
    The function's first address.
    """
    def __init__(self, init_args):  # @UnusedVariable
        self._addr = None

    def _collect_data(self, collect_args):
        self._addr = collect_args["first_addr"]

    def _extract(self):
        return self._addr


class _ExeName(Attribute):
    """
    The executable's name.
    """
    def __init__(self, init_args):  # @UnusedVariable
        self._exe_name = None

    def _collect_data(self, collect_args):  # @UnusedVariable
        try:
            self._exe_name = idc.GetInputFile()
        except:  # exe does not exist.
            self._exe_name = ""

    def _extract(self):
        return self._exe_name


class _ExeMd5(Attribute):
    """
    The executable's md5 signature.
    """
    def __init__(self, init_args):  # @UnusedVariable
        self._exe_md5 = None

    def _collect_data(self, collect_args):  # @UnusedVariable
        try:
            exe_file_path = idc.GetInputFilePath()
            md5_obj = hashlib.md5(open(exe_file_path).read())
            self._exe_md5 = md5_obj.hexdigest()
        except:  # exe does not exist.
            self._exe_md5 = ""

    def _extract(self):
        return self._exe_md5


#==============================================================================
# Instruction-related attributes
#==============================================================================
class _InsNum(Attribute):
    """
    The number of instructions in the function.
    """
    def __init__(self, init_args):
        self._ins_num = None
        self._func_items = init_args["func_items"]

    def _collect_data(self, collect_args):  # @UnusedVariable
        self._ins_num = len(self._func_items)

    def _extract(self):
        del self._func_items
        return self._ins_num


class _FuncMd5(Attribute):
    """
    The whole function's MD5 hash.
    """
    def __init__(self, init_args):  # @UnusedVariable
        self._hash_string = ""
        self._to_be_hashed = hashlib.md5()

    def _collect_data(self, collect_args):
        self._to_be_hashed.\
            update(str(redb_client_utils.\
                            instruction_data(collect_args["func_item"])))

    def _extract(self):
        self._hash_string = str(self._to_be_hashed.hexdigest())
        del self._to_be_hashed
        return self._hash_string


class _InsDataList (Attribute):
    """
    A list of integers representing the instructions themselves.
    """
    def __init__(self, init_args):  # @UnusedVariable
        self._hash_list = []

    def _collect_data(self, collect_args):
        self._hash_list.\
            append(redb_client_utils.\
                        instruction_data(collect_args["func_item"]))

    def _extract(self):
        return self._hash_list


class _InsTypeList (Attribute):
    """
    A list of instruction types.
    """
    def __init__(self, init_args):  # @UnusedVariable
        self._itype_list = []

    def _collect_data(self, collect_args):
        self._itype_list.append(collect_args["ins_type"])

    def _extract(self):
        return self._itype_list


class _InsTypeDict (Attribute):
    """
    A dictionary of (itype, count) pairs.
    """
    def __init__(self, init_args):  # @UnusedVariable
        self._type_counters = {}

    def _collect_data(self, collect_args):
        ins_type = collect_args["ins_type"]
        if not(ins_type in self._type_counters):
            self._type_counters[ins_type] = 0
        self._type_counters[ins_type] += 1

    def _extract(self):
        return self._type_counters


#==============================================================================
# Strings-related attributes
#==============================================================================
class _StrList(Attribute):
    """
    A list of the strings which appear in the function.
    """
    def __init__(self, init_args):
        self._list_of_strings = []
        self._string_addresses = init_args["string_addresses"]

    def _collect_data(self, collect_args):
        for data_ref in list(idautils.DataRefsFrom(collect_args["func_item"])):
            if data_ref in self._string_addresses:
                str_type = idc.GetStringType(data_ref)
                if idc.GetStringType(data_ref) is not None:
                    string = idc.GetString(data_ref, -1, str_type)
                self._list_of_strings.append(string)

    def _extract(self):
        del self._string_addresses
        return self._list_of_strings


class _StrDict(Attribute):
    """
    A dictionary of (string, count) pairs.
    """
    def __init__(self, init_args):
        self._string_counters = {}
        self._string_addresses = init_args["string_addresses"]

    def _collect_data(self, collect_args):
        for data_ref in list(idautils.DataRefsFrom(collect_args["func_item"])):
            if data_ref in self._string_addresses:
                str_type = idc.GetStringType(data_ref)
                if idc.GetStringType(data_ref) is not None:
                    string = idc.GetString(data_ref, -1, str_type)
                    if not(string in self._string_counters):
                        self._string_counters[string] = 0
                    self._string_counters[string] += 1

    def _extract(self):
        del self._string_addresses
        return self._string_counters


#==============================================================================
# Library calls-related attributes
#==============================================================================
class _LibCallsList(Attribute):
    """
    A list containing the lib call names which occur in a function.
    """
    def __init__(self, init_args):
        self._imported_modules = init_args["imported_modules"]
        self._lib_calls_list = []

    def _collect_data(self, collect_args):
        func_item = collect_args["func_item"]
        code_refs_from_list = \
            list(idautils.CodeRefsFrom(func_item, False))

        for code_ref in code_refs_from_list:
            is_loaded_dynamically = False
            is_library_function = False
            called_function_name = ""

            if (idc.GetFunctionFlags(code_ref) == -1):
                # Find code_ref in functions that are imported dynamically
                for imported_module in self._imported_modules:
                    if code_ref in imported_module.get_addresses():
                        is_loaded_dynamically = True
                        break
            else:
                # get_func(code_ref) != get_func(func_item) ->
                # do not include coderefs to self.
                if ((idc.GetFunctionFlags(code_ref) & idaapi.FUNC_LIB) != 0 and
                    idaapi.get_func(code_ref) != idaapi.get_func(func_item)):
                    # code_ref is imported statically
                    is_library_function = True

            # Data is gathered only for library functions or Imports.
            if (is_library_function or is_loaded_dynamically):
                # get name
                called_function_name = idc.NameEx(func_item, code_ref)

                # include in attribute
                self._lib_calls_list.append(called_function_name)

    def _extract(self):
        del self._imported_modules
        return self._lib_calls_list


class _LibCallsDict(Attribute):
    """
    A dictionary of (libCallName, count) pairs.
    """
    def __init__(self, init_args):
        self._lib_calls_counters = {}
        self._imported_modules = init_args["imported_modules"]

    def _collect_data(self, collect_args):
        func_item = collect_args["func_item"]
        code_refs_from_list = list(idautils.CodeRefsFrom(func_item, False))

        for code_ref in code_refs_from_list:
            is_loaded_dynamically = False
            is_library_function = False
            function_name = ""

            if (idc.GetFunctionFlags(code_ref) == -1):
                # Find code_ref in functions that are imported dynamically
                for imported_module in self._imported_modules:
                    if code_ref in imported_module.get_addresses():
                        is_loaded_dynamically = True
                        break
            else:
                if ((idc.GetFunctionFlags(code_ref) & idaapi.FUNC_LIB) != 0 and
                    idaapi.get_func(code_ref) != idaapi.get_func(func_item)):
                    # code_ref is imported statically
                    is_library_function = True

            if (is_library_function or is_loaded_dynamically):
                # get name
                function_name = idc.NameEx(func_item, code_ref)

                # include in attribute
                if not(function_name in self._lib_calls_counters):
                    self._lib_calls_counters[function_name] = 0
                self._lib_calls_counters[function_name] += 1

    def _extract(self):
        del self._imported_modules
        return self._lib_calls_counters


#==============================================================================
# Immediates-realted attributes
#==============================================================================
class _ImmList (Attribute):
    """
    A list of immediate values.
    """
    def __init__(self, init_args):  # @UnusedVariable
        self._list_of_pairs = []

    def _collect_data(self, collect_args):
        for one_op in collect_args["ins_operands"]:
            if ((one_op[0] in [5, 6, 7]) and
                (one_op[1] not in list(idautils.\
                    CodeRefsFrom(collect_args["func_item"], True)))):
                op = one_op[1]
                self._list_of_pairs.append(op)

    def _extract(self):
        return self._list_of_pairs


class _ImmediateDict (Attribute):
    """
    A dictionary of (immediate_value, count) pairs.
    """
    def __init__(self, init_args):  # @UnusedVariable
        self._imm_counters = {}

    def _collect_data(self, collect_args):
        for one_op in collect_args["ins_operands"]:
            if one_op[0] in [5, 6, 7]:
                if not one_op[1] in self._imm_counters:
                    self._imm_counters[one_op[1]] = 0
                self._imm_counters[one_op[1]] += 1

    def _extract(self):
        return self._imm_counters


#==============================================================================
# Control-Flow Graph-related attribute
#==============================================================================
class _GraphRep (Attribute):
    """
    A representation of the function's control-flow.
    """
    def __init__(self, init_args):  # @UnusedVariable
        self.nodes = []  # numbers list. identifying vertices. not used.
        self.edges = []  # 2-tuples of numbers. edges.

    def _collect_data(self, collect_args):
        self.func_flow_chart = \
            idaapi.FlowChart(idaapi.get_func(collect_args["first_addr"]),
                             None, 0)
        for basic_block in self.func_flow_chart:
            self.nodes.append(basic_block.id)

        for basic_block in self.func_flow_chart:
            for basic_block_neighbour in basic_block.succs():
                self.edges.append((basic_block.id, basic_block_neighbour.id))

    def _extract(self):
        return self.edges
