"""
A script meant to be run within IDA, and used to extract function names
from one executable or the union/intersection of a few executables functions
names.
"""

import idautils
import idc
import idaapi

MIN_INS_PER_HANDLED_FUNCTION = 5


class FunctionNames:
    """
    Usage: Create an instance, open each executable in IDA and call the
    AddFunctions method. self.function_name_union holds the union.
    self.function_name_intersection holds the intersection.
    """
    def __init__(self):
        self.function_names_union = set()
        self.function_names_intersection = set()

    def AddFunctions(self):
        current = set()
        for function in list(idautils.Functions()):
            if (self._IsFunctionHandled(function)):
                current.add(idc.GetFunctionName(function))

        self.function_names_union.update(current)
        if len(self.function_names_intersection) == 0:
            self.function_names_intersection.update(current)
        self.function_names_intersection.intersection_update(current)

    def _IsFunctionHandled(self, addr):
        first_addr = idaapi.get_func(addr).startEA
        flags = idc.GetFunctionFlags(first_addr)
        if (flags & (idc.FUNC_THUNK | idc.FUNC_LIB)):
            err_str = "REDB: function has been identified by IDA as a "
            err_str += "thunk or a library function and therefore will "
            err_str += "not be handled."
            print err_str
            return False
        else:
            if (len(list(idautils.FuncItems(addr))) <
                MIN_INS_PER_HANDLED_FUNCTION):
                err_str = "REDB: function has too few instructions "
                err_str += "and therefore will not be handled."
                print err_str
                return False
            else:
                return True

if ('obj' not in globals()) or obj == None:  # @UndefinedVariable
    obj = FunctionNames()
obj.AddFunctions()
