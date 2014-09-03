"""
Tools for Similarity Grading.
"""

# related third party imports
import simplejson as json

# local application/library specific imports
from redb_heuristics import StringEquality, IntegerEquality
from redb_heuristics import ListSimilarity  # @UnusedImport
from redb_heuristics import DictionarySimilarity  # @UnusedImport
from redb_heuristics import GraphCompTTL  # @UnusedImport

from redb_server_utils import _decode_dict

#==============================================================================
# Constants defining similarity grading.
#==============================================================================
ATTRIBUTES = \
{
"_ins_type_dict_attr": {"weight": 4,
                        "min_arg": 0,
                        "min_func": "MinDataFunction",
                        "heuristic": "DictionarySimilarity"},
"_lib_calls_dict_attr": {"weight": 2,
                         "min_arg": 1,
                         "min_func": "MinDataFunction",
                         "heuristic": "DictionarySimilarity"},
"_str_dict_attr": {"weight": 2,
                   "min_arg": 1,
                   "min_func": "MinDataFunction",
                   "heuristic": "DictionarySimilarity"},
"_ins_data_list_attr": {"weight": 10,
                        "min_arg": 0,
                        "min_func": "MinDataFunction",
                        "heuristic": "ListSimilarity"},
"_ins_type_list_attr": {"weight": 8,
                        "min_arg": 0,
                        "min_func": "MinDataFunction",
                        "heuristic": "ListSimilarity"},
"_str_list_attr": {"weight": 6,
                   "min_arg": 1,
                   "min_func": "MinDataFunction",
                   "heuristic": "ListSimilarity"},
"_lib_calls_list_attr": {"weight": 6,
                         "min_arg": 1,
                         "min_func": "MinDataFunction",
                         "heuristic": "ListSimilarity"},
"_imm_list_attr": {"weight": 4,
                   "min_arg": 1,
                   "min_func": "MinDataFunction",
                   "heuristic": "ListSimilarity"},
"_graph_rep_attr": {"weight": 6,
                    "min_arg": 4,
                    "min_func": "MinDataFunction_Graphs",
                    "heuristic": "GraphCompTTL"},
}

FILTERING_THRESHOLD = 0.8

# Attributes used for filtering.
FILTER_ATTR_LIST = ["_ins_type_dict_attr", "_lib_calls_dict_attr",
                    "_str_dict_attr"]

MATCHING_THRESHOLD = 0.9

# Attributes used for MatchingGrade.
MG_ATTR_LIST = ["_ins_data_list_attr", "_ins_type_list_attr", "_str_list_attr",
                "_lib_calls_list_attr", "_imm_list_attr", "_graph_rep_attr"]


#==============================================================================
# Main class used for similarity grading.
#==============================================================================
class similarity_grading:
    """
    Contains methods used for grading similarity between functions.
    """
    def filter_grade(self, first_function, second_function):
        """
        Used for preliminary filtering of the DB.
        """

        if StringEquality(first_function.func_md5,
                          second_function.func_md5).ratio():
            return True
        if (StringEquality(first_function.exe_md5,
                           second_function.exe_md5).ratio() and
            IntegerEquality(first_function.first_addr,
                            second_function.first_addr).ratio()):
            return True

        first_function_filtering_attributes = \
            json.loads(first_function.filtering_attributes,
                       object_hook=_decode_dict)
        second_function_filtering_attributes = \
            json.loads(second_function.filtering_attributes,
                       object_hook=_decode_dict)

        grade = self.similarity_grade(first_function_filtering_attributes,
                                 second_function_filtering_attributes,
                                 FILTER_ATTR_LIST)

        return grade

    def matching_grade(self, first_function, second_function):
        """
        Given two function, return their similarity matching grade.
        """

        if (StringEquality(first_function.func_md5,
                           second_function.func_md5).ratio() and
                StringEquality(first_function.exe_md5,
                               second_function.exe_md5).ratio() and
                IntegerEquality(first_function.first_addr,
                                second_function.first_addr).ratio()):
            return 1.0

        first_function_matching_grade_attributes = \
            json.loads(first_function.matching_grade_attributes,
                       object_hook=_decode_dict)
        second_function_matching_grade_attributes = \
            json.loads(second_function.matching_grade_attributes,
                       object_hook=_decode_dict)

        grade = self.similarity_grade(first_function_matching_grade_attributes,
                                 second_function_matching_grade_attributes,
                                 MG_ATTR_LIST)

        return grade

    def similarity_grade(self, attr_dict_1, attr_dict_2, attr_list):
        """
        Given two dictionaries containing attributes and a list of attributes,
        return a matching grade based on the attribute and their weights.
        """
        total_weight = 0
        grade = 0
        for attr in attr_list:
            set_1 = attr_dict_1[attr]
            set_2 = attr_dict_2[attr]

            minfunc = globals()[ATTRIBUTES[attr]["min_func"]]

            if minfunc(set_1, set_2, ATTRIBUTES[attr]["min_arg"]):

                heuristic_function = globals()[ATTRIBUTES[attr]["heuristic"]]

                attr_grade = heuristic_function(set_1, set_2)
                attr_grade = attr_grade.ratio()

                weight = ATTRIBUTES[attr]["weight"]
                total_weight += weight
                grade += weight * attr_grade

        if total_weight:
            grade /= total_weight
        else:
            grade = -1

        assert (-1 <= grade <= 1)
        return grade


#==============================================================================
# Utilities
#==============================================================================
def MinDataFunction(set_1, set_2, minimum):
    """
    Given two sets, returns True if both are larger than minimum
    """
    if len(set_1) >= minimum and len(set_2) >= minimum:
        return True
    else:
        return False


def MinDataFunction_Graphs(set_1, set_2, minimum):
    """
    Given two graphs, returns True if both are have minimum edges or more.
    """
    if len(set_1['compressed_graph']) >= minimum and\
        len(set_2['compressed_graph']) >= minimum and\
        sum([len(l) for l in set_1['list_graph']]) >= minimum and\
        sum([len(l) for l in set_2['list_graph']]) >= minimum:
        return True
    else:
        return False
