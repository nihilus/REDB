"""
Methods and utilities required for communicating with the client.
"""

# standard library imports
import simplejson as json

# related third party imports
from redb_server_utils import _decode_dict


#==============================================================================
# Communication Data Types
#==============================================================================
class Request:
    """
    A request for descriptions for a specific function.
    """
    def __init__(self, \
                 primary_attributes=None, \
                 filtering_attributes=None, \
                 matching_grade_attributes=None, \
                 num_of_returned_comments=None):

        self.primary_attributes = primary_attributes
        self.filtering_attributes = filtering_attributes
        self.matching_grade_attributes = matching_grade_attributes
        self.num_of_returned_comments = num_of_returned_comments

    def to_json(self):
        req_dict = {}
        req_dict["primary_attributes"] = self.primary_attributes
        req_dict["filtering_attributes"] = self.filtering_attributes
        req_dict["matching_grade_attributes"] = self.matching_grade_attributes
        req_dict["num_of_returned_comments"] = self.num_of_returned_comments
        return json.dumps(req_dict)

    def from_json(self, json_obj):
        req_dict = json.loads(json_obj, object_hook=_decode_dict)
        self.primary_attributes = req_dict["primary_attributes"]
        self.filtering_attributes = req_dict["filtering_attributes"]
        self.matching_grade_attributes = req_dict["matching_grade_attributes"]
        self.num_of_returned_comments = req_dict["num_of_returned_comments"]


class Response:
    """
    A response from the server to a request.
    """
    def __init__(self, \
                  suggested_descriptions_list=None):

        self.suggested_descriptions = suggested_descriptions_list

    def to_json(self):
        return json.dumps(self.suggested_descriptions)

    def from_json(self, json_obj):
        self.suggested_descriptions = json.loads(json_obj,
                                                 object_hook=_decode_dict)


class Submit:
    """
    A Submit includes data gathered about a specific function.
    """
    def __init__(self, \
                 primary_attributes=None, \
                 filtering_attributes=None, \
                 matching_grade_attributes=None, \
                 comments_and_name=None):

        self.primary_attributes = primary_attributes
        self.filtering_attributes = filtering_attributes
        self.matching_grade_attributes = matching_grade_attributes
        self.comments_and_name = comments_and_name

    def to_json(self):
        sub_dict = {}
        sub_dict["primary_attributes"] = self.primary_attributes
        sub_dict["filtering_attributes"] = self.filtering_attributes
        sub_dict["matching_grade_attributes"] = self.matching_grade_attributes
        sub_dict["comments_and_name"] = self.comments_and_name
        return json.dumps(sub_dict)

    def from_json(self, json_obj):
        sub_dict = json.loads(json_obj, object_hook=_decode_dict)
        self.primary_attributes = sub_dict["primary_attributes"]
        self.filtering_attributes = sub_dict["filtering_attributes"]
        self.matching_grade_attributes = sub_dict["matching_grade_attributes"]
        self.comments_and_name = sub_dict["comments_and_name"]


class Compare:
    """
    A comparison request.
    Compare functions_from_exe_1 from exe_name_1 with functions_from_exe_2
    from exe_name_2.
    """
    def __init__(self, \
                 exe_name_1=None, \
                 functions_from_exe_1=None, \
                 exe_name_2=None, \
                 functions_from_exe_2=None, \
                 attr_list=None
                 ):

        self.exe_name_1 = exe_name_1
        self.functions_from_exe_1 = functions_from_exe_1
        self.exe_name_2 = exe_name_2
        self.functions_from_exe_2 = functions_from_exe_2
        self.attr_list = attr_list

    def to_json(self):
        cmp_dict = {}
        cmp_dict["exe_name_1"] = self.exe_name_1
        cmp_dict["functions_from_exe_1"] = self.functions_from_exe_1
        cmp_dict["exe_name_2"] = self.exe_name_2
        cmp_dict["functions_from_exe_2"] = self.functions_from_exe_2
        cmp_dict["attr_list"] = self.attr_list
        return json.dumps(cmp_dict)

    def from_json(self, json_obj):
        cmp_dict = json.loads(json_obj, object_hook=_decode_dict)
        self.exe_name_1 = cmp_dict["exe_name_1"]
        self.functions_from_exe_1 = cmp_dict["functions_from_exe_1"]
        self.exe_name_2 = cmp_dict["exe_name_2"]
        self.functions_from_exe_2 = cmp_dict["functions_from_exe_2"]
        self.attr_list = cmp_dict["attr_list"]


class CompareResponse:
    """
    Comparison results.
    """
    def __init__(self, \
                  compare_results=None):

        self.compare_results = compare_results

    def to_json(self):
        return json.dumps(self.compare_results)

    def from_json(self, json_obj):
        self.compare_results = json.loads(json_obj, object_hook=_decode_dict)
