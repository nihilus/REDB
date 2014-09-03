"""
This module contains the server's Request, Submit and Compare handlers.
"""

# standard library imports
import simplejson as json

# related third party imports
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.utils import timezone

# local application/library specific imports
import redb_server_com
from redb_server_descriptions import SuggestedDecsription
from redb_server_utils import (_decode_dict, get_graph_list,
                               get_graph_compressed)
from models import Function, Description
import redb_similarity_grading

MAX_REQ_CMTS = 25


#==============================================================================
# Handlers
#==============================================================================
@csrf_exempt
def request_handler(request):
    """
    Handles a Request for descriptions.
    """
    print "REDB: request_handler called"

    unpickled_request = redb_server_com.Request()
    unpickled_request.from_json(request.FILES['pickled_request'].read())

    # Adding more graph attributes:
    unpickled_request.matching_grade_attributes = \
        _process_matching_grade_attrs(unpickled_request.\
                                      matching_grade_attributes)

    # Building a temporary function
    second_function = Function()

    second_function.primary_attributes = \
        json.dumps(unpickled_request.primary_attributes)
    second_function.filtering_attributes = \
        json.dumps(unpickled_request.filtering_attributes)
    second_function.matching_grade_attributes = \
        json.dumps(unpickled_request.matching_grade_attributes)

    second_function.func_md5 = \
        unpickled_request.primary_attributes["_func_md5_attr"]
    second_function.exe_md5 = \
        unpickled_request.primary_attributes["_exe_md5_attr"]
    second_function.exe_name = \
        unpickled_request.primary_attributes["_exe_name_attr"]
    second_function.first_addr = \
        unpickled_request.primary_attributes["_first_addr_attr"]
    second_function.ins_num = \
        unpickled_request.primary_attributes["_ins_num_attr"]

    num_req_descs = unpickled_request.num_of_returned_comments
    if num_req_descs <= 0 or num_req_descs > MAX_REQ_CMTS:
        return _error_http_response("Error: required descriptions" +
                                   "number not in range")

    filtered_functions = []

    for function_obj in Function.objects.all():
        filter_grade = redb_similarity_grading.similarity_grading().\
            filter_grade(function_obj, second_function)
        if filter_grade >= redb_similarity_grading.FILTERING_THRESHOLD:
            filtered_functions.append(function_obj)

    function_grade_pairs = []
    for filtered_function in filtered_functions:
        matching_grade = redb_similarity_grading.similarity_grading().\
            matching_grade(filtered_function, second_function)
        if matching_grade >= redb_similarity_grading.MATCHING_THRESHOLD:
            pair = (filtered_function, matching_grade)
            function_grade_pairs.append(pair)

    sorted_functions = sorted(function_grade_pairs, key=lambda func: func[1])
    sorted_functions.reverse()

    suggested_descriptions = []

    for func, grade in sorted_functions:
        if len(suggested_descriptions) == num_req_descs:
            break
        fitting_descriptions = Description.objects.filter(function=func)
        for desc in fitting_descriptions:
            func_name_and_cmts = json.loads(desc.func_name_and_cmts,
                                            object_hook=_decode_dict)
            suggested_description = \
                SuggestedDecsription(func_name_and_cmts=func_name_and_cmts,
                                     matching_grade=grade,
                                     can_be_embedded=(func.ins_num ==
                                                      second_function.ins_num),
                                     date=desc.date)

            suggested_description_dict = suggested_description.to_dict()
            suggested_descriptions.append(suggested_description_dict)
            if len(suggested_descriptions) == num_req_descs:
                break

    response = redb_server_com.Response(\
                        suggested_descriptions_list=suggested_descriptions)
    response = response.to_json()

    http_response = HttpResponse(response)
    print "REDB: request_handler finished"
    return http_response


@csrf_exempt
def submit_handler(request):
    """
    Handles a Submitted descriptions.
    """
    print "REDB: submit_handler called"

    unpickled_submit = redb_server_com.Submit()
    unpickled_submit.from_json(request.FILES['pickled_submit'].read())

    # Adding more graph attributes:
    unpickled_submit.matching_grade_attributes = \
        _process_matching_grade_attrs(unpickled_submit.\
                                      matching_grade_attributes)

    primary_attributes_unjsoned = unpickled_submit.primary_attributes

    primary_attributes = json.dumps(unpickled_submit.primary_attributes)
    filtering_attributes = json.dumps(unpickled_submit.filtering_attributes)
    matching_grade_attributes = \
        json.dumps(unpickled_submit.matching_grade_attributes)
    func_name_and_cmts = json.dumps(unpickled_submit.comments_and_name)

    first_addr = primary_attributes_unjsoned["_first_addr_attr"]
    exe_name = primary_attributes_unjsoned["_exe_name_attr"]
    exe_md5 = primary_attributes_unjsoned["_exe_md5_attr"]
    func_md5 = primary_attributes_unjsoned["_func_md5_attr"]
    ins_num = primary_attributes_unjsoned["_ins_num_attr"]

    func_set = Function.\
        objects.filter(first_addr=first_addr,
                       exe_name=exe_name,
                       exe_md5=exe_md5,
                       func_md5=func_md5,
                       ins_num=ins_num,
                       primary_attributes=primary_attributes,
                       filtering_attributes=filtering_attributes,
                       matching_grade_attributes=matching_grade_attributes
                       )

    func = None
    duplicate = False

    if len(func_set):
        func = func_set[0]

        dup_descriptions = \
            Description.objects.filter(func_name_and_cmts=func_name_and_cmts)

        if len(dup_descriptions):
            duplicate = True
    else:

        func = Function(first_addr=first_addr,
                        exe_name=exe_name,
                        exe_md5=exe_md5,
                        func_md5=func_md5,
                        ins_num=ins_num,
                        primary_attributes=primary_attributes,
                        filtering_attributes=filtering_attributes,
                        matching_grade_attributes=matching_grade_attributes)
        func.save()
        print "REDB: Added new Function!"

    if not duplicate:
        func.description_set.create(func_name_and_cmts=func_name_and_cmts,
                                    date=str(timezone.now()))
        print "REDB: Added new Description!"
    else:
        print "REB: Duplicate Description!"

    print "DEBUG: submit_handler finished"
    return HttpResponse("Success")


@csrf_exempt
def compare_handler(request):
    """
    Used for testing and and debugging.
    Handles a request to compare functions.
    """
    unjsoned_compare = redb_server_com.Compare()
    unjsoned_compare.from_json(request.FILES['compare'].read())

    exe_name_1 = unjsoned_compare.exe_name_1
    functions_from_exe_1 = unjsoned_compare.functions_from_exe_1
    exe_name_2 = unjsoned_compare.exe_name_2
    functions_from_exe_2 = unjsoned_compare.functions_from_exe_2
    attr_list = unjsoned_compare.attr_list

    num_of_comparisons = "/" + str(len(list(functions_from_exe_1)) *
                                   len(list(functions_from_exe_1)))
    comparison_index = 0

    all_results = {}
    for attr in attr_list:
        all_results[attr] = {}

    # Get all functions in exe 1
    func_set_1 = Function.objects.filter(exe_name=exe_name_1)
    if func_set_1.count() == 0:
        return _error_http_response("exe_name_1 was not found in DB")

    # Get all functions in exe 2
    func_set_2 = Function.objects.filter(exe_name=exe_name_2)
    if func_set_2.count() == 0:
        return _error_http_response("exe_name_2 was not found in DB")

    # All Descriptions in exe 1
    desc_set_1 = Description.objects.filter(function__in=func_set_1)
    if desc_set_1.count() == 0:
        return _error_http_response("No Descriptions were found" +
                                   "in DB for exe_name_1")

    # All Descriptions in exe 2
    desc_set_2 = Description.objects.filter(function__in=func_set_2)
    if desc_set_2.count() == 0:
        return _error_http_response("No Descriptions were found" +
                                   "in DB for exe_name_2")

    for function_1 in functions_from_exe_1:

        # Descriptions of function_1
        search_string = ("\"FunctionName\": \"" + function_1 + "\"")
        desc_function_1_exe_1 = \
            desc_set_1.filter(func_name_and_cmts__contains=search_string)
        desc_function_1_exe_2 = \
            desc_set_2.filter(func_name_and_cmts__contains=search_string)

        if ((desc_function_1_exe_1.count() == 1) and
                (desc_function_1_exe_2.count() == 1)):
            func_1 = desc_function_1_exe_1[0].function
            for attr in attr_list:
                all_results[attr][function_1] = {}
        else:
            continue

        for function_2 in functions_from_exe_2:
            # Descriptions of function_2
            search_string = ("\"FunctionName\": \"" + function_2 + "\"")
            desc_function_2_exe_1 = \
                desc_set_1.filter(func_name_and_cmts__contains=search_string)
            desc_function_2_exe_2 = \
                desc_set_2.filter(func_name_and_cmts__contains=search_string)

            if ((desc_function_2_exe_1.count() == 1) and
                    (desc_function_2_exe_2.count() == 1)):
                func_2 = desc_function_2_exe_2[0].function
            else:
                continue

            comparison_index += 1
            print str(comparison_index) + num_of_comparisons

            for attr in attr_list:
                print func_1, func_2, attr
                all_results[attr][function_1][function_2] = \
                    _compare_functions(func_1, func_2, attr)

    response = \
        redb_server_com.CompareResponse(compare_results=all_results).to_json()

    http_response = HttpResponse(response)
    return http_response


#==============================================================================
# Handler utility methods
#==============================================================================
def _process_matching_grade_attrs(matching_grade_attributes):
    """
    Given a normal graph, create two new graphs: compressed_graph and
    list_graph, from it.
    """
    normal_graph = matching_grade_attributes['_graph_rep_attr']
    graph_attr = {'normal_graph': normal_graph, \
                  'compressed_graph': get_graph_compressed(normal_graph), \
                  'list_graph': get_graph_list(normal_graph)}
    matching_grade_attributes['_graph_rep_attr'] = graph_attr
    return matching_grade_attributes


def _error_http_response(string):
    response = redb_server_com.\
        CompareResponse(compare_results=string).to_json()
    return HttpResponse(response)


def _compare_functions(func1, func2, attr):
    """
    Given two functions and an attribute, returns the similarity grade of the
    two functions with regard to the attribute.
    """
    filtering_attributes_1 = json.loads(func1.filtering_attributes,
                                        object_hook=_decode_dict)
    filtering_attributes_2 = json.loads(func2.filtering_attributes,
                                        object_hook=_decode_dict)

    matching_grade_attributes_1 = json.loads(func1.matching_grade_attributes,
                                             object_hook=_decode_dict)
    matching_grade_attributes_2 = json.loads(func2.matching_grade_attributes,
                                             object_hook=_decode_dict)

    primary_attributes_1 = json.loads(func1.primary_attributes,
                                      object_hook=_decode_dict)
    primary_attributes_2 = json.loads(func2.primary_attributes,
                                      object_hook=_decode_dict)

    attr_dict_1 = dict(filtering_attributes_1.items() + \
                       matching_grade_attributes_1.items() + \
                       primary_attributes_1.items())

    attr_dict_2 = dict(filtering_attributes_2.items() + \
                       matching_grade_attributes_2.items() + \
                       primary_attributes_2.items())

    similarity_grade = redb_similarity_grading.\
        similarity_grading().similarity_grade(attr_dict_1,
                                              attr_dict_2,
                                              [attr])

    return similarity_grade
