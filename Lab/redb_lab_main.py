import redb_lab_com
import os
import sys
import json
import redb_lab_results
import redb_lab_utils
from redb_lab_utils import (dump_in_cwd, enter_directory, up_one_directory,
                            results_to_excel_txt)

HOST = "127.0.0.1:3306"

# Sorted by importance
ATTR_LIST = ["_ins_type_list_attr", "_graph_rep_attr", "_str_list_attr",
             "_lib_calls_list_attr", "_ins_data_list_attr", "_imm_list_attr"]

#ATTR_LIST = ["_ins_type_list_attr", "_graph_rep_attr"]

# lab grading method.
LAB_METHOD_AVG = 1
LAB_METHOD_RATIO = 2


#==============================================================================
# Querying the server
#==============================================================================
def _query_server(exe_name_1, \
                functions_from_exe_1, \
                exe_name_2, \
                functions_from_exe_2, \
                attr_list):
    """
    Given two executables, two lists of functions (one from each executable),
    and a list of attributes, queries the server with the exe's, lists and
    attributes. Returns the results.
    """
    compare = redb_lab_com.Compare(exe_name_1,
                                   functions_from_exe_1,
                                   exe_name_2,
                                   functions_from_exe_2,
                                   attr_list)

    compare_response = redb_lab_com.send_compare(HOST, compare.to_json())
    return compare_response


def query_server_dump_results(exe_name_1,
                              functions_from_exe_1,
                              exe_name_2,
                              functions_from_exe_2,
                              attr_list):
    """
    Given two executables, two lists of functions (one from each executable)
    and a list of attributes, queries the server with the exe's, lists,
    attributes, and dumps the results to CWD in two formats.
    """
    response = _query_server(exe_name_1, \
                           functions_from_exe_1, \
                           exe_name_2,
                           functions_from_exe_2, \
                           attr_list
                           )

    for attr in response.compare_results:

        # Excel txt format
        excel_file_name = (attr + ".txt")
        txt = results_to_excel_txt(functions_from_exe_1,
                                   functions_from_exe_2,
                                   response.compare_results[attr])
        dump_in_cwd(excel_file_name, txt)

        # Json dump format
        dump_file_name = (attr + ".dump")
        dump_in_cwd(dump_file_name, json.dumps(response.compare_results[attr]))


def query_server_dump_results_few_executables(executables_list,
                                              functions_list):
    """
    Calls query_server_dump_results for all pairs of executables in
    executables_list with functions_list.
    """
    functions_from_exe_1 = functions_list
    functions_from_exe_2 = functions_list
    attr_list = ATTR_LIST

    # First executable
    for i in range(len(executables_list)):
        exe_name_1 = executables_list[i]
        enter_directory(exe_name_1)
        # Second executable
        for j in range((i + 1), len(executables_list), 1):
            exe_name_2 = executables_list[j]
            enter_directory(exe_name_2)

            query_server_dump_results(exe_name_1,
                                      functions_from_exe_1,
                                      exe_name_2,
                                      functions_from_exe_2,
                                      attr_list)

            up_one_directory()
        up_one_directory()


#==============================================================================
# Extract custom summaries
#==============================================================================
def _dump_comparison_summary(comparison_name, results, additional_data=None):

        processed_results = redb_lab_results.ResultsProcessing(results)

        # Average Differance
        summary = ("\"Average Differance\": " +
                   str(processed_results.ComputeGrade(1)) + "\r\n")

        # Min FalsePos-FalseNeg Ratio
        summary += ("\"Min FalsePos-FalseNeg Ratio\": " +
                   str(processed_results.ComputeGrade(2)) +
                   ", for threshold: " +
                   str(processed_results.GetThresholdNumber()))

        if additional_data is not None:
            summary = summary + "\r\n" + str(additional_data)

        comparison_summary_file_name = ("summary_" + comparison_name + ".txt")
        dump_in_cwd(comparison_summary_file_name, summary)


def dump_single_attribute_summaries(base, executables_list):
    """
    Iterate all single attribute comparison results and dump summaries.
    """
    for i in range(len(executables_list)):
        exe_name_1 = executables_list[i]
        enter_directory(exe_name_1)
        for j in range(i + 1, len(executables_list), 1):
            exe_name_2 = executables_list[j]
            enter_directory(exe_name_2)

            for attr in ATTR_LIST:
                results = redb_lab_utils.get_lab_results(base, exe_name_1,
                                                         exe_name_2, attr)

                comparison_name = "single_attr_" + attr
                _dump_comparison_summary(comparison_name, results)

            up_one_directory()
        up_one_directory()


def dump_several_weighted_attrs(base, executables_list, weights,
                                functions_list):
    """
    Given that the attributes exist on disc, for each pair of executables
    compares matching grade (for each pair of functions) with regard to weights
    and dumps the results summaries into relevant folders.
    """
    for i in range(len(executables_list)):
        exe_1 = executables_list[i]
        enter_directory(exe_1)
        for j in range(i + 1, len(executables_list), 1):
            exe_2 = executables_list[j]
            enter_directory(exe_2)
            lab_results = redb_lab_utils.get_several_lab_results(base, exe_1,
                                                             exe_2, ATTR_LIST)
            mg_result = redb_lab_utils.attr_results_to_mgs(weights,
                                                           lab_results,
                                                           functions_list)

            comparison_name = "several_weighted_attrs"
            additional_data = "For weights: " + str(weights)
            _dump_comparison_summary(comparison_name, mg_result,
                                    additional_data)

            file_name = comparison_name + ".dump"
            dump_in_cwd(file_name, json.dumps(mg_result))

            up_one_directory()
        up_one_directory()


def dump_several_weighted_attrs_partial(base, executables_list, weights,
                                           functions_list, attr_list):
    """
    Given that the attributes exist on disc, for each pair of executables
    compares matching grade (for each pair of functions) with regard to weights
    and dumps the results summaries into relevant folders. Performs this
    action several times: each time drops an attribute.
    """
    for i in range(len(executables_list)):
        exe_1 = executables_list[i]
        enter_directory(exe_1)
        for j in range(i + 1, len(executables_list), 1):
            exe_2 = executables_list[j]
            enter_directory(exe_2)

            iterate_attr_list_tmp = list(attr_list)
            for attr_name in iterate_attr_list_tmp:
                backup_list = list(attr_list)
                attr_list.remove(attr_name)

                lab_results = redb_lab_utils.get_several_lab_results(base,
                                                                     exe_1,
                                                                     exe_2,
                                                                     attr_list)
                mg_result = redb_lab_utils.attr_results_to_mgs(weights,
                                                               lab_results,
                                                               functions_list)
                comparison_name = ("several_weighted_attrs_" +
                                   attr_name + "_dropped")
                additional_data = "For weights: " + str(weights)
                _dump_comparison_summary(comparison_name, mg_result,
                                         additional_data)

                file_name = comparison_name + ".dump"
                dump_in_cwd(file_name, json.dumps(mg_result))

                attr_list = list(backup_list)
            up_one_directory()
        up_one_directory()


#==============================================================================
# Optimal weights
#==============================================================================
def compute_mgs_optimal_weights(base, executables_list, Method,
                                functions_list):
    for i in range(len(executables_list)):
        exe_name_1 = executables_list[i]
        enter_directory(exe_name_1)
        for j in range(i + 1, len(executables_list), 1):
            exe_name_2 = executables_list[j]
            enter_directory(exe_name_2)

            mg_result = redb_lab_utils.find_optimal_weights(base, exe_name_1,
                                                          exe_name_2, Method,
                                                          functions_list,
                                                          ATTR_LIST)

            comparison_name = "optimal_weights_method" + str(Method)
            additional_data = "optimal weights:" + str(mg_result[1])
            _dump_comparison_summary(comparison_name,
                                     mg_result[0].GetResDict(),
                                    additional_data)

            file_name = comparison_name + ".dump"
            dump_in_cwd(file_name, json.dumps(mg_result[0].GetResDict()))

            up_one_directory()
        up_one_directory()


#==============================================================================
# Main
#==============================================================================
if __name__ == "__main__":
    base_dir = r"C:\Users\Yaron\Desktop\base"
    os.chdir(base_dir)
#-----------------------------------------------------------------------------
    functions_list_file_path = os.path.join(os.path.dirname(sys.argv[0]),
                                       "functions_list.txt")
    functions_list_file = open(functions_list_file_path, "r")
    functions_list = json.load(functions_list_file)
    functions_list_file.close()
#-----------------------------------------------------------------------------
    executables_list_file_path = os.path.join(os.path.dirname(sys.argv[0]),
                                          "executables_list.txt")
    executables_list_file = open(executables_list_file_path, "r")
    executables_list = json.load(executables_list_file)
    executables_list_file.close()
#-----------------------------------------------------------------------------
    """
    query_server_dump_results_few_executables(executables_list, functions_list)

    dump_single_attribute_summaries(base_dir, executables_list)

    #compute_mgs_optimal_weights(base_dir, executables_list, LAB_METHOD_AVG,
    #                            functions_list)
    compute_mgs_optimal_weights(base_dir, executables_list, LAB_METHOD_RATIO,
                                functions_list)

    """
    weights = {'_ins_data_list_attr': 2, '_lib_calls_list_attr': 2,
               '_graph_rep_attr': 8, '_str_list_attr': 5,
               '_ins_type_list_attr': 10, '_imm_list_attr': 1}

    dump_several_weighted_attrs(base_dir, executables_list, weights,
                                functions_list)

    dump_several_weighted_attrs_partial(base_dir, executables_list, weights,
                                        functions_list, ATTR_LIST)
