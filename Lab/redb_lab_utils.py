import os
import json
import itertools
import redb_lab_results

OPTIMAL_WEIGHTS_MAX_RANGE = 10

# lab grading method.
LAB_METHOD_AVG = 1
LAB_METHOD_RATIO = 2


#==============================================================================
# Processing results
#==============================================================================
def get_lab_results(base, exe_1, exe_2, attr):
    """
    Reads from dump file and returns results of comaprison between functions in
    exe_1 and functions in exe_2 by attr.
    """
    file_path = os.path.join(base, exe_1, exe_2, attr + ".dump")

    file_handle = open(file_path)
    jsoned_results = file_handle.read()
    file_handle.close()

    unjsoned_results_dict = json.loads(jsoned_results)

    return unjsoned_results_dict


def get_several_lab_results(base, exe_1, exe_2, attr_list):
    """
    Returns a dictionary of (attr: (results of comaprison between functions in
    exe_1 and functions in exe_2 by attr)) pairs, for each attr in attr_list.
    """
    return {attr:
            get_lab_results(base, exe_1, exe_2, attr) for attr in attr_list}


def _calc_matching_grade_for_pair(weights, one_attr_results_dict,
                                  func_1, func_2):
    """
    Returns for some position in the results arrays, its total matching grade,
    using one_attr_results_dict.
    """
    oard = one_attr_results_dict
    sum_of_grades = float(0)
    sum_of_weights = float(0)
    for attr in oard.keys():
        # avoid case when heuristic could not be compared
        if (oard[attr][func_1][func_2] != (-1)):
            sum_of_grades += (weights[attr] * oard[attr][func_1][func_2])
            sum_of_weights += weights[attr]

    if (sum_of_weights == 0):  # no heuristics to use.
        return -1

    return sum_of_grades / sum_of_weights


def attr_results_to_mgs(weights, one_attr_results_dict, functions_list):
    """
    Given one_attr_results_dict and weights return matching grades.
    """
    mg_result = dict()  # the result matching grade dictionary.

    # calculate matching grade for each functions pair.
    for function1_name in functions_list:
        for function2_name in functions_list:

            if function1_name not in mg_result:
                mg_result[function1_name] = dict()
            mg_result[function1_name][function2_name] = \
                _calc_matching_grade_for_pair(weights, one_attr_results_dict,
                                              function1_name, function2_name)
    return mg_result


#==============================================================================
# Optimal weights
#==============================================================================
def _find_optimal_weights(one_attr_results_dict, Method, functions_list,
                          attr_list):
    """
    Given all the comparisons by one attribute in lab_results, find the
    optimal weights with regard to method. assumes attribute are sorted by
    order of importance.
    """
    min_class_instance = None
    if Method is 1:
        min_class_instance = MinWeightsMethodAvg(one_attr_results_dict,
                                                 functions_list)
    elif Method is 2:
        min_class_instance = MinWeightsMethodRatio(one_attr_results_dict,
                                                   functions_list)

    """ Computing permutations of weights. """
    N = len(one_attr_results_dict.keys())  # N = heuristics number used.

    # all possible permutations.
    weights_list = itertools.\
        product(*[range(1, OPTIMAL_WEIGHTS_MAX_RANGE + 1, 1) for
                  i in range(N)])  # @UnusedVariable

    sorted_weights_list = []

    for weight in weights_list:
        weight = list(weight)
        weight.sort(reverse=True)
        # drop permutations when weights have a common divider, also drop dups.
        if (weight not in sorted_weights_list) and (GCD_List(weight) == 1):
            sorted_weights_list.append(weight)

    # connecting attributes with their weights
    # a list of dictionaries of (attribute:weight) pairs.
    weights_dict = [{attr_list[index]:weight[index] for index in
                     range(len(attr_list))} for weight in sorted_weights_list]

    ind = 0
    weights_num = len(weights_dict)
    for weights in weights_dict:
        ind += 1
        print ind, "//", weights_num
        min_class_instance.update(weights)

    return min_class_instance.get_best()


def find_optimal_weights(base, exe1, exe2, method, functions_list, attr_list):
    """
    Returns optimal weights with regard to method.
    """
    lab_results = get_several_lab_results(base, exe1, exe2, attr_list)
    return _find_optimal_weights(lab_results, method, functions_list,
                                 attr_list)


def GCD(a, b):
    """ The Euclidean Algorithm """
    a = abs(a)
    b = abs(b)
    while a:
        a, b = b % a, a
    return b


def GCD_List(lst):
    """
    Finds the GCD of numbers in a list.
    Input: List of numbers you want to find the GCD of
        E.g. [8, 24, 12]
    Returns: GCD of all numbers
    """
    return reduce(GCD, lst)


#==============================================================================
# Optimal Weights - Measures
#==============================================================================
class MinWeightsMethodRatio():
    """
    (The lower the better)
    """
    def __init__(self, one_attr_results_dict, functions_list):
        self.one_attr_results_dict = one_attr_results_dict

        self.cur_max_grade = 1.0
        self.optimal_results = {}
        self.optimal_weights = {}

        self.functions_list = functions_list

    def update(self, weights):
        cur_mg_result = redb_lab_results.\
            ResultsProcessing(attr_results_to_mgs(weights,
                                                  self.one_attr_results_dict,
                                                  self.functions_list))
        cur_grade = cur_mg_result.ComputeGrade(LAB_METHOD_RATIO)
        if cur_grade < self.cur_max_grade:
            self.cur_max_grade = cur_grade
            self.optimal_weights = weights
            self.optimal_results = cur_mg_result

    def get_best(self):
        return self.optimal_results, self.optimal_weights


class MinWeightsMethodAvg():
    """
    (The higher the better)
    """
    def __init__(self, one_attr_results_dict, functions_list):
        self.one_attr_results_dict = one_attr_results_dict

        self.cur_min_grade = 0.0
        self.optimal_results = {}
        self.optimal_weights = {}

        self.functions_list = functions_list

    def update(self, weights):
        cur_mg_result = redb_lab_results.\
            ResultsProcessing(attr_results_to_mgs(weights,
                                                  self.one_attr_results_dict,
                                                  self.functions_list))
        cur_grade = cur_mg_result.ComputeGrade(LAB_METHOD_AVG)
        if cur_grade > self.cur_min_grade:
            self.cur_min_grade = cur_grade
            self.optimal_weights = weights
            self.optimal_results = cur_mg_result

    def get_best(self):
        return self.optimal_results, self.optimal_weights


#==============================================================================
# Other utilities
#==============================================================================
def enter_directory(relative_directory):
        """
        if relative_directory does not exist in CWD, create it.
        Finally, change CWD to relative_directory.
        """
        if not os.path.exists(relative_directory):
            os.makedirs(relative_directory)
        os.chdir(os.path.join(os.getcwd(), relative_directory))


def up_one_directory():
        """ Change CWD to one directory up. """
        os.chdir(os.path.dirname(os.getcwd()))


def dump_in_cwd(name, contents):
    handle = open(name, "wb")
    handle.write(contents)
    handle.close()


def results_to_excel_txt(functions_from_exe_1, functions_from_exe_2,
                           compare_results):
    """
    Given two lists of functions and comparison results, return the
    results in excel txt format.
    """
    txt = "\t"

    # first line
    for function_1 in functions_from_exe_1:
        txt += function_1 + "\t"
    txt += "\n"

    # other lines
    for function_2 in functions_from_exe_2:
        txt += function_2 + "\t"
        for function_1 in functions_from_exe_1:
            txt += str(compare_results[function_1][function_2]) + "\t"
        txt += "\n"

    return txt
