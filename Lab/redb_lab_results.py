# lab grading method.
LAB_METHOD_AVG = 1
LAB_METHOD_RATIO = 2

# lab intervals constantss.
INTERVALS_START = 0.0
INTERVALS_END = 1.0
INTERVALS_NUM = 20
INTERVAL_JUMP = (INTERVALS_END - INTERVALS_START) / INTERVALS_NUM


class ResultsProcessing():
    def __init__(self, res_dict):
        """
        res_dict - dictionary of comparison results of a pair of functions.
        grades are from 0 to 1.
        """
        self.res_dict = res_dict
        self.match_dict = self._get_should_be_match_dict()

    def _get_should_be_match_dict(self):
        """
        Returns a dictionary similar to results except the values boolean:
        True if they should have a high similarity grade, i.e same function
        name, from different versions, False o.w.
        """
        res_dict = self.res_dict
        match_dict = dict()
        for name1 in res_dict:
            for name2 in res_dict[name1]:
                if name1 not in match_dict:
                    match_dict[name1] = dict()
                match_dict[name1][name2] = True if (name1 == name2) else False
        return match_dict

    def ComputeGrade(self, method):
        """
        compute a measurement of the results, using method.
        """
        if method is LAB_METHOD_AVG:
            return self._compute_grade_avg()
        if method is LAB_METHOD_RATIO:
            return self._compute_grade_ratio()

#==============================================================================
# max(FP-ratio,FN-ratio)
#==============================================================================

    def _max_fp_fn_ratio(self, threshold):
        """
        returns max(FP-ratio,FN-ratio), with regard to threshold.
        """
        res_dict = self.res_dict

        FalsePosNum = 0
        PosTTL = 0
        FalseNegNum = 0
        NegTTL = 0

        for name1 in res_dict:
            for name2 in res_dict[name1]:
                if (res_dict[name1][name2] is not -1):
                    if (res_dict[name1][name2] >= threshold):
                        PosTTL += 1
                        if not self.match_dict[name1][name2]:
                            FalsePosNum += 1
                    else:
                        NegTTL += 1
                        if self.match_dict[name1][name2]:
                            FalseNegNum += 1

        grade = 1.0  # worst grade possible.
        if (PosTTL is not 0) and (NegTTL is not 0):
            grade = max(float(FalsePosNum) / (PosTTL),
                        float(FalseNegNum) / (NegTTL))
        elif PosTTL is not 0:
            grade = float(FalsePosNum) / (PosTTL)
        elif NegTTL is not 0:
            grade = float(FalseNegNum) / (NegTTL)
        elif NegTTL is 0 and PosTTL is 0:
            print res_dict, threshold, PosTTL, NegTTL
            print ("REDB_Lab_Result_Critical_Error_Occured: Results:" +
                   "compare_results_arr function")
        return grade

    def _compute_grade_ratio(self):
        max_fp_fn_ratio_list = \
            [self._max_fp_fn_ratio(INTERVALS_START +
                                   (float(i) * INTERVAL_JUMP)) for
             i in range(1, INTERVALS_NUM, 1)]

        min_max_fp_fn_ratio = min(max_fp_fn_ratio_list)

        self.grade = min_max_fp_fn_ratio
        grade_threshold_index = max_fp_fn_ratio_list.index(min_max_fp_fn_ratio)
        self.grade_threshold = (INTERVALS_START +
                                (float(grade_threshold_index) * INTERVAL_JUMP))

        return min_max_fp_fn_ratio

#==============================================================================
# Averages difference
#==============================================================================
    def _compute_grade_avg(self):
        res_dict = self.res_dict

        matching_pairs = 0
        sum_of_grades_for_matching_pairs = float(0)
        non_matching_pairs = 0
        sum_of_grades_for_non_matching_pairs = float(0)

        match_dict = self._get_should_be_match_dict()

        for name1 in res_dict:
            for name2 in res_dict[name1]:

                if (res_dict[name1][name2] is not -1):
                    if match_dict[name1][name2]:
                        matching_pairs += 1
                        sum_of_grades_for_matching_pairs += \
                            res_dict[name1][name2]
                    else:
                        non_matching_pairs += 1
                        sum_of_grades_for_non_matching_pairs += \
                            res_dict[name1][name2]

        if (matching_pairs == 0):
            return (float(sum_of_grades_for_non_matching_pairs) /
                    non_matching_pairs)
        elif (non_matching_pairs == 0):
            return (float(sum_of_grades_for_matching_pairs) / matching_pairs)
        else:
            return ((float(sum_of_grades_for_matching_pairs) /
                     matching_pairs) -
                    (float(sum_of_grades_for_non_matching_pairs) /
                     non_matching_pairs))
#-----------------------------------------------------------------------------

    def GetThresholdNumber(self):
        return self.grade_threshold

    def GetResDict(self):
        return self.res_dict

    def GetGraphArrays(self, N):
        """
        gets N = how many segments the x-axis of the graph will be splitted
        to. returns GoodMatches array (greens), BadMatches array (reds).
        """
        GoodMatches = [0] * N
        BadMatches = [0] * N
        for name1 in self.res_dict:
            for name2 in self.res_dict[name1]:
                if self.res_dict[name1][name2] is not -1:
                    try:
                        segment_num = min(int(N * self.res_dict[name1][name2]),
                                          N - 1)
                        if name1 == name2:
                            GoodMatches[segment_num] += 1
                        else:
                            BadMatches[segment_num] += 1
                    except Exception, e:
                        print e, (int(N * self.res_dict[name1][name2]),
                                  name1, name2, N)
        return tuple(GoodMatches), tuple(BadMatches)
