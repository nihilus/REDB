# required to set-up constants.
import os
base_directory = r"C:\Users\CompilingUser\Desktop\Lab_TrainingSet"
os.chdir(base_directory)

# import Result processing class.
import redb_lab_results
R = redb_lab_results.ResultsProcessing

from pylab import *  # @UnusedWildImport
import json

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

functions_from_exe_1 = functions_list
functions_from_exe_2 = functions_list
N = 10

# color-constants
RED = (1, 0, 0, 1)
GREEN = (0, 1, 0, 1)
BLACK = (0, 0, 0, 1)
YELLOW = (1, 1, 0, 1)


def enter_directory(relative_directory):
        # make current-working dir, the current results dir.
        if not os.path.exists(relative_directory):
            os.makedirs(relative_directory)
        os.chdir(os.getcwd() + "\\" + relative_directory)


def up_one_directory():
        # go back from current dir.
        os.chdir(os.getcwd() + "\\..\\")

# Create the graphs using dictionary saved in the hard-disk.


def createGraphs_with_result_obj(Exe1, Exe2, R_object, filepath):
    res = R_object
    grades = (res.ComputeGrade(1), res.ComputeGrade(2))
    real_threshold = res.GetThresholdNumber()
    graph_arr = []

    for name1 in res.res_dict:
        graph_arr.append([])
        for name2 in res.res_dict[name1]:
                if (res.res_dict[name1][name2] == -1):  # no result color.
                    graph_arr[-1].append(YELLOW)
                elif ((name1 == name2) and
                      (res.res_dict[name1][name2] > real_threshold)):
                    graph_arr[-1].append(GREEN)
                elif (not(name1 == name2) and
                      (res.res_dict[name1][name2] <= real_threshold)):
                    graph_arr[-1].append(RED)
                else:  # FP/NP very bad ones.
                    graph_arr[-1].append(BLACK)
    fig2 = figure(1)
    plt.title("1. REDB: Results \n" + Exe1 + " vs " + Exe2 +
              " \nGrades by matching-type")
    imshow(graph_arr, interpolation='nearest')
    fig2.savefig(filepath + "_graph1.pdf")
    fig2.savefig(filepath + "_graph1.png")

    (GoodMatches, BadMatches) = res.GetGraphArrays(N)

    ind = np.arange(N)  # the x locations for the groups
    width = 0.35       # the width of the bars

    fig = plt.figure()
    ax = fig.add_subplot(111)
    rects1 = ax.bar(ind, BadMatches, width, color='r')
    rects2 = ax.bar(ind + width, GoodMatches, width, color='y')

    # add some
    ticks_font = \
        matplotlib.font_manager.FontProperties(family='times new roman',
                                               style='normal', size=8,
                                               weight='normal',
                                               stretch='normal')

    ax.set_ylabel('Number of functions-pairs')
    ax.set_xlabel('Grades')
    plt.title("2. REDB: Results \n" + Exe1 + " vs " + Exe2 +
              " \nGrades by matching-type")
    ax.set_xticks(ind + width)
    ax.set_xticklabels([str(float(i) / N) + "\n(Threshold)" if
                        int(N * real_threshold) == i else str(float(i) / N) for
                        i in range(N)])

    ax.legend((rects1[0], rects2[0]), ('BadMatches', 'GoodMatches'))

    fig.savefig(filepath + "_graph2.pdf")
    fig.savefig(filepath + "_graph2.png")


# create graphs, with option to read results from the dictionary,
# or an array-2d.
def createGraphs():
    for i1 in range(len(executables_list)):
        exe_name_1 = executables_list[i1]
        enter_directory(executables_list[i1])
        for j1 in range(i1 + 1, (len(executables_list)), 1):
            exe_name_2 = executables_list[j1]
            enter_directory(executables_list[j1])
            cur_dir_path = os.getcwd()
            print os.getcwd()
            print os.listdir(os.getcwd())
            for file1 in filter(lambda x: x.endswith(".dump"),
                                os.listdir(os.getcwd())):
                    print "Here1", file1
                    if (file1 + "_graph1.pdf" not in os.listdir(os.getcwd())):
                        if (file1 + "_graph2.pdf" not in
                                os.listdir(os.getcwd())):
                            fhandle = open(file1)
                            createGraphs_with_result_obj(exe_name_1,
                                                         exe_name_2,
                                        R(json.loads(fhandle.read())), file1)
                            fhandle.close()
            up_one_directory()  # go dir back.
        up_one_directory()  # go dir back.

createGraphs()
