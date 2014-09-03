"""
Heuristics for comparing attribute instances.
"""

# standard library imports
from difflib import SequenceMatcher
import itertools

# related third party imports
import networkx as nx
import networkx.algorithms as reg_alg

MAX_GRAPH_COMP_SIZE = 120
# used for graph heuristics only.
# when we compare pair functions' graphs:
# when graph1-nodes-num * graph2-nodes-num > MAX_GRAPH_COMP_SIZE,
# the "basic-heuristic"-NormalGraphComp would not be used.
# we instead activate other comparison methods.


class Heuristic:
    """ Represents a single attribute. """
    def __init__(self, instnace_1, instance_2):
        """
        Initializes Heuristic class with two attribute instances and computes
        similarity grade with regard to the heuristic and attribute.
        """
        pass

    def ratio(self):
        """ Retrieves Results """
        pass


class ListSimilarity(Heuristic):
    """
    Grades lists similarity.
    """
    def __init__(self, list1, list2):
        self.list1 = list1
        self.list2 = list2
        self._ratio = None
        self._quick_ratio = None
        self._real_quick_ratio = None
        self.sm = SequenceMatcher(a=list1, b=list2)

    def ratio(self):
        if self._ratio == None:
            self._ratio = self.sm.ratio()
        return self._ratio


class DictionarySimilarity(Heuristic):
    """
    Grades dictionaries similarity.
    """
    def __init__(self, dict1, dict2):
        self.a_dict = dict1
        self.b_dict = dict2
        self._ratio = None

    def ratio(self):
        if (self._ratio == None):
            c_s = set(self.a_dict.keys()).union(set(self.b_dict.keys()))
            d_s = {}
            f_s = {}
            f_sum = 0
            for c in c_s:

                if (c in self.a_dict):
                    a_value = int(self.a_dict[c])
                else:
                    a_value = 0

                if (c in self.b_dict):
                    b_value = int(self.b_dict[c])
                else:
                    b_value = 0

                minimum = (float)(min(a_value, b_value))
                maximum = (float)(max(a_value, b_value))

                d_s[c] = minimum / maximum
                f_s[c] = minimum + maximum

            d_sum = sum(d_s.values())
            f_sum = sum(f_s.values())
            if (f_sum):
                self._ratio = d_sum / f_sum
            else:
                self._ratio = 0

        return self._ratio


class IntegerEquality(Heuristic):
    """
    Determines if two integers are equal.
    """
    def __init__(self, int1, int2):
        self._int1 = int1
        self._int2 = int2
        self._ratio = None

    def ratio(self):
        if self._ratio == None:
            if (self._int1 == self._int2):
                self._ratio = 1.0
            else:
                self._ratio = 0.0
        return self._ratio


class StringEquality(Heuristic):
    """
    Determines if two strings are equal.
    """
    def __init__(self, str1, str2):
        self._str1 = str1
        self._str2 = str2
        self._ratio = None

    def ratio(self):
        if self._ratio == None:
            if (self._str1 == self._str2):
                self._ratio = 1.0
            else:
                self._ratio = 0.0
        return self._ratio


class GraphCompTTL(Heuristic):
    """
    Main graph comparison heuristic. Calls other graph heuristics.
    """
    def __init__(self, graph_data1, graph_data2):
        self.normal_graph1 = graph_data1['normal_graph']
        self.compressed_graph1 = graph_data1['compressed_graph']
        self.list_graph1 = graph_data1['list_graph']

        self.normal_graph2 = graph_data2['normal_graph']
        self.compressed_graph2 = graph_data2['compressed_graph']
        self.list_graph2 = graph_data2['list_graph']

    def ratio(self):
        # 0. if the graphs are identical in their representation.
        # (not isomorphic).
        if self.normal_graph1 == self.normal_graph2:
            return 1.0

        # Stage 0 has failed, continue to next comparison:
        # 1. check for heuristic comparison for normal_graph.
        self.normal_graph1_tmp = nx.Graph(self.normal_graph1)
        self.normal_graph2_tmp = nx.Graph(self.normal_graph2)
        if (len(self.normal_graph1_tmp.nodes()) *
            len(self.normal_graph2_tmp.nodes()) <= MAX_GRAPH_COMP_SIZE):
            return NormalGraphComp(self.normal_graph1,
                                   self.normal_graph2).ratio()

        # Stage 1 has failed, continue to next comparison:
        # 2. check for heuristic comparison for compressed_graph.
        self.compressed_graph1_tmp = nx.Graph(self.compressed_graph1)
        self.compressed_graph2_tmp = nx.Graph(self.compressed_graph2)
        if (len(self.compressed_graph1_tmp.nodes()) *
            len(self.compressed_graph2_tmp.nodes()) <= MAX_GRAPH_COMP_SIZE):
            return NormalGraphComp(self.compressed_graph1,
                                   self.compressed_graph2).ratio()

        # Stage 2 has failed, continue to last comparison:
        # 3. chek for heuristic comparison for list_graph.
        else:
            return ListGraphComp(self.list_graph1, self.list_graph2).ratio()


class EqualityGraphComp(Heuristic):
    """
    Compare graphs as lists, to check if it is exactly the same-graph.
    """
    def __init__(self, graph1_data, graph2_data):
        self.graph1 = graph1_data
        self.graph2 = graph2_data

    def ratio(self):
        return (1.0 if (self.graph1 == self.graph2) else 0.0)


class NormalGraphComp(Heuristic):
    """
    Heuristic is based on algorithm described in: "Heuristics for Chemical
    Compound Matching" paper. Paper download link:
    "http://www.jsbi.org/pdfs/journal1/GIW03/GIW03F015.pdf"
    """
    # graph1 and graph2 are NetworkX graphs,
    def __init__(self, graph1_data, graph2_data):
        self.graph1 = nx.Graph(graph1_data)
        self.graph1.add_node(0)
        self.graph2 = nx.Graph(graph2_data)
        self.graph2.add_node(0)

    def ratio(self):
        # When one of the graphs has no nodes.
        if len(self.graph1.nodes()) == 0 or len(self.graph2.nodes()) == 0:
            return EqualityGraphComp(self.graph1.edges(),
                                     self.graph2.edges()).ratio()

        # Check first for heuristic comparison.
        if (len(self.graph1.nodes()) * len(self.graph2.nodes()) <=
                MAX_GRAPH_COMP_SIZE):
            return self._calcRatio()
        else:  # equality of graphs check, if comparison cant be done.
            return EqualityGraphComp(self.graph1.edges(),
                                     self.graph2.edges()).ratio()

    def _calcRatio(self):
        """
        Return grade between the two graphs this object currently owns.
        """
        MCS_Weight_Size = self._getMaxCliqueSize(self._createAG())
        return (float(MCS_Weight_Size) /
                (len(self.graph1.nodes()) +
                 len(self.graph2.nodes()) - MCS_Weight_Size))

    def _createAG(self):
        """
        Create an Association Graph from the two graphs given in the
        constructor. Each of the AG's vertices will be a pair (V1,V2), where V1
        is a vertex of graph1,and V2 is a vertex of graph2. The AG's edges are
        as described in the article.
        """
        G = nx.Graph()
        # Creating the new product graph.
        G.add_nodes_from(itertools.product(self.graph1.nodes(),
                                           self.graph2.nodes()))

        # Adding edges as expected from AG.
        for (i, s) in G.nodes():
            for (j, t) in G.nodes():
                if s != t and i != j:
                # has_edge((i,s),(j,t)) iff (has_edge(i,j) and has_edge(s,t))
                # or (!has_edge(i,j) and !has_edge(s,t)).
                    if not (self.graph1.has_edge(i, j) ^
                            self.graph2.has_edge(s, t)):
                        G.add_edge((i, s), (j, t))
        return G

    # Given an AG, compute the maximal-vertices clique's size.
    def _getMaxCliqueSize(self, graph):
        max_clique1 = reg_alg.graph_clique_number(graph)
        return (max_clique1)


class ListGraphComp(Heuristic):
    """
    Comparing ListGraph heuristic.
    A ListGraph object is actually a List of Graphs, and Graph is a list of
    edges.
    ListGraph comparison is as follows:
        1. offset=0, start comparison.
        2. grade the injection of the smaller graph into the bigger graph
             (from the offset we got in 1).
        3. goto (2), while increasing the offset until it reaches
            len(bigger_graph)-len(smaller_graph)
        4. returning maximum grade received.
    """
    def __init__(self, list_graph1, list_graph2):
        # Putting graphs in the object, graph1 is the biggest, graph2 is
        # smaller/equal.
        if (len(list_graph1) > len(list_graph2)):
            self.list_graph1 = list_graph1
            self.list_graph2 = list_graph2
        else:
            self.list_graph1 = list_graph2
            self.list_graph2 = list_graph1

        # add lists for saving nodes number for each graph in the graph list.
        # add number for saving total nodes number
        self.ttl_nodes_num = 0
        self.nodes_num_per_list_graph1 = []
        self.nodes_num_per_list_graph2 = []
        for i in range(len(self.list_graph1)):
            self.nodes_num_per_list_graph1.\
                append(self.\
                    _get_number_of_nodes_by_edges_list(self.list_graph1[i]))
            self.ttl_nodes_num += self.nodes_num_per_list_graph1[i]

        for i in range(len(self.list_graph2)):
            self.nodes_num_per_list_graph2.\
                append(self.\
                    _get_number_of_nodes_by_edges_list(self.list_graph2[i]))
            self.ttl_nodes_num += self.nodes_num_per_list_graph2[i]

    def ratio(self):
        res_list = []
        # find the maximum comparison result by graphs.
        for offset in range(0, (1 + abs(len(self.list_graph1) -
                                        len(self.list_graph2))), 1):
            res_list.append(self._ratio(offset))
        return max(res_list)

    def _ratio(self, offset):
        cur_sum = 0
        cur_weight = 0
        ttl_weights = self.ttl_nodes_num
        for i in range(len(self.list_graph2)):  # graph2 is the smallest.
            # get number of nodes for each graph in the graph_list.
            num_of_nodes1 = self.nodes_num_per_list_graph1[offset + i]
            num_of_nodes2 = self.nodes_num_per_list_graph2[i]

            # weights are total nodes size, being compared.
            cur_weight = (num_of_nodes1 + num_of_nodes2)
            g = NormalGraphComp(self.list_graph1[offset + i],
                                self.list_graph2[i])
            cur_sum += (cur_weight * float(g.ratio()))

        if ttl_weights == 0:
            return 0
        return float(float(cur_sum) / ttl_weights)

    def _get_number_of_nodes_by_edges_list(self, edges_list):
        # compute number of nodes for each graph.
        graph1_tmp = nx.Graph(edges_list)
        graph1_tmp.add_node(0)  # add root node if not exists.
        return len(graph1_tmp.nodes())
