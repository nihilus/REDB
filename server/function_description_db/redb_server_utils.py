"""
Utilities for all the other modules.
"""
import networkx as nx


#==============================================================================
# Changing from unicode for compatibility.
#==============================================================================
def _decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for key, value in data.iteritems():
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv


#==============================================================================
# Control-Flow Graph-related utilities
#==============================================================================
def _collapse(directed_graph):
    """
    Collapse the graph, used for compressing relatively big graphs.
    For each edge = (node1,node2), if ((out-degree(node1) == 1) and
                                       (in-degree(node2) == 1)),
    remove the two nodes, node1,node2 and instead create one node,
    which represents both.
    """
    DG = nx.copy.deepcopy(directed_graph)

    kill_list = []
    for edge in DG.edges():
        if DG.out_degree(edge[0]) == 1 and DG.in_degree(edge[1]) == 1:
            kill_list.append(edge)
    while (len(kill_list) > 0):

        for edge in kill_list:
            for successor in DG.successors(edge[1]):
                DG.add_edge(edge[0], successor)
            DG.remove_node(edge[1])

            i = 0
            while(i < len(kill_list)):
                edge2 = kill_list[i]
                if edge2[0] == edge[1] or edge2[1] == edge[1]:
                    kill_list.remove(edge2)
                    i -= 1
                i += 1

            if (DG.out_degree(edge[0]) == 1 and
                DG.in_degree(DG.successors(edge[0])[0]) == 1):
                kill_list.append((edge[0], DG.successors(edge[0])[0]))
            for edge2 in kill_list:
                if DG.out_degree(edge2[0]) != 1 or DG.in_degree(edge2[1]) != 1:
                    kill_list.remove(edge2)

    return DG


def add_new_node(graph, node):
    """
    Add a new graph node to graph.
    if the node exists, create another node with name == max(graph.nodes())+1
    """
    if graph.has_node(node):
        return add_new_node(graph, max(graph.nodes()) + 1)
    else:
        graph.add_node(node)
        return node


def expand(directed_graph, s, t):
    """
    For each node, splits it to two nodes, with node for out-edges, and node
    for in-edges.
    """
    DG = nx.copy.deepcopy(directed_graph)
    for node in DG.nodes():
        if (node != s and node != t):
            if DG.out_degree(node) > 1 and DG.in_degree(node) > 1:
                new_node = add_new_node(DG, node)
                for out_edge in DG.out_edges(node):
                    DG.add_edge(new_node, out_edge[1])
                    DG.remove_edge(out_edge[0], out_edge[1])
                DG.add_edge(node, new_node)
    return DG


def get_all_zero_edges(G, s, t, topological_dict):
    """
    Get all "zero-edges" from a graph: all the edges that if we remove them,
    the graph won't be connected anymore.
    """
    if nx.min_cut(G, s, t) != 1:
        return []
    auxiliary = nx.copy.deepcopy(G)
    zero_edges = nx.bidirectional_shortest_path(auxiliary, s, t)
    zero_edges = list(zip(zero_edges[:-1], zero_edges[1:]))

    kill_list = []
    for edge in zero_edges:

        auxiliary.remove_edge(edge[0], edge[1])

        try:
            nx.bidirectional_shortest_path(auxiliary, s, t)
            print edge
            kill_list.append(edge)
        except nx.NetworkXNoPath:
            pass
        auxiliary.add_edge(edge[0], edge[1])

    for edge in kill_list:
        zero_edges.remove(edge)
    zero_edges.sort(lambda x, y: cmp(topological_dict[x[0]],
                                     topological_dict[y[0]]))
    return zero_edges


def _generate_graph_list(Graph, s):
    """
    Generates the graph list from a given graph.
    """
    #Graph = nx.DiGraph()
    # 1.10 bug fix, remove any other root node can be...
    bfsy = nx.bfs_tree(Graph, s).nodes()
    if s not in bfsy:
        bfsy.append(s)
    for i in Graph.nodes():
        if i not in bfsy:
            Graph.remove_node(i)

    G = nx.condensation(Graph)

    l = nx.topological_sort(G)
    s = l[0]
    t = l[-1]

    #clear
    # assuming node 0 is the function root node.
    bfsy = nx.bfs_tree(G, s).nodes()
    if s not in bfsy:
        bfsy.append(s)
    for i in G.nodes():
        if i not in bfsy:
            G.remove_node(i)

    D = nx.copy.deepcopy(G)
    for edge in G.edges():
        D.remove_edge(edge[0], edge[1])
        D.add_edge(edge[1], edge[0])

    # assuming node 0 is the function root node.
    print D.nodes(), D.edges(), t
    bfsy = nx.bfs_tree(D, t).nodes()
    if t not in bfsy:
        bfsy.append(t)
    for i in G.nodes():
        if i not in bfsy:
            G.remove_node(i)

    G = expand(G, s, t)
    l = nx.topological_sort(G)

    topological_dict = {}
    for i in xrange(len(l)):
        topological_dict[l[i]] = i

    for edge in G.edges():
        G.edge[edge[0]][edge[1]]['capacity'] = 1

    zero_edges = get_all_zero_edges(G, s, t, topological_dict)

    zero_len = len(zero_edges)
    pair_array = []
    graph_array = []
    if zero_len > 0:
        pair_array.append((s, zero_edges[0][0]))
        for i in xrange(zero_len - 1):
            pair_array.append((zero_edges[i][1], zero_edges[i + 1][0]))
        pair_array.append((zero_edges[-1][1], t))

        for pair in pair_array:
            auxiliary = nx.copy.deepcopy(G)
            min_num_node = topological_dict[pair[0]]
            max_num_node = topological_dict[pair[1]]

            for node in auxiliary.nodes():
                if (topological_dict[node] > max_num_node or
                    topological_dict[node] < min_num_node):
                    auxiliary.remove_node(node)

            graph_array.append(_collapse(auxiliary))

    else:
        graph_array.append(_collapse(G))

    return graph_array


def get_graph_list(edges):
    """
    Get the graph list: edges lists for each graph in their order of
    appearance order.
    """
    G = nx.DiGraph(edges)
    if not G.has_node(0):  # adding root node, on one node case.
        G.add_node(0)

    G = _collapse(G)
    num_of_nodes = len(G.nodes())

    if num_of_nodes == 1:
        return [[0]]

    lst = _generate_graph_list(G, 0)

    lst2 = []
    for grph in lst:
        lst2.append(grph.edges())

    return lst2


def get_graph_compressed(graph_data):
    """
    Getting the Compressed Graph. A Compressed Graph is a DAG, after removing
    unreachable graph nodes, and getting bfs tree.
    """
    # Creating the directed graphs, for graph1.
    dgraph = nx.DiGraph(graph_data)
    if not dgraph.has_node(0):  # adding root node, on one node case.
        dgraph.add_node(0)
    # First, remove non reachable nodes, from the root.
    # assuming node 0 is the function root node.
    bfsy = nx.bfs_tree(dgraph, 0).nodes()
    if 0 not in bfsy:
        bfsy.append(0)
    for i in dgraph.nodes():
        if i not in bfsy:
            dgraph.remove_node(i)

    # Second, _collapse some vertices together...
    dgraph = _collapse(dgraph)

    # create DAG's (computing scc) from digraph before.
    compressed_graph = nx.condensation(dgraph)

    return compressed_graph.edges()
