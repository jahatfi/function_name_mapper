"""
Given a graph A and equal or smaller subgraph B,
find all subgraph isomorphisms of B as a subgraph of A.
"""


import argparse

import json
import logging
import pprint
import re
from copy import deepcopy

import networkx as nx

from dataclasses import dataclass
from typing import List, Tuple, Set, Dict
from networkx.algorithms.isomorphism import ISMAGS
import networkx.algorithms.isomorphism as iso
from networkx.algorithms.isomorphism import vf2pp_all_isomorphisms

#from networkx.algorithms.isomorphism

logging.basicConfig(level=logging.INFO)



def parse_graph_from_file(filename: str)->nx.DiGraph:
    """
    Parse the graph produced by
    the Ghidra script into a directed edge list.
    """

    G = nx.DiGraph()
    result: List[Tuple[str, str]] = []
    with open(filename, 'r', encoding='utf-8') as fp:
        whole_graph = json.load(fp)
        for entry in whole_graph:
            for caller, callees in sorted(entry.items()):
                for callee in callees:
                    if callee == caller:
                        logging.info("Skipping recursive call: %s->%s", caller, callee)
                        continue
                    result.append((caller, callee))
                    eligible_for_rename = False
                    if callee.startswith("FUN_") or callee.startswith("__"):
                        eligible_for_rename = True

                    G.add_node(callee, eligible_for_rename=eligible_for_rename)

                    eligible_for_rename = False
                    if caller.startswith("FUN_") or caller.startswith("__"):
                        eligible_for_rename = True

                    G.add_node(caller, eligible_for_rename=eligible_for_rename)
                    G.add_edge(caller, callee)
    print(f"Degrees for graph loaded from {filename}")
    for node, degree in G.out_degree:
        print(f"{node}: {degree}")
    return G


def nm(node1, node2):
    if not node1 or not node2:
        return
    print(f"Comparing {node1=} to {node2=}")
    if node2['eligible_for_rename']:
        return True
    return False

@dataclass
class Configuration:
    """
    Keeps track of current state in recursive exploration of graph configurations
    """
    whole_graph:nx.DiGraph
    subgraph:nx.DiGraph
    successor_node_name:str
    this_subgraph_node_name:str
    depth:int
    remaining_nodes:Set[str]
    mapping:Dict[str, str]
    epsilon:int=2
    rename_functions:bool=True

def show_isomorphisms_heuristic(whole_graph:nx.DiGraph,
                                subgraph:nx.DiGraph,
                                successor_node_name:str,
                                this_subgraph_node_name:str,
                                depth:int,
                                remaining_nodes:Set[str],
                                mapping:Dict[str, str],
                                epsilon:int=2,
                                rename_functions:bool=True
                                ):
    """
    Fuzzy match
    """
    print("-"*80)
    if not remaining_nodes:
        print("Found valid assignment:")
        pprint.pprint(mapping)
        return True

    print(f"{depth=} {epsilon=} {this_subgraph_node_name=} {successor_node_name=} remaining_nodes=")
    pprint.pprint(remaining_nodes)

    this_subgraph_node = subgraph.nodes[this_subgraph_node_name]
    this_subgraph_node_out_degree = subgraph.out_degree[this_subgraph_node_name]
    this_subgraph_node_in_degree = subgraph.in_degree[this_subgraph_node_name]
    candidate_graph_nodes = []
    print(f"{this_subgraph_node_out_degree=} {this_subgraph_node_in_degree=}")
    if successor_node_name:
        print("successor list: "+str(list(whole_graph.successors(successor_node_name))))
    for n, v in sorted(whole_graph.out_degree):
        if not re.match("^(__|FUN)", n):
            continue
        if successor_node_name:
            if not n in whole_graph.successors(successor_node_name):
                #print("continue 116")
                continue
            #if depth == 2:
            print(f"{n:<30} # out_edges: {v} # of in edges: {whole_graph.in_degree[n]}")
        #print(f"{n=} {whole_graph.in_degree[n]=}")
        if abs(whole_graph.in_degree[n] - this_subgraph_node_in_degree) <= 1 and abs(v - this_subgraph_node_out_degree) <= epsilon:
            candidate_graph_nodes.append(n)
    print(pprint.pformat(f"{candidate_graph_nodes=}"))

    # D/B FS Recursive Search
    for candidate_graph_node in candidate_graph_nodes:

        remaining_neighbors = set(subgraph.neighbors(this_subgraph_node_name)) - set([n for n in whole_graph.nodes])

        if not remaining_neighbors:
            print(f"Subgraph node {this_subgraph_node_name} has no neighbors and cannot make a reasonable guess, removing it from list and returning from {depth=}...")
            remaining_nodes.remove(this_subgraph_node_name)
            return


        new_whole_graph = deepcopy(whole_graph)
        new_whole_graph = nx.relabel_nodes(new_whole_graph, {candidate_graph_node:this_subgraph_node_name})
        new_successor = this_subgraph_node_name
        print(f"Assigning label \"{this_subgraph_node_name}\" to {candidate_graph_node}")
        mapping_copy = deepcopy(mapping)
        mapping[candidate_graph_node] = this_subgraph_node_name
        remaining_nodes_copy = deepcopy(remaining_nodes)
        remaining_nodes_copy.remove(this_subgraph_node_name)
        print(f"Labels remaining: {remaining_nodes_copy}")
        print(f"{subgraph[this_subgraph_node_name]=}")
        #connected_nodes = list(subgraph.neighbors(this_subgraph_node_name))
        #this_subgraph_node_name = max(subgraph[this_subgraph_node_name].edges, key=lambda x: x[1])[0]



        print(f"{remaining_neighbors=}")

        this_subgraph_node_name = max(remaining_neighbors, key=lambda n: subgraph.out_degree[n])
        print(f"{this_subgraph_node_name=}")
        if show_isomorphisms_heuristic(
            new_whole_graph,
            subgraph,
            new_successor,
            this_subgraph_node_name,
            depth+1,
            remaining_nodes_copy,
            mapping_copy,
            epsilon,
            rename_functions
        ):
            continue

    return False

def show_isomorphisms(a:nx.DiGraph, b:nx.DiGraph, rename_functions=True):
    """
    Courtesy of ChatGPT
    """
    print("*"*80)
    nm2 = iso.categorical_node_match("eligible_for_rename", True)
    print(f"{a=}")
    for node, neighbors in a.adjacency():
        print(f"{node=}:")
        pprint.pprint(neighbors, width=200)

    print(f"{b}=")
    for node, neighbors in b.adjacency():
        print(f"{node=}:")
        pprint.pprint(neighbors, width=200)

    isomatcher = nx.isomorphism.DiGraphMatcher(a, b, nm)


    for isomorph in isomatcher.subgraph_isomorphisms_iter():
        print(isomorph)

    print(f"{nx.is_isomorphic(a, b, nm)=}")# node_match=nm))
    # Create an ISMAGS instance
    print("Looking for similar graphs...")
    return
    ismags = ISMAGS(a, b)

    # Find subgraph isomorphisms
    isomorphisms = []

    for isomorphism in ismags.find_isomorphisms():
        print(isomorphism)
        isomorphisms.append(isomorphism)
    isos = []
    count = 0
    if rename_functions:
        for isomorphism in isomorphisms:
            #print(isomorphism)
            count +=1
            print(count)
            if any(x.startswith("FUN_") for x in isomorphism.keys()):
                continue
            if isomorphism:
                isos.append(isomorphism)

    else:
        isos = isomorphisms

    if isos:
        print(isos)
        print("B is a subgraph isomorphism of A. Possible mappings:")
        for mapping in isos:
            print(mapping)
        print(f"{len(mapping)=}")
    else:
        print("B is not a subgraph isomorphism of A.")
    print(f"{count=}")

def main():
    """
    Given a graph A and equal or smaller subgraph B,
    find all subgraph isomorphisms of B as a subgraph of A.
    """

    sample_whole_graph = [(0, 1), (1, 2), (2, 3), (3, 1), (2, 4)] # Contains a cycle
    sample_subgraph = [('a', 'b'), ('b', 'c'), ('c', 'a')] # Cycle structure

    print("Here's an example:")
    print(f"{sample_whole_graph=}")
    print(f"{sample_subgraph=}")

    # Create directed graph A
    A = nx.DiGraph()
    A.add_edges_from(sample_whole_graph)  # A contains a cycle

    # Create directed graph B (potential subgraph)
    B = nx.DiGraph()
    B.add_edges_from(sample_subgraph)

    show_isomorphisms(A, B, False)
    #print("Done")
    #return
    parser = argparse.ArgumentParser(
        description="Find subgraph options for subgraph B of larger graph A")
    parser.add_argument("--whole_graph",
                        "--a",
                        type=str,
                        default="example/graph_a.json",
                        help="Result of running the 'DumpCallGraph.java' Ghidra script.")
    parser.add_argument("--graph_b",
                        "--b",
                        type=str,
                        default="example/graph_b.json",
                        help="Result of running the 'dump_call_graph.sc' Joern script.")
                        default="example/subgraph.json",
                        help="The name of the json file as a result of running the 'dump_call_graph.sc' Joern script.")
    args = parser.parse_args()

    whole_graph = parse_graph_from_file(args.whole_graph)
    subgraph = parse_graph_from_file(args.subgraph)
    this_subgraph_node_name = max(subgraph.out_degree, key=lambda x: x[1])[0]


    initial_state = Configuration(  whole_graph,
                                    subgraph,
                                    "",
                                    this_subgraph_node_name, 
                                    0, 
                                    set([subgraph.nodes]) - set([n for n in whole_graph.nodes]),
                                    {},
                                    2, 
                                    True)

    show_isomorphisms_heuristic(initial_state)

if __name__ == "__main__":
    main()
