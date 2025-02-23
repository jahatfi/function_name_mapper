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
    return_code:int
    epsilon:int=2
    rename_functions:bool=True


def show_isomorphisms_heuristic(state: Configuration):
    """
    Fuzzy match
    """
    print("-"*80)
    if not state.remaining_nodes:
        print("Found valid assignment:")
        pprint.pprint(state.mapping)
        return True

    print(f"{state.depth=} {state.epsilon=} {state.this_subgraph_node_name=} {state.successor_node_name=} remaining_nodes=")
    pprint.pprint(state.remaining_nodes)

    this_subgraph_node = state.subgraph.nodes[state.this_subgraph_node_name]
    this_subgraph_node_out_degree = state.subgraph.out_degree[state.this_subgraph_node_name]
    this_subgraph_node_in_degree = state.subgraph.in_degree[state.this_subgraph_node_name]
    candidate_graph_nodes = []
    print(f"{this_subgraph_node_out_degree=} {this_subgraph_node_in_degree=} {candidate_graph_nodes=}")
    if state.successor_node_name:
        print("successor list: "+str(list(state.whole_graph.successors(state.successor_node_name))))
    for n, v in sorted(state.whole_graph.out_degree):
        if not re.match("^(__|FUN)", n):
            continue
        if state.successor_node_name:
            if not n in state.whole_graph.successors(state.successor_node_name):
                
                continue
            #if depth == 2:
            print(f"{n:<30} # out_edges: {v} # of in edges: {state.whole_graph.in_degree[n]}")
        #print(f"{n=} {whole_graph.in_degree[n]=}")
        if abs(state.whole_graph.in_degree[n] - this_subgraph_node_in_degree) <= 1 and abs(v - this_subgraph_node_out_degree) <= state.epsilon:
            print(f"Appending {n}")
            candidate_graph_nodes.append(n)
    print(pprint.pformat(f"{candidate_graph_nodes=}"))

    if not candidate_graph_nodes:
        print(f"No clear candidates for {state.this_subgraph_node_name}; removing it from list and returning...")
        state.remaining_nodes.remove(state.this_subgraph_node_name)
        state.return_code = -1
        print("-"*80)
        return state

    # D/B FS Recursive Search
    for candidate_graph_node in candidate_graph_nodes:
        print(f"{candidate_graph_node=}")

        remaining_neighbors = set(state.subgraph.neighbors(state.this_subgraph_node_name)) - set(list(state.whole_graph.nodes))

        if not remaining_neighbors:
            print(f"Subgraph node {state.this_subgraph_node_name} has no neighbors and cannot make a reasonable guess, removing it from list and returning from {state.depth=}...")
            state.remaining_nodes.remove(state.this_subgraph_node_name)
            return

        print(f"{remaining_neighbors=}")

        new_state = deepcopy(state)
        new_state.whole_graph = nx.relabel_nodes(new_state.whole_graph, {candidate_graph_node:state.this_subgraph_node_name})
        new_state.successor_node_name = state.this_subgraph_node_name
        print(f"Assigning label \"{state.this_subgraph_node_name}\" to {candidate_graph_node}")
        state.mapping[candidate_graph_node] = state.this_subgraph_node_name

        print(state.remaining_nodes)
        try:
            new_state.remaining_nodes.remove(state.this_subgraph_node_name)
        except KeyError:
            pass
        print(f"Labels remaining: {state.remaining_nodes}")
        print(f"{state.subgraph[state.this_subgraph_node_name]=}")
        new_state.depth += 1
        #connected_nodes = list(subgraph.neighbors(this_subgraph_node_name))
        #this_subgraph_node_name = max(subgraph[this_subgraph_node_name].edges, key=lambda x: x[1])[0]



        print(f"{remaining_neighbors=}")

        new_state.this_subgraph_node_name = max(remaining_neighbors, key=lambda n: new_state.subgraph.out_degree[n])
        print(f"{new_state.this_subgraph_node_name=}")
        show_isomorphisms_heuristic(new_state)

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
                                    set(list(subgraph.nodes)) - set(list(whole_graph.nodes)),
                                    {},
                                    0,
                                    2, 
                                    True)

    show_isomorphisms_heuristic(initial_state)

if __name__ == "__main__":
    main()
