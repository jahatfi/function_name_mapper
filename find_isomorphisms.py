"""
Given a graph A and equal or smaller subgraph B,
find all subgraph isomorphisms of B as a subgraph of A.
"""


import argparse
import json
import logging
import networkx as nx

from typing import List, Tuple
from networkx.algorithms.isomorphism import ISMAGS

logging.basicConfig(level=logging.INFO)

def parse_graph_from_file(filename: str)->List[Tuple[str, str]]:
    """
    Parse the graph produced by
    the Ghidra script into a directed edge list.
    """
    result: List[Tuple[str, str]] = []
    with open(filename, 'r', encoding='utf-8') as fp:
        graph_a = json.load(fp)
        for entry in graph_a:
            for caller, callees in entry.items():
                for callee in callees:
                    result.append((caller, callee))
    return result

def show_isomorphisms(a, b):
    """
    Courtesy of ChatGPT
    """
    # Create directed graph A
    A = nx.DiGraph()
    A.add_edges_from(a)  # A contains a cycle

    # Create directed graph B (potential subgraph)
    B = nx.DiGraph()
    B.add_edges_from(b)

    # Create an ISMAGS instance
    ismags = ISMAGS(A, B)

    # Find subgraph isomorphisms
    isomorphisms = list(ismags.find_isomorphisms())

    if isomorphisms:
        print("B is a subgraph isomorphism of A. Mappings:")
        for mapping in isomorphisms:
            print(mapping)
    else:
        print("B is not a subgraph isomorphism of A.")

def main():
    """
    Given a graph A and equal or smaller subgraph B,
    find all subgraph isomorphisms of B as a subgraph of A.
    """

    sample_graph_a = [(0, 1), (1, 2), (2, 3), (3, 1), (2, 4)] # Contains a cycle
    sample_graph_b = [('a', 'b'), ('b', 'c'), ('c', 'a')] # Cycle structure
    print("Here's an example:")
    print(f"{sample_graph_a=}")
    print(f"{sample_graph_b=}")
    show_isomorphisms(sample_graph_a, sample_graph_b)

    parser = argparse.ArgumentParser(
        description="Find subgraph options for subgraph B of larger graph A")
    parser.add_argument("--graph_a",
                        "--a",
                        type=str,
                        default="example/graph_a.json",
                        help="Result of running the 'DumpCallGraph.java' Ghidra script.")
    parser.add_argument("--graph_b",
                        "--b",
                        type=str,
                        default="example/graph_b.json",
                        help="Result of running the 'dump_call_graph.sc' Joern script.")
    args = parser.parse_args()

    graph_a = parse_graph_from_file(args.graph_a)
    graph_b = parse_graph_from_file(args.graph_b)
    show_isomorphisms(graph_a, graph_b)
    return

if __name__ == "__main__":
    main()
