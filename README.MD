
### Step 1: Get Function Call Graph (FCG) from Binary with Ghidra:
   * Install Ghidra (tested on 11.2.1)
   * Strip and compile layers.c `gcc -s layers.c -o layers`  
   * import, autoanalyze, and save `layers` in Ghidra
   * Add this directory to Ghidra's script directories
   * Run the DumpCallGraph.java Ghidra script; name the output file as whole_graph.json

### Step 2: Get Function Call Graph (FCG) from Source with Joern
   * Install Joern (tested on 4.0.258): https://docs.joern.io/installation/
   * Run the DumpCallGraph.sc Joern script, eg.
   * `./joern --script dump_call_graph.sc --param cFile=/layers.c --param projectName=layers --param outFile=subgraph.json`

### Get Isomorphisms with Python's networkx Module
```bash
python -m venv .ven
source .venv/bin/activate
pip install -r requirements
python find_isomorphisms.py 
```