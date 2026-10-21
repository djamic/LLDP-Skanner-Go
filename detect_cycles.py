import re
import sys

def find_cycles():
    edges = []
    nodes = set()
    
    # Regex to parse the log line:
    # [NEW EDGE] Added connection: SRC -> DST (Label: ...)
    # [NEW EDGE] Added Hub connection: SRC -> DST (Label: ...)
    # [NEW EDGE] Added Hub-Endpoint link: SRC -> DST
    # [NEW EDGE] Added MAC endpoint link: SRC -> DST
    pattern = re.compile(r"\[NEW EDGE\].*?: (\S+) -> (\S+)")
    
    try:
        with open("debug_edges_analysis.log", "r") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    u, v = match.groups()
                    if u == v:
                        continue # Self loop
                    edges.append((u, v))
                    nodes.add(u)
                    nodes.add(v)
    except FileNotFoundError:
        print("Error: debug_edges_analysis.log not found")
        return

    print(f"Loaded {len(nodes)} nodes and {len(edges)} edges.")

    # Build adjacency list
    adj = {n: [] for n in nodes}
    for u, v in edges:
        adj[u].append(v)
        # Note: The log might only show one direction if the other was skipped as DUP.
        # But for loop detection in physical network, we usually treat as undirected graph or check for directed cycles.
        # However, the user is likely asking about L2 loops which are physical.
        # Let's treat as undirected for "structural" loops, but directed for logical flow.
        # Since the code adds edges directionally, let's start with directed detection which is stricter.
        
    # Standard DFS for cycle detection
    visited = set()
    recursion_stack = set()
    cycles = []

    def dfs(u, path):
        visited.add(u)
        recursion_stack.add(u)
        path.append(u)

        for v in adj[u]:
            if v not in visited:
                dfs(v, path)
            elif v in recursion_stack:
                # Cycle detected
                # Check cycle length
                cycle_start_index = path.index(v)
                cycle = path[cycle_start_index:]
                
                # Ignore immediate bidirectional loops (A->B->A) as they are standard links
                if len(cycle) > 2:
                    cycles.append(list(cycle))
        
        recursion_stack.remove(u)
        path.pop()

    for node in nodes:
        if node not in visited:
            dfs(node, [])

    if not cycles:
        print("No loops (cycles of length > 2) found.")
    else:
        print(f"Found {len(cycles)} potential loops:")
        for i, cycle in enumerate(cycles):
            print(f"Loop {i+1}: {' -> '.join(cycle)} -> {cycle[0]}")

if __name__ == "__main__":
    find_cycles()
