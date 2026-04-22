# Robust Model Provenance Against Poisoning in ML Supply Chains
**Java Implementation**

## Compile & Run

```bash
# 1. Compile all files
mkdir -p out
javac -d out \
  src/main/java/provenance/core/*.java \
  src/main/java/provenance/demo/SeedData.java \
  src/main/java/provenance/benchmark/Benchmark.java \
  src/main/java/provenance/api/ProvenanceAPI.java \
  src/main/java/provenance/ProvenanceSystem.java \
  src/main/java/provenance/Main.java \
  src/test/java/provenance/test/ProvenanceTest.java

# 2. Run the full demo (Steps 1–11)
java -cp out provenance.Main

# 3. Run the test suite (70+ tests)
java -cp out provenance.test.ProvenanceTest
```

## Project Structure

```
src/
├── main/java/provenance/
│   ├── core/
│   │   ├── ArtifactNode.java        Day 1: SHA-256 Merkle node
│   │   ├── ProvenanceEdge.java      Day 1: Directed weighted edge
│   │   ├── MerkleDAG.java           Day 1: Kahn's sort + Merkle chaining
│   │   ├── ReachabilityIndex.java   Day 2: DFS interval labeling + BFS fallback
│   │   ├── RiskEngine.java          Day 3: PageRank diffusion + priority queue
│   │   └── ImpactQueryEngine.java   Day 4: k-hop BFS + bidirectional BFS
│   ├── demo/
│   │   └── SeedData.java            23-node realistic ML pipeline
│   ├── benchmark/
│   │   └── Benchmark.java           Performance: 100–5000 nodes
│   ├── api/
│   │   └── ProvenanceAPI.java       REST API simulation (no external deps)
│   ├── ProvenanceSystem.java        Day 5: Unified system facade
│   └── Main.java                    Full demo runner (Steps 1–11)
└── test/java/provenance/test/
    └── ProvenanceTest.java          70+ test cases
```

## DSA Concepts → Java Classes

| DSA Concept | Class | Method |
|---|---|---|
| SHA-256 Merkle hash | `ArtifactNode` | `computeHash()` |
| Adjacency list graph | `MerkleDAG` | `children`, `parents` maps |
| Kahn's topological sort | `MerkleDAG` | `topologicalSort()` |
| Cycle detection | `MerkleDAG` | `topologicalSort()` throws `IllegalStateException` |
| DFS with timestamps | `ReachabilityIndex` | `dfsIterative()` |
| Interval labeling | `ReachabilityIndex` | `canReach()` |
| BFS fallback | `ReachabilityIndex` | `bfsCanReach()` |
| PageRank diffusion | `RiskEngine` | `pageRankDiffusion()` |
| Priority Queue (max-heap) | `RiskEngine` | `getTopRiskNodes()` — `PriorityQueue` |
| k-hop BFS | `ImpactQueryEngine` | `bfsForward()`, `bfsBackward()` |
| Bidirectional BFS | `ImpactQueryEngine` | `shortestPath()` |

## Complexity

| Operation | Time | Space |
|---|---|---|
| `topologicalSort()` | O(V + E) | O(V) |
| `computeAllHashes()` | O(V + E) | O(V) |
| `index.build()` | O(V + E) | O(V) |
| `canReach(u, v)` | O(1) amortized | — |
| `findImpacted(id)` | O(V) | O(V) |
| `shortestPath(u,v)` | O(√(V+E)) avg | O(V) |
| `propagate()` | O(V + E) per iter | O(V) |
| `getTopRiskNodes(k)` | O(N log k) | O(k) |

## API Endpoints (ProvenanceAPI.java)

```
POST /artifacts              ingestArtifact()
POST /edges                  addEdge()
POST /compromise             markCompromised()
GET  /query/impact/{id}      queryImpact()
GET  /query/ancestors/{id}   queryAncestors()
POST /query/path             queryPath()
GET  /query/reachable        queryReachable()
GET  /report/{id}            getReport()
GET  /proof/{id}             getProof()
POST /proof/verify           verifyProof()
GET  /stats                  getStats()
GET  /hashes                 getAllHashes()
```

To expose as real HTTP: wrap `ProvenanceAPI` methods in Spring Boot `@RestController`
or Javalin route handlers. All logic is already implemented.
## Interactive UI (Frontend)

We have built a fully interactive web-based UI to visualize and interact with the ML Provenance system.

### Features
- Build ML pipeline graph dynamically
- Visualize dependencies between datasets, models, tools, and products
- Simulate poisoning and observe risk propagation
- Query:
  - Impacted nodes
  - Ancestors
  - Reachability
  - Shortest path
- Generate Merkle proofs
- View performance benchmarks

---

### How to Run UI

1. Open the file:


2. Run it in any browser (Chrome recommended)

---

### UI + Backend Integration (Optional)
The UI is designed to work independently (demo mode), but can be connected to backend APIs:

- Connect to Java backend (`ProvenanceAPI.java`)
- Replace mock logic with API calls:
  - `/artifacts`
  - `/edges`
  - `/query/*`
  - `/proof/*`

---

### Screenshots

(Add screenshots here)

---

### Demo Video

(Add Google Drive / YouTube link here)

