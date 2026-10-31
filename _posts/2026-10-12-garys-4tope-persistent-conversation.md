---
layout: post
title: "Gary's 4tope and the natural geometry of persistent conversation"
seo_title: "Gary's 4tope: The Geometry of Persistent Conversation"
date: 2026-10-12
categories: [research, ai]
tags: [garys-4tope, nl-veil, agent-memory, context-management, graph-algorithms, zig, benchmarks]
excerpt: "The formula, implementation, and reproducible benchmarks behind Gary's 4tope: protecting a dependency path and unfolding a conversation from its current step."
description: "Garrett Stimpson's engineering paper on Gary's 4tope, its NL-Veil implementation, graph benchmarks, and the question of persistent conversation."
permalink: /posts/2026/10/12/garys-4tope-persistent-conversation/
---

[Paper, reference code, and raw benchmark data on Hugging Face](https://huggingface.co/datasets/gary23w/garys-4tope) · [Download the PDF](https://huggingface.co/datasets/gary23w/garys-4tope/resolve/main/garys-4tope-paper.pdf?download=true)

## Abstract

I want a conversation to keep its working identity when a model's context window fills. Gary's 4tope approaches that problem through the structure of the work: which action produced an observation, which later action reused it, and which observations were replaced or led to a dead end. The implemented method builds a directed acyclic graph of a turn's working span. A longest weighted path identifies one critical chain to protect during pruning. A shortest-path tree rooted at the current step orders a bounded continuation assembled from existing text. The same idea appears in the tool tree, where the engine holds the catalogue and exposes a small view the model can navigate.

## Why I approached chat as a geometric problem

The thing that bothered me was watching a long task keep losing its own working shape. A file had been written. A result had ruled something out. The next action depended on a detail discovered several calls earlier. Then a boundary arrived and the engine asked a model to write a short account of what had happened. The account could sound perfectly reasonable while leaving out the detail that made the next step possible.

The October 10 release record describes a concrete version of that problem: a tools array of about 405 KB, estimated at roughly 110,000 tokens, uploaded on each call with the full security catalogue attached. A 400,000-token spend ceiling was being reached after only three or four calls. Four stretches of work were then carried forward in roughly 180-word continuations. Those figures describe an observed application workload, with both tool-advertisement cost and context policy involved. They are not a controlled evaluation of the new graph algorithm. [1]

I framed the conversation as something with structure beyond its order on the screen. An observation belongs to the action that requested it. A later action can depend on that observation. A failed attempt changes which route remains worth taking. A successful edit changes which version of a file is current. Flattening all of that into a fresh paragraph gives the writer another opportunity to change the shape.

My question was practical: can the engine preserve the relations it already knows, then show the next model call an appropriate view from where the work stands? That became Gary's 4tope. The name and geometric framing are recorded in the source on October 10, 2026. The useful engineering contribution is the combination of a protected dependency path and a source-centred continuation view, wired into a running chat engine. [2]

## What the name means geometrically

A polytope generalizes familiar shapes into higher dimensions. A four-dimensional polytope has three-dimensional facets. Its geometric net, when an unfolding is available, lives in three dimensions; a drawing of it on a page is a further projection. A cube's two-dimensional net is the simpler analogy people already recognize. [3]

The analogy I use is about adjacency and viewpoint. When a structure is too large to show whole, the choice of cut and layout determines which relations remain easy to follow. In a conversation, the important adjacency is the dependency between pieces of work. The current step is the source from which I want the next view to unfold.

There is an important boundary to that analogy. The v1.1.16 code constructs a dependency graph. It does not assign four-dimensional coordinates, define polytope facets, or calculate continuous surface geodesics. Calling its output a net describes a graph layout inspired by geometric unfolding. The four continuation headings are not evidence that the implementation is literally a four-dimensional polytope. The executable mathematics is the pair of graph recurrences below. [2]

![A dependency graph viewed through its critical path and continuation tree](/assets/4tope/graph-views.png){: width="1738" height="1100" loading="lazy"}

*Figure 1. Schematic views of the same working record. The arrows describe dependencies; this is not a coordinate embedding of a four-dimensional polytope.*

## The working record becomes a dependency graph

Let the working span be a sequence of messages, and let its graph be G=(V,E). A node records one user message, assistant step, assistant note, tool result, or engine message. The frontier f is the most recent assistant step or note. Each dependency points from a newer node to an older node. The resulting graph is acyclic, and the original message order already supplies a topological order.

The implementation builds this graph from the engine's comma-joined message representation. `Graph.fromSpan` performs the message pass, records tool-call identities, adds dependencies, and marks superseded results. It is a reader for that engine representation, rather than a general conversation-file importer. [2]

Dependencies have different origins:

| Relation | How the reference implementation recognizes it | Critical-path weight |
|---|---|---:|
| Tool result to issuing step | Matching `tool_call_id` | 1 |
| Step to a used result from the preceding round | Reuse of a distinctive token in the step's words or arguments | 2 |
| Step to another result from the preceding round | Present in that round, without a detected reuse | 0 |
| Step to preceding assistant step | The continuing sequence of actions | 1 |

Distinctive-token matching is a heuristic, not access to a model's private reasoning. The code keeps tokens between 5 and 64 characters that contain a letter, retains useful path and identifier punctuation, and filters common words. Matching is case-insensitive. A repeated identifier can provide useful evidence of reuse; it does not prove semantic dependence. A relevant fact expressed with different words can be missed.

A result can also become stale. A later identical call, or a later recognized file operation on the same path, supersedes an earlier result. Failures are identified from recognizable error text. That gives the engine a way to distinguish an established observation from a failed route, although both recognizers have limits discussed below.

## The first formula protects one critical chain

For a node v, define L(v) as the greatest cumulative dependency weight obtainable by walking backward from v. With an empty dependency set, its value is zero:

![L(v) = max of zero and L(u) + w(v,u) over dependencies u of v.](/assets/4tope/equation-1.png){: width="1459" height="118" loading="lazy"}

The engine processes nodes oldest first. Every value needed on the right is already available. It records the maximizing predecessor, then follows those predecessor links backward from f. This is the critical chain returned by `Graph.criticalChain`.

Why does this work? Any path starting at v either stops there or first visits one of its dependencies u. Its remaining best score is L(u). Taking the maximum over those choices gives the best score at v. Acyclicity makes the recurrence evaluable in one pass, with time proportional to the nodes and dependency edges. Ties in the reference code prefer the newer dependency after a predecessor has been selected.

Here is a small worked chain. A read is issued, its result is used by a later step, another result arrives, and the process continues to a frontier:

| Node | Dependency used on this path | Weight | L |
|---|---|---:|---:|
| s₀ | No older dependency | — | 0 |
| r₀ | Its issuing step s₀ | 1 | 1 |
| s₁ | Reuses result r₀ | 2 | 3 |
| r₁ | Its issuing step s₁ | 1 | 4 |
| s₂ | Reuses result r₁ | 2 | 6 |
| r₂ | Its issuing step s₂ | 1 | 7 |
| f | Reuses result r₂ | 2 | 9 |

The heavier reuse edges make this route outrank the bare step-to-step thread in this example. `protectedIds` extracts live, non-superseded tool-result identities on the selected chain. `compactWorking` passes those identities to `pruneToolResults`, which leaves those results unstubbed during that pruning attempt. [4]

The scope of the guarantee matters. This protects one maximum-weight path. It does not compute the entire transitive dependency closure, protect every relevant branch, or guarantee that a later summary fold preserves everything on the path. If the protected span still exceeds the working budget, the engine can proceed to its existing folding machinery.

## The second formula unfolds a view from the frontier

Protection and presentation answer different questions. The first recurrence asks which path deserves protection during pruning. The second asks how far each piece of the record is from the frontier when constructing a continuation.

For this view, the engine traverses the dependency graph in both directions. Let u∼ v mean the nodes are adjacent in that topology. With positive traversal costs, the shortest distance from the frontier is:

![d(f) = 0; d(v) is the minimum of d(u) + c(u,v) over adjacent u.](/assets/4tope/equation-2.png){: width="1167" height="138" loading="lazy"}

Equivalently, d(v) is the minimum sum of traversal costs over paths from f to v. Dijkstra's algorithm computes these distances and a parent for each reachable node. The shortest-path method is established graph mathematics; the particular event graph, costs, selection, and engine integration are the method being described here. [5]

The current costs are deliberately simple:

| Traversal | Base cost |
|---|---:|
| Reused result, issuing relation, or step thread | 1 |
| Merely present result | 3 |
| Additional cost to enter a superseded node | +4 |
| Additional cost to enter a failed result | +1 |

The penalty belongs to the destination node, so the topology is traversable both ways while the total cost need not be symmetric. These numbers express a policy: direct evidence should be close, a glance should be farther away, and stale or failed material should be approached with its status visible. They have not been optimized against a held-out task benchmark.

The implementation reserves space for the frontier's words and the file ledger, then considers eligible nodes by increasing distance. It skips an item that will not fit and continues to smaller candidates. Superseded results, user and engine nodes, ordinary step narration, and empty result excerpts are excluded from this selection. Notes qualify only when they look like an existing distillation.

Finally, a depth-first walk of the shortest-path tree lays out the selected established results. Failed results are rendered separately. A visited set prevents duplicate emission within the traversal. The chosen ordering gives each subtree a contiguous region of the walk, although omitted nodes and separately rendered failures mean the printed text is not a complete serialization of every dependency edge.

This is a greedy, distance-guided view under a byte allowance. It is not a proof of optimal semantic retention for that allowance. A fact can be relevant and still fall outside the selected view.

## What the next segment receives

The continuation uses four existing labels:

- **NEXT:** the frontier's current words, or a description of its last tool calls when it has no words.
- **ON DISK:** the engine's verified file ledger.
- **RULED OUT:** selected failed calls that have not been superseded.
- **ESTABLISHED:** selected live evidence in the continuation tree's order.

The release verification exercised a turn that wrote a file, read it back, attempted to read a missing specification, and crossed a spend ceiling set to 8,000 tokens. It reported this continuation, followed by the task continuing and finishing: [1]

```text
NEXT (the frontier, in its own last words): Reading the spec file missing-spec.md next.
ON DISK: notes.md (22 B)
RULED OUT (calls that failed; do not repeat them as they were):
- r3 read_file {"path": "missing-spec.md"} -> not found
ESTABLISHED (what the frontier rests on, nearest first, each derivation contiguous):
- r2 read_file {"path": "notes.md"}: 1:xuv:gij→alpha ZEBRA-7781 line
```

That verification used a scripted model on a scratch server. It demonstrates the wiring and a controlled continuation case. It does not establish reliability across real hosted models or arbitrarily long tasks. The release record also notes that the first version of the check exposed an ON DISK clipping defect, which was fixed before the release.

The text is taken from the existing record rather than written by a summarizing model. In the executable code, that means decoded, whitespace-normalized, clipped excerpts. Ordinary message excerpts are capped at 240 bytes, frontier text at 700 bytes, and tool arguments at 160 bytes; clipping can add an ellipsis. Avoiding a new paraphrase does not make those excerpts lossless copies of the full messages.

## Where it was implemented

The reference is the public `v1.1.16` tag, commit `a6b1b5d8c6e3a667e8d7436667b17ab16265fbda`. The geometric framing and tool tree were merged on October 10, after v1.1.15. Pinning this release keeps the discussion separate from subsequent application changes.

| Location | Responsibility |
|---|---|
| `src/worker/chat/net.zig` | Graph construction, critical chain, protected identities, shortest-path selection, and continuation rendering |
| `src/worker/chat/engine.zig` | Applies protection before pruning; creates the geometric handoff at engine cuts; retains summary fallbacks and banks observations |
| `src/worker/chat/belt.zig` | Tool catalogue, bounded tree views, navigation, automatic opening, and learned walk state |
| `src/worker/chat/context.zig` | Separates durable conversation storage from the bounded history supplied to a model |

Two integration points are especially important. At the engine-cut path, the engine calls `Graph.fromSpan` and `unfold` before falling back to `turnHandoff`. During working-context maintenance, `compactWorking` builds the graph and passes the protected result identities into `pruneToolResults`. [4]

The continuation allowance adapts to the replay window W, in bytes:

![H(W) = max(max(512, min(1400, floor(W/8))), min(6144, floor(W/16))).](/assets/4tope/equation-3.png){: width="1566" height="107" loading="lazy"}

The graph renderer receives H(W)-min(⌊ H(W)/4⌋,400), leaving room for the surrounding carry information. These are byte limits, not exact token counts. The language model's tokenizer determines how much inference context those bytes consume.

`NL_HANDOFF=net` is the default behavior; `NL_HANDOFF=model` selects the model-written handoff. An empty or failed geometric rendering can also use that fallback. Tool findings and engine-observed progress are banked into neuron-db at step boundaries. The memory bank is selected observations and progress, not a guarantee that every byte of every tool result has been indexed. The transcript and file state remain separate sources of continuity.

## The tool tree uses the same separation of responsibilities

A large catalogue is another structure that a model should not have to see whole on every call. In the tool tree, the engine retains the catalogue, paths, visited information, and open groups. The model sees a local view and can use `open_tools` to navigate. [6]

The reference defaults are seven displayed branches, four open groups, and a fallback search after four consecutive navigation rounds without a useful tool call. The engine can pre-open a likely group from the request. A known tool name can open its group and execute in the same round. Closing a group changes what is advertised; it does not remove a known tool from the underlying catalogue.

In v1.1.16 the tree is opt-in with `NL_TOOL_MAP=1`. The release verification reports a scripted small-model run that opened file tools before the first call, navigated with `open_tools`, automatically opened a called tool's branch, and saved its state. The same release reported reducing the security schema from roughly 366 KB to 140 KB through typed schema cleanup and alias handling, about a 61.7% reduction calculated from those rounded figures. That schema reduction is a separate optimization, not a measured consequence of the 4tope graph. [1]

The common design is useful: the engine keeps the larger structure while the model receives a bounded view appropriate to its immediate work. The tool catalogue and conversation history are different structures, and the tests for one do not validate all claims about the other.

## Reproducible implementation benchmarks

The new measurements were run on October 12, 2026 against source copied directly from the v1.1.16 Git objects. The package includes SHA-256 provenance, the unchanged modules, test output, the benchmark generator, and all 84 measured timing rows.

The machine was an AMD Ryzen 7 7800X3D, 8 cores and 16 logical processors, running Windows x86-64. The compiler was Zig 0.16.0. Tests used ReleaseSafe; timings used ReleaseFast and the monotonic awake clock. Each case received three warm-up iterations followed by 21 measured iterations. No model, network request, or neuron-db call participates in the timed algorithm.

The generator produces a linear sequence of lookup steps, each reusing the previous result's distinct identifier, followed by a frontier note. There are 2R+1 message nodes and 3R edges for R lookup rounds. This is a deliberately simple, sparse workload. It does not represent every graph shape an agent can produce.

Each measurement covers graph construction, `protectedIds`, and `unfold` with a 1,400-byte allowance. Allocations are included; deallocation, fixture generation, compilation, and process startup are outside the timed interval. The table reports the median and full observed range of that combined operation.

| Messages | Input bytes | Carry bytes | Median ms | Observed range ms |
|---:|---:|---:|---:|---:|
| 21 | 3,230 | 1,036 | 0.0177 | 0.0176–0.0182 |
| 101 | 15,870 | 1,043 | 0.1098 | 0.1005–0.1170 |
| 201 | 31,670 | 1,044 | 0.2607 | 0.2568–0.5628 |
| 501 | 79,370 | 1,051 | 1.0997 | 1.0936–1.1409 |

![Measured time for the reference graph implementation](/assets/4tope/benchmark-latency.png){: width="1686" height="769" loading="lazy"}

*Figure 2. Median combined time with the observed minimum-to-maximum range. These timings measure the graph operations on synthetic spans, not end-to-end agent quality.*

The carry stays small because it is a selected representation. That is not evidence that it preserves every fact from the larger input. In the 501-message case, 250 results belong to the protected critical chain, but the bounded handoff includes only a small portion of the available text. Protection at pruning time and inclusion in the carry are different outcomes.

The graph's critical-path pass is O(V+E). The current shortest-path implementation uses dense vertex scanning and scans incoming dependencies rather than maintaining a precomputed incoming adjacency list. A conservative bound for that implementation is O(V²+VE), which behaves quadratically when the graph remains sparse with E=O(V). The source's simple O(V²) description should be read in that sparse-span setting. The measured growth gives a reason to keep graphs bounded or improve their indexing before claiming large-scale history performance.

## Tests and observed boundaries

The original graph module passed all 4 tests. They cover dependency construction, critical-path protection, supersession and failure handling, bounded rendering on the supplied fixtures, and its readers. The belt module passed all 35 tests, comprising 14 tool-tree tests and 21 imported context tests. The new verification module passed 8 tests: the 4 imported original graph tests plus 4 additional boundary cases. Those counts should not be added as independent tests.

The boundary cases make the scope of the implementation easier to see:

| Case | Reproduced result | Consequence |
|---|---|---|
| A 100-result critical chain with a 320-byte carry | All 100 results are in the protected set; the first result's identifier is absent from the carry | Pruning protection does not guarantee that every protected fact fits in a handoff |
| A fact beyond the ordinary result excerpt | A distinct late marker is omitted | The current excerpt policy can lose a relevant fact without any model-written summary |
| A valid read followed by a failed edit on the same path | The valid earlier read is marked superseded | Current supersession tests identity and order, without requiring the replacement operation to succeed |
| A node with 65 selected sibling results and ample allowance | The renderer emits 64 evidence lines | A fixed 64-child traversal buffer limits wide tree rendering |

These checks describe the unchanged release code. They are not patches. The latter two cases identify concrete implementation behavior worth improving, and the first two show why a universal retention claim would be too strong even if the graph routines were otherwise flawless.

The v1.1.16 release record separately reports all nine gates of `scripts/check.ps1 -Full` passing and the two scripted end-to-end demonstrations. That is historical integration evidence from the release record. This paper's new local run is the smaller, reproducible module test and timing run described above. [1]

## What I mean by removing finite chats

I believe a useful assistant should let the same conversation continue as the work grows. The context window should determine the size of the current view, while durable state and retrieval preserve the larger working record. A user should not have to reconstruct the project every time that view changes.

There are two meanings of compaction that need to stay separate. Model-written summarization rewrites a record into new prose. Selecting a bounded view also reduces what is shown, even when its excerpts come from original material. Gary's 4tope removes the additional model-written continuation call when the geometric handoff succeeds. It still performs selection, and the surrounding v1.1.16 engine still performs pruning and can call `summarizeWorkingSpan` when pruning is insufficient.

A fixed-size prompt cannot encode every possible arbitrarily long history without loss. There are more possible histories than fixed-size views. An external archive and retrieval can change that engineering problem, but they do not make the prompt itself infinite or make retrieval infallible. Whether the necessary fact is stored, found, and presented remains observable behavior to test.

My claim for the released implementation is therefore concrete: it uses recorded relationships to protect a dependency path and build a continuation without an extra summarizing inference on the successful path. My larger hypothesis is that this kind of geometry can support conversations that persist across many windows with less drift and repeated work. That hypothesis needs long-run task evidence. Completely eliminating compaction requirements is not a result established by this version.

## The evaluation that should come next

The next comparison should use the same model, task, tools, carry allowance, and overall inference budget across a recent-tail baseline, a model-summary baseline, and the geometric carry. A full-transcript condition can serve as a reference on tasks where it still fits. Once the transcript exceeds the model's window, that reference needs to be described as unavailable rather than silently given a larger budget.

The tasks should require an old exact value, a changed file state, a corrected error, and dependencies across several branches. Multiple seeds and held-out tasks should report completion, exact-fact recovery, repeated tool calls, stale conclusions, total model calls, tokens, latency, and the number of context transitions. Keeping the task and cost controls visible is essential: a smaller tools schema or a larger spend ceiling can help independently of the graph.

An ablation should remove the critical-path protection, replace semantic distance with recency, and remove supersession and failed-route handling in turn. That will show which part of the combined design contributes to an improvement. Wide graphs, long messages, paraphrased identifiers, unsuccessful file mutations, and repeated boundaries belong in the failure set as well as in ordinary tests.

That is the evidence I want the method to stand on. The existing implementation and attached measurements are a starting point people can inspect and reproduce.

## Relationship to earlier work

The broader idea of continuing an agent beyond its immediate context window already has research behind it. MemGPT presents virtual context management using a hierarchy of memory tiers and movement between them. It evaluates document analysis and multi-session chat. That is relevant background for the distinction between a finite active view and longer-lived stored state. [7]

A-MEM organizes agent memories through interconnected notes, dynamic linking, and updates to existing representations. Its focus is memory organization and evolution. Gary's 4tope, as implemented here, focuses on deterministic dependency-path protection and the rendering of a particular working span at a boundary. A broader comparison would be needed before making a claim that this combination is the first of its kind. [8]

The longest-path recurrence on a DAG and Dijkstra's shortest paths are established methods. The geometric framing makes their complementary roles easier to see, while the event representation, weights, text policy, and engine integration determine what the system actually does. Those choices can be evaluated without treating the name as a proof.

## Reproducing this paper

The accompanying package contains the fixed reference modules, their MIT license, the source provenance manifest, `benchmark.zig`, `verification.zig`, and `run_benchmarks.py`. With Zig 0.16.0 installed, run:

```text
python run_benchmarks.py /path/to/zig
```

On Windows, supply the path to `zig.exe`. The script runs the module tests, compiles the timing program, and writes `benchmarks/timings.csv` and `benchmarks/results.json`. Timing values will vary across machines and operating conditions. The boundary assertions and source commit are the reproducible parts of the behavioral report.

## References

1. [NL-Veil v1.1.16 release record and scripted verification](https://github.com/gary23w/nl-veil/blob/v1.1.16/docs/release/RELEASE-v1.1.16.md).
2. [Gary's 4tope reference source in net.zig](https://github.com/gary23w/nl-veil/blob/v1.1.16/src/worker/chat/net.zig), especially graph construction, `criticalChain`, `protectedIds`, and `unfold`.
3. [Eric W. Weisstein, Polytope, Wolfram MathWorld](https://mathworld.wolfram.com/Polytope.html).
4. [NL-Veil engine handoff integration](https://github.com/gary23w/nl-veil/blob/v1.1.16/src/worker/chat/engine.zig#L3988) and [working-context protection and folding](https://github.com/gary23w/nl-veil/blob/v1.1.16/src/worker/chat/engine.zig#L13064).
5. [E. W. Dijkstra, A note on two problems in connexion with graphs, Numerische Mathematik 1, 269–271, 1959](https://doi.org/10.1007/BF01386390).
6. [Tool-tree source in belt.zig](https://github.com/gary23w/nl-veil/blob/v1.1.16/src/worker/chat/belt.zig).
7. [Charles Packer and colleagues, MemGPT: Towards LLMs as Operating Systems, 2023](https://arxiv.org/abs/2310.08560).
8. [Wujiang Xu and colleagues, A-MEM: Agentic Memory for LLM Agents, 2025](https://arxiv.org/abs/2502.12110).

## Sources

- [Paper, reference code, and raw benchmark data on Hugging Face](https://huggingface.co/datasets/gary23w/garys-4tope)
- [Download the PDF](https://huggingface.co/datasets/gary23w/garys-4tope/resolve/main/garys-4tope-paper.pdf?download=true)
- [NL-Veil v1.1.16 release record and scripted verification](https://github.com/gary23w/nl-veil/blob/v1.1.16/docs/release/RELEASE-v1.1.16.md)
- [Gary's 4tope reference source in net.zig](https://github.com/gary23w/nl-veil/blob/v1.1.16/src/worker/chat/net.zig)
- [Eric W. Weisstein, Polytope, Wolfram MathWorld](https://mathworld.wolfram.com/Polytope.html)
- [NL-Veil engine handoff integration](https://github.com/gary23w/nl-veil/blob/v1.1.16/src/worker/chat/engine.zig#L3988)
- [working-context protection and folding](https://github.com/gary23w/nl-veil/blob/v1.1.16/src/worker/chat/engine.zig#L13064)
- [E. W. Dijkstra, A note on two problems in connexion with graphs, Numerische Mathematik 1, 269–271, 1959](https://doi.org/10.1007/BF01386390)
- [Tool-tree source in belt.zig](https://github.com/gary23w/nl-veil/blob/v1.1.16/src/worker/chat/belt.zig)
- [Charles Packer and colleagues, MemGPT: Towards LLMs as Operating Systems, 2023](https://arxiv.org/abs/2310.08560)
- [Wujiang Xu and colleagues, A-MEM: Agentic Memory for LLM Agents, 2025](https://arxiv.org/abs/2502.12110)
