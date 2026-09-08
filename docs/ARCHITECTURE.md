# Architecture review

This review describes the current source implementation. Recommendations below are proposed work, not implemented capabilities.

## System boundaries

AgentGuard has two independent application surfaces sharing a Python module directory:

1. `app.py` runs a synchronous Streamlit workflow using `AdversarialEngine`, `AgentGuardInterceptor`, and `AuditPDFGenerator`. Reports are stored in Streamlit session state.
2. `main.py` runs FastAPI, using `MCPSecurityInterceptor`, `TrajectoryGraph`, and `GeneticSemanticFuzzer` with `LiveModelAdapter`. A global dictionary stores trajectories by caller-supplied agent ID.

The API does not run tools. An integrating application must submit a proposed call, evaluate the response, and enforce its own execution policy. There is no implemented MCP client/server transport or proxy. The dashboard is not an API client and does not display the API's live trajectory stream.

## Implemented workflows

### Audit and reporting

The audit engine iterates over five static vectors. It chooses mock execution when the model name begins with `mock-` or the API key is absent; otherwise it uses synchronous LiteLLM completion. No tool definitions or agent execution loop are passed into that request. Returned text and any tool-call metadata are checked with category-specific heuristics.

Findings become typed Pydantic records. Risk is the percentage of vectors producing findings; a score of at most 20% yields `PASSED`. The PDF consumes this report directly. This is a local test outcome, despite the compliance wording currently present in the product.

### Call inspection and trajectories

The API independently inspects the proposed call and appends it to its trajectory, even when inspection blocks it. Tool-name substrings select one of SQL, file, or network inspection branches. Unmatched names receive an allowed verdict.

The graph stores a sequential list of nodes and edges between consecutive calls. Its score is `min(round(0.4 * node_weights + 0.6 * edge_weights, 2), 1.0)`. A database/file-to-network transition adds an edge weight of `0.8`. An edge weight of at least `0.7`, or cumulative risk of at least `0.7`, produces `ANOMALY_DETECTED`. This does not override the inspector's decision.

### Genetic fuzzing

The fuzzer creates an initial population, evaluates each generation with `asyncio.gather`, scores responses, retains high-scoring candidates, and constructs the next generation through mutation or crossover. Scoring uses English refusal phrases, target keywords, and formatting markers. It is not an independent evaluator of attack success.

The live adapter spaces request starts using a lock and delay, then performs provider calls outside that lock. Calls can overlap; this is not a global concurrency limiter. Rate-limit retries are handled per call. The API creates a new adapter for each fuzzing request, so pacing is not shared across requests.

## Strengths

- Small modules with clear entry points make the prototype easy to inspect.
- Pydantic models provide useful boundaries for findings and inspection results.
- A mock audit and local demonstrations support exploration without credentials.
- Per-call inspection and sequence analysis expose two distinct kinds of risk.
- The fuzzer accepts an async evaluation function, allowing alternative targets without changing mutation logic.

## Findings and recommended changes

| Priority | Finding | Recommended change |
| --- | --- | --- |
| High | Unknown tools are allowed; policies rely on substrings and incomplete argument matching. | Introduce an explicit tool registry, argument schemas, and configurable default-deny policy. Use context-aware SQL/path/network validation. |
| High | API endpoints have no authentication or tenant isolation, and fuzzing has no workload bounds. | Add authenticated ownership, positive bounded request fields, quotas, and job-level execution limits before shared deployment. |
| High | Provider errors become response text; missing dashboard credentials silently select simulation. | Model errors separately, exclude failed evaluations from security scoring, and make execution mode explicit. |
| High | UI and PDF compliance labels overstate what the finding-rate threshold measures. | Rename these to audit outcome and document the limits of the evaluation. |
| Medium | Three inspection implementations diverge; dashboard constructor policy flags are stored but not applied. | Consolidate rules and results behind one tested policy interface; enforce or remove configuration flags. |
| Medium | Trajectory storage is unbounded and process-local; blocked attempts and executed actions are indistinguishable. | Add retention limits, session ownership, persistence where needed, and explicit attempt/execution status. |
| Medium | Fuzzer retained candidates can repeat and share mutable references; evaluation counts are misleading. | Return immutable evaluation records, count actual attempts, deduplicate findings, and separate scores from verified outcomes. |
| Medium | `mutation_rate` is accepted but unused; request sizes/generation counts are not constrained. | Define mutation semantics and validate population and generation limits. |
| Medium | `test_*.py` files are demonstrations with no assertions. | Add deterministic unit cases and API contract tests, including unknown tools, error paths, and quota limits. |
| Medium | Provider identifiers are embedded in source; adapter pacing is per instance. | Centralize provider configuration and introduce a shared rate/concurrency budget. |
| Low | Earlier scanner/firewall/reporter modules are not wired into current entry points. | Consolidate or clearly mark them as experimental to reduce maintenance ambiguity. |

## Suggested implementation sequence

1. Establish reproducible dependency installation and assertion-based tests for existing behavior.
2. Unify inspection policies and define the contract between proposed calls, decisions, and execution.
3. Correct execution-mode reporting, provider error handling, and fuzzing result accounting.
4. Add API identity, bounded inputs, session retention, and workload management.
5. Align product/report terminology with measured outcomes and localize the interface.

## Review validation

Source files and entry-point imports were inspected. The supplied `venv` cannot run on this machine: its launcher refers to a Python installation under another user's directory. A fresh environment is required before claiming runtime validation. The dependency manifest lists direct dependencies and supported major-version ranges; it is not a verified lockfile. No live provider requests were made during this review.
