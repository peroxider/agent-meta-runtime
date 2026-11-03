# Vendored upstream ABI (frozen)

The files under `agentos/kernel/v1/` are verbatim copies of the frozen
`agentos.kernel.v1` ABI from the `agentos-execution-kernel` repository
(`proto/agentos/kernel/v1/`, last upstream change: commit `c9ed8ad621608c5d3b76235b3a46e283a807ecdb`).
They are the upstream contract consumed by the AgentOS execution backend
bridge (`docs/plans/agentos-execution-kernel-bridge.md`); field and enum wire
numbers are frozen upstream and must never be edited here. Regenerate the
Python modules with `scripts/generate_protos.py`.
