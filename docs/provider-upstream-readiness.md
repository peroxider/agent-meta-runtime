# Selected upstream: readiness investigation

Investigated: 2026-11-01. Status: no upstream request made.

The operator selected an existing Volcano/Anthropic-compatible configuration.
The first intended model remains `glm-5.3-flash`. Its configured custom gateway
has not been probed; public vendor documentation does not prove that gateway's
behavior, billing, tokenization, retention or idempotency guarantees. No token,
endpoint from the private configuration or secret-derived identifier belongs in
this document.

## Confirmed documentation and resulting work

The [model author's GLM-5.3-Flash guide](https://docs.z.ai/guides/vlm/glm-5.3-flash)
documents always-enabled thinking, text output and function calling. The current
`anthropic-messages-terminal/v1` profile refuses reasoning blocks. Consequently,
that narrow codec and synthetic text/tool fixtures do not establish compatibility
with the selected model. A new explicitly versioned profile must define which
reasoning-related wire fields are accepted, which are excluded from persisted
normalized content, and how billable output is counted. Unknown block kinds and
unverified usage dimensions must still fail closed. Do not treat a thinking block
as an executable tool or save its raw contents as replay evidence by default.

Volcano documents a [Messages token-count endpoint](https://docs.volcengine.com/docs/ark/messages-count-tokens-api?lang=zh)
under its public compatible API. This is a possible investigation path, not an
installed exact local tokenizer or proof of support at the operator's gateway.
A remote count path would need separate egress/credential authorization,
bounded deterministic input binding, model/version identity, explicit accounting
semantics and failure handling before it could support a firm admission ceiling.
The existence of that endpoint does not justify using character counts.

Volcano's [public model price catalog](https://docs.volcengine.com/docs/ark/model-pricing?lang=zh&redirect=1)
and [plan billing rules](https://docs.volcengine.com/docs/ark/agent-plan-personal-afp-credits-billing-rules?lang=zh)
describe different billing contexts. Neither is adopted as the tariff of the
custom gateway. A frozen operator-reviewed pricing Artifact must state the
actual currency, effective version, input/output/cache dimensions and rounding.
Current synthetic TEST prices remain fixture-only.

## Next integration gates

1. Assemble the Root-owned configuration-aware Host path. Recheck the Task's
   frozen approval at reservation and immediately before dispatch, retain the
   approved credential scope, and independently settle original wire usage.
2. Close EffectIntent and execution-placement requirements before advertising
   a real Provider. A native owned process is not proof of a Managed sandbox.
3. Implement and test the selected model's explicit terminal reasoning/usage
   profile using clearly synthetic fixtures first. Keep that separate from R2
   captured traffic and from the existing narrow profile's compatibility claim.
4. Establish the actual gateway's exact token counting, maximum cost, protocol
   and retry/lookup contract. Missing prerequisites fail before model admission.
5. Prepare a concrete request with explicit call/cost/time limits for live
   authorization, then capture only permitted redacted normalized R2 evidence.

No paid execution, captured R2, actual gateway compatibility, support-matrix
promotion or RP-03 closure follows from this documentation investigation.
