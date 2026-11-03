"""v0.1 authoritative SQLite DDL migration (§41.34.3).

``MIGRATION_SQL`` is the verbatim v0.1 logical DDL from the spec; the
``schema_migrations`` checksum records the SHA-256 of its UTF-8 bytes. The
schema contract test verifies the migration applies cleanly and that
``application_id``/``user_version`` match the frozen values.
"""

from __future__ import annotations

import hashlib

MIGRATION_VERSION = 1
MIGRATION_NAME = "v0_1_authoritative_ddl"

MIGRATION_SQL = """\
CREATE TABLE realms (
  realm_id TEXT PRIMARY KEY, epoch_id TEXT NOT NULL,
  next_seq INTEGER NOT NULL CHECK(next_seq >= 1),
  fact_head_hash TEXT NOT NULL,
  current_meta_revision INTEGER NOT NULL CHECK(current_meta_revision >= 0),
  created_at_us INTEGER NOT NULL
) STRICT;

CREATE TABLE epochs (
  epoch_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
  constitution_artifact_id TEXT NOT NULL, meta_root_artifact_id TEXT NOT NULL,
  authority_root_principal_id TEXT NOT NULL, fact_root_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','PRIOR','CANDIDATE')),
  created_at_us INTEGER NOT NULL, UNIQUE(realm_id, ordinal)
) STRICT;

CREATE TABLE principals (
  principal_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('OPERATOR_ROOT','AGENT','CAPABILITY','SERVICE','PEER')),
  public_identity_json BLOB NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','REVOKED','ARCHIVED')),
  created_at_us INTEGER NOT NULL, FOREIGN KEY(realm_id) REFERENCES realms(realm_id)
) STRICT;

CREATE TABLE root_recovery (
  realm_id TEXT PRIMARY KEY, active_recovery_hash TEXT NOT NULL UNIQUE,
  generation INTEGER NOT NULL CHECK(generation >= 1), created_at_us INTEGER NOT NULL,
  FOREIGN KEY(realm_id) REFERENCES realms(realm_id)
) STRICT;

CREATE TABLE root_recovery_history (
  realm_id TEXT NOT NULL, generation INTEGER NOT NULL, recovery_hash TEXT NOT NULL UNIQUE,
  used_at_us INTEGER NOT NULL, replacement_principal_id TEXT NOT NULL,
  PRIMARY KEY(realm_id, generation), FOREIGN KEY(realm_id) REFERENCES realms(realm_id)
) STRICT;

CREATE TABLE meta_revisions (
  realm_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision >= 1),
  transaction_id TEXT NOT NULL UNIQUE, command_id TEXT NOT NULL,
  committed_at_us INTEGER NOT NULL,
  PRIMARY KEY(realm_id, revision), FOREIGN KEY(realm_id) REFERENCES realms(realm_id)
) STRICT;

CREATE TABLE transactions (
  transaction_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, command_id TEXT NOT NULL,
  primary_aggregate_type TEXT NOT NULL, primary_aggregate_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('COMMITTED')),
  meta_revision INTEGER NOT NULL, committed_at_us INTEGER NOT NULL,
  UNIQUE(realm_id, meta_revision), FOREIGN KEY(realm_id) REFERENCES realms(realm_id)
) STRICT;

CREATE TABLE commands (
  command_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, payload_hash TEXT NOT NULL,
  authorization_hash TEXT NOT NULL,
  auth_nonce_hash TEXT,
  status TEXT NOT NULL CHECK(status IN ('COMMITTED','REJECTED')),
  meta_revision INTEGER NOT NULL CHECK(meta_revision >= 0),
  receipt_json BLOB, resource_json BLOB, error_json BLOB,
  created_at_us INTEGER NOT NULL, completed_at_us INTEGER NOT NULL,
  CHECK((status='COMMITTED' AND receipt_json IS NOT NULL AND error_json IS NULL)
     OR (status='REJECTED' AND receipt_json IS NULL AND error_json IS NOT NULL))
) STRICT;

CREATE TABLE artifacts (
  artifact_id TEXT PRIMARY KEY, kind TEXT NOT NULL, media_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0), schema_version INTEGER NOT NULL,
  created_by TEXT NOT NULL, created_at_us INTEGER NOT NULL,
  parents_json BLOB NOT NULL, manifest_json BLOB NOT NULL,
  integrity_status TEXT NOT NULL CHECK(integrity_status IN ('VALID','MISSING','CORRUPT'))
) STRICT;

CREATE TABLE artifact_blobs (
  blob_id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL, realm_id TEXT,
  storage_class TEXT NOT NULL CHECK(storage_class IN ('PLAIN_CAS','ENCRYPTED_RESTRICTED')),
  size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0), storage_relpath TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','QUARANTINED','MISSING','CORRUPT','DELETED')),
  created_at_us INTEGER NOT NULL, deleted_at_us INTEGER,
  FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id)
) STRICT;

CREATE TABLE artifact_encryption (
  artifact_id TEXT NOT NULL, realm_id TEXT NOT NULL, encryption_revision INTEGER NOT NULL,
  blob_id TEXT NOT NULL UNIQUE, algorithm TEXT NOT NULL,
  key_handle TEXT NOT NULL, wrapped_dek BLOB NOT NULL,
  content_nonce BLOB NOT NULL, wrap_nonce BLOB NOT NULL,
  aad_hash TEXT NOT NULL, ciphertext_hash TEXT NOT NULL, retention_until_us INTEGER,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','ROTATED','CRYPTO_ERASED')),
  created_at_us INTEGER NOT NULL, deleted_at_us INTEGER,
  PRIMARY KEY(artifact_id, realm_id, encryption_revision),
  FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id),
  FOREIGN KEY(blob_id) REFERENCES artifact_blobs(blob_id)
) STRICT;

CREATE TABLE capabilities (
  capability_id TEXT NOT NULL, descriptor_revision INTEGER NOT NULL CHECK(descriptor_revision >= 1),
  artifact_id TEXT NOT NULL, descriptor_json BLOB NOT NULL, created_at_us INTEGER NOT NULL,
  PRIMARY KEY(capability_id, descriptor_revision),
  FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id)
) STRICT;

CREATE TABLE capability_instances (
  instance_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, capability_id TEXT NOT NULL,
  descriptor_revision INTEGER NOT NULL, composition_id TEXT NOT NULL,
  placement TEXT NOT NULL, trust_class TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN
    ('DEFINED','VALIDATED','INSTANTIATING','INACTIVE','ACTIVE','DEGRADED','DRAINING','RELEASED','FAILED')),
  binding_incarnation INTEGER, created_at_us INTEGER NOT NULL, updated_at_us INTEGER NOT NULL,
  FOREIGN KEY(capability_id, descriptor_revision)
    REFERENCES capabilities(capability_id, descriptor_revision)
) STRICT;

CREATE TABLE capability_surfaces (
  realm_id TEXT NOT NULL, surface_revision INTEGER NOT NULL,
  composition_id TEXT NOT NULL, artifact_id TEXT NOT NULL,
  authority_fingerprint TEXT NOT NULL, backend_profile_hash TEXT NOT NULL,
  created_at_us INTEGER NOT NULL,
  PRIMARY KEY(realm_id, surface_revision),
  UNIQUE(realm_id, composition_id, authority_fingerprint, backend_profile_hash),
  FOREIGN KEY(composition_id) REFERENCES compositions(composition_id),
  FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id)
) STRICT;

CREATE TABLE compositions (
  composition_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, revision INTEGER NOT NULL,
  parent_id TEXT, body_json BLOB NOT NULL, body_hash TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at_us INTEGER NOT NULL,
  UNIQUE(realm_id, revision), FOREIGN KEY(parent_id) REFERENCES compositions(composition_id)
) STRICT;

CREATE TABLE harness_installations (
  harness_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL,
  package_name TEXT NOT NULL, package_version TEXT NOT NULL,
  package_artifact_id TEXT NOT NULL, manifest_artifact_id TEXT NOT NULL,
  contract_fingerprint TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('INSTALLED','ACTIVE','INACTIVE','UNINSTALLED')),
  active_composition_id TEXT, installed_by TEXT NOT NULL,
  installed_at_us INTEGER NOT NULL, updated_at_us INTEGER NOT NULL,
  CHECK((status='ACTIVE' AND active_composition_id IS NOT NULL)
     OR (status<>'ACTIVE' AND active_composition_id IS NULL)),
  UNIQUE(realm_id, package_name, package_version),
  FOREIGN KEY(realm_id) REFERENCES realms(realm_id),
  FOREIGN KEY(package_artifact_id) REFERENCES artifacts(artifact_id),
  FOREIGN KEY(manifest_artifact_id) REFERENCES artifacts(artifact_id),
  FOREIGN KEY(active_composition_id) REFERENCES compositions(composition_id)
) STRICT;

CREATE TABLE harness_installation_history (
  harness_id TEXT NOT NULL, meta_revision INTEGER NOT NULL,
  status TEXT NOT NULL, composition_id TEXT, source_fact_id TEXT NOT NULL,
  PRIMARY KEY(harness_id, meta_revision),
  FOREIGN KEY(harness_id) REFERENCES harness_installations(harness_id),
  FOREIGN KEY(composition_id) REFERENCES compositions(composition_id),
  FOREIGN KEY(source_fact_id) REFERENCES facts(fact_id)
) STRICT;

CREATE TABLE composition_refs (
  realm_id TEXT PRIMARY KEY,
  desired_revision INTEGER NOT NULL DEFAULT 0,
  serving_revision INTEGER NOT NULL DEFAULT 0,
  realized_revision INTEGER NOT NULL DEFAULT 0,
  desired_cas INTEGER NOT NULL DEFAULT 0,
  serving_cas INTEGER NOT NULL DEFAULT 0,
  realized_cas INTEGER NOT NULL DEFAULT 0,
  reconcile_status TEXT NOT NULL CHECK(reconcile_status IN
    ('PENDING','APPLYING','READY','DEGRADED','FAILED','RETRYING','ROLLED_BACK','UNKNOWN')),
  last_error_json BLOB, FOREIGN KEY(realm_id) REFERENCES realms(realm_id)
) STRICT;

CREATE TABLE composition_ref_history (
  realm_id TEXT NOT NULL, meta_revision INTEGER NOT NULL,
  desired_revision INTEGER NOT NULL, serving_revision INTEGER NOT NULL,
  realized_revision INTEGER NOT NULL, reconcile_status TEXT NOT NULL,
  source_fact_id TEXT NOT NULL,
  PRIMARY KEY(realm_id, meta_revision),
  FOREIGN KEY(source_fact_id) REFERENCES facts(fact_id)
) STRICT;

CREATE TABLE state_revisions (
  state_revision_id TEXT PRIMARY KEY, state_id TEXT NOT NULL, owner_id TEXT NOT NULL,
  schema_id TEXT NOT NULL, parent_revision_id TEXT, artifact_id TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at_us INTEGER NOT NULL,
  FOREIGN KEY(parent_revision_id) REFERENCES state_revisions(state_revision_id),
  FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id)
) STRICT;

CREATE TABLE managed_states (
  state_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, schema_id TEXT NOT NULL,
  current_revision_id TEXT NOT NULL, cas_revision INTEGER NOT NULL CHECK(cas_revision >= 1),
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','MIGRATING','DEGRADED','ARCHIVED')),
  updated_at_us INTEGER NOT NULL,
  FOREIGN KEY(current_revision_id) REFERENCES state_revisions(state_revision_id)
) STRICT;

CREATE TABLE state_ref_history (
  state_id TEXT NOT NULL, meta_revision INTEGER NOT NULL,
  state_revision_id TEXT NOT NULL, source_fact_id TEXT NOT NULL,
  PRIMARY KEY(state_id, meta_revision),
  FOREIGN KEY(state_revision_id) REFERENCES state_revisions(state_revision_id),
  FOREIGN KEY(source_fact_id) REFERENCES facts(fact_id)
) STRICT;

CREATE TABLE authority_grants (
  grant_id TEXT PRIMARY KEY, epoch_id TEXT NOT NULL, issuer_id TEXT NOT NULL,
  subject_id TEXT NOT NULL, parent_grant_id TEXT, permissions_json BLOB NOT NULL,
  scope_json BLOB NOT NULL, constraints_json BLOB NOT NULL,
  delegable INTEGER NOT NULL CHECK(delegable IN (0,1)), delegation_depth INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','REVOKED','EXPIRED')),
  issued_at_us INTEGER NOT NULL, expires_at_us INTEGER, revoked_at_us INTEGER,
  FOREIGN KEY(parent_grant_id) REFERENCES authority_grants(grant_id)
) STRICT;

CREATE TABLE authority_grant_history (
  grant_id TEXT NOT NULL, meta_revision INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','REVOKED','EXPIRED')),
  effective_at_us INTEGER NOT NULL, source_fact_id TEXT NOT NULL,
  PRIMARY KEY(grant_id, meta_revision),
  FOREIGN KEY(grant_id) REFERENCES authority_grants(grant_id),
  FOREIGN KEY(source_fact_id) REFERENCES facts(fact_id)
) STRICT;

CREATE TABLE authority_uses (
  grant_id TEXT NOT NULL, action_id TEXT NOT NULL, use_kind TEXT NOT NULL,
  amount_json BLOB NOT NULL, meta_revision INTEGER NOT NULL, used_at_us INTEGER NOT NULL,
  PRIMARY KEY(grant_id, action_id, use_kind),
  FOREIGN KEY(grant_id) REFERENCES authority_grants(grant_id)
) STRICT;

CREATE TABLE tasks (
  task_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, actor_id TEXT NOT NULL,
  authority_grant_id TEXT, input_artifact_id TEXT NOT NULL,
  serving_composition_id TEXT NOT NULL, serving_revision INTEGER NOT NULL,
  capability_surface_revision INTEGER NOT NULL, capability_surface_artifact_id TEXT NOT NULL,
  state_snapshot_json BLOB NOT NULL, budget_json BLOB NOT NULL,
  consumed_budget_json BLOB NOT NULL, root_action_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK(status IN
    ('ACCEPTED','RUNNING','SUCCEEDED','FAILED','FAILED_RECOVERY','TIMED_OUT','CANCELLED')),
  accepted_at_us INTEGER NOT NULL, started_at_us INTEGER, deadline_at_us INTEGER,
  completed_at_us INTEGER, result_artifact_id TEXT, error_json BLOB,
  FOREIGN KEY(input_artifact_id) REFERENCES artifacts(artifact_id),
  FOREIGN KEY(serving_composition_id) REFERENCES compositions(composition_id),
  FOREIGN KEY(realm_id, capability_surface_revision)
    REFERENCES capability_surfaces(realm_id, surface_revision),
  FOREIGN KEY(capability_surface_artifact_id) REFERENCES artifacts(artifact_id)
) STRICT;

CREATE TABLE task_budget_adjustments (
  task_id TEXT NOT NULL, ordinal INTEGER NOT NULL, delta_json BLOB NOT NULL,
  grant_id TEXT NOT NULL, action_id TEXT NOT NULL, created_at_us INTEGER NOT NULL,
  PRIMARY KEY(task_id, ordinal), FOREIGN KEY(task_id) REFERENCES tasks(task_id)
) STRICT;

CREATE TABLE actions (
  action_id TEXT PRIMARY KEY, task_id TEXT, actor_id TEXT NOT NULL, intent TEXT NOT NULL,
  composition_id TEXT NOT NULL, grant_id TEXT, causal_parent_action_id TEXT,
  status TEXT NOT NULL CHECK(status IN ('CREATED','RUNNING','SUCCEEDED','FAILED','TIMED_OUT','CANCELLED')),
  budget_json BLOB NOT NULL, consumed_budget_json BLOB NOT NULL,
  created_at_us INTEGER NOT NULL, started_at_us INTEGER, completed_at_us INTEGER,
  error_json BLOB, FOREIGN KEY(task_id) REFERENCES tasks(task_id),
  FOREIGN KEY(causal_parent_action_id) REFERENCES actions(action_id)
) STRICT;

CREATE TABLE effect_intents (
  effect_intent_id TEXT PRIMARY KEY, action_id TEXT NOT NULL, kind TEXT NOT NULL,
  target_scope_json BLOB NOT NULL, payload_artifact_id TEXT,
  idempotency_class TEXT NOT NULL, reversibility TEXT NOT NULL,
  required_permissions_json BLOB NOT NULL, required_features_json BLOB NOT NULL,
  reservation_json BLOB NOT NULL, request_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK(status IN
    ('VALIDATED','RESERVED','DISPATCHED','SUCCEEDED','FAILED','UNKNOWN','COMPENSATED')),
  created_at_us INTEGER NOT NULL, completed_at_us INTEGER,
  FOREIGN KEY(action_id) REFERENCES actions(action_id)
) STRICT;

CREATE TABLE invocations (
  invocation_id TEXT PRIMARY KEY, action_id TEXT NOT NULL, kind TEXT NOT NULL,
  target TEXT NOT NULL, attempt INTEGER NOT NULL CHECK(attempt >= 1),
  input_artifact_id TEXT NOT NULL, context_projection_id TEXT,
  backend_ref_json BLOB, status TEXT NOT NULL CHECK(status IN
    ('CREATED','DISPATCHED','RUNNING','SUCCEEDED','FAILED','TIMED_OUT','CANCELLED')),
  started_at_us INTEGER, completed_at_us INTEGER, output_artifact_id TEXT, error_json BLOB,
  usage_json BLOB NOT NULL, latency_us INTEGER,
  CHECK(NOT(output_artifact_id IS NOT NULL AND error_json IS NOT NULL)),
  FOREIGN KEY(action_id) REFERENCES actions(action_id)
) STRICT;

CREATE TABLE facts (
  fact_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, seq INTEGER NOT NULL,
  occurred_at_us INTEGER NOT NULL, recorded_at_us INTEGER NOT NULL,
  actor_id TEXT NOT NULL, action_id TEXT, transaction_id TEXT,
  entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, event_type TEXT NOT NULL,
  schema_version INTEGER NOT NULL, payload_json BLOB NOT NULL, payload_hash TEXT NOT NULL,
  prev_fact_hash TEXT NOT NULL, fact_hash TEXT NOT NULL UNIQUE,
  UNIQUE(realm_id, seq), FOREIGN KEY(realm_id) REFERENCES realms(realm_id)
) STRICT;

CREATE TABLE causal_edges (
  realm_id TEXT NOT NULL, from_id TEXT NOT NULL, edge_type TEXT NOT NULL,
  to_id TEXT NOT NULL, source_fact_id TEXT NOT NULL,
  PRIMARY KEY(realm_id, from_id, edge_type, to_id),
  FOREIGN KEY(source_fact_id) REFERENCES facts(fact_id)
) STRICT;

CREATE TABLE outbox (
  outbox_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, kind TEXT NOT NULL,
  dedupe_key TEXT NOT NULL UNIQUE, payload_json BLOB NOT NULL, payload_hash TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('PENDING','LEASED','DELIVERED','DEAD_LETTER')),
  available_at_us INTEGER NOT NULL, lease_owner TEXT, lease_expires_at_us INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0, last_error_json BLOB,
  created_at_us INTEGER NOT NULL, delivered_at_us INTEGER
) STRICT;

CREATE TABLE operations (
  operation_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, kind TEXT NOT NULL,
  command_id TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN
    ('ACCEPTED','RUNNING','SUCCEEDED','FAILED','FAILED_RECOVERY','CANCELLED')),
  request_json BLOB NOT NULL, result_json BLOB, error_json BLOB,
  created_at_us INTEGER NOT NULL, started_at_us INTEGER, completed_at_us INTEGER,
  CHECK(NOT(result_json IS NOT NULL AND error_json IS NOT NULL))
) STRICT;

CREATE TABLE workspaces (
  workspace_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, owner_entity_id TEXT NOT NULL,
  root_relpath TEXT NOT NULL UNIQUE, quota_bytes INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE','QUARANTINED','RELEASING','RELEASED')),
  created_at_us INTEGER NOT NULL, expires_at_us INTEGER, released_at_us INTEGER
) STRICT;

CREATE TABLE execution_bindings (
  backend_id TEXT NOT NULL, semantic_id TEXT NOT NULL, incarnation INTEGER NOT NULL,
  request_id TEXT NOT NULL, payload_hash TEXT NOT NULL, handle_bytes BLOB NOT NULL,
  session_id TEXT NOT NULL, status TEXT NOT NULL, expires_at_us INTEGER,
  last_observed_at_us INTEGER NOT NULL,
  PRIMARY KEY(backend_id, semantic_id, incarnation), UNIQUE(backend_id, request_id)
) STRICT;

CREATE TABLE checkpoints (
  realm_id TEXT NOT NULL, projection TEXT NOT NULL, seq INTEGER NOT NULL,
  updated_at_us INTEGER NOT NULL, PRIMARY KEY(realm_id, projection)
) STRICT;

CREATE TABLE context_projections (
  projection_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, action_id TEXT NOT NULL,
  policy_artifact_id TEXT NOT NULL, composition_id TEXT NOT NULL,
  meta_revision INTEGER NOT NULL, manifest_json BLOB NOT NULL,
  rendered_artifact_id TEXT NOT NULL, created_at_us INTEGER NOT NULL
) STRICT;

CREATE TABLE scratch_sessions (
  session_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, owner_principal_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('STARTING','ACTIVE','LOST','RELEASING','RELEASED','FAILED')),
  workspace_id TEXT NOT NULL, backend_request_id TEXT NOT NULL UNIQUE,
  idle_expires_at_us INTEGER NOT NULL, wall_expires_at_us INTEGER NOT NULL,
  last_activity_at_us INTEGER NOT NULL, created_at_us INTEGER NOT NULL, updated_at_us INTEGER NOT NULL
) STRICT;

CREATE TABLE scratch_bindings (
  session_id TEXT NOT NULL, binding_name TEXT NOT NULL, generation INTEGER NOT NULL,
  type_module TEXT NOT NULL, type_name TEXT NOT NULL, source_artifact_id TEXT NOT NULL,
  last_cell_action_id TEXT NOT NULL, observed_handle_hash TEXT,
  status TEXT NOT NULL CHECK(status IN ('LIVE','EXPIRED','EXPORTED','RELEASED')),
  metadata_json BLOB NOT NULL,
  PRIMARY KEY(session_id, binding_name, generation),
  FOREIGN KEY(session_id) REFERENCES scratch_sessions(session_id)
) STRICT;

CREATE TABLE worlds (
  world_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, backend_profile_hash TEXT NOT NULL,
  body_json BLOB NOT NULL, body_hash TEXT NOT NULL, created_at_us INTEGER NOT NULL
) STRICT;

CREATE TABLE evolution_objects (
  object_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL,
  object_type TEXT NOT NULL CHECK(object_type IN ('PROPOSAL','CHANGE_SET','CANDIDATE')),
  parent_id TEXT, body_json BLOB NOT NULL, status TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at_us INTEGER NOT NULL
) STRICT;

CREATE TABLE experiments (
  experiment_id TEXT PRIMARY KEY, realm_id TEXT NOT NULL, candidate_id TEXT NOT NULL,
  baseline_id TEXT NOT NULL, world_id TEXT NOT NULL, criteria_artifact_id TEXT NOT NULL,
  budget_json BLOB NOT NULL, status TEXT NOT NULL, body_json BLOB NOT NULL,
  created_at_us INTEGER NOT NULL, completed_at_us INTEGER
) STRICT;

CREATE TABLE evidence (
  evidence_id TEXT PRIMARY KEY, experiment_id TEXT, producer_action_id TEXT NOT NULL,
  kind TEXT NOT NULL, subject_id TEXT NOT NULL, artifact_id TEXT NOT NULL,
  world_id TEXT, observed_at_us INTEGER NOT NULL, metadata_json BLOB NOT NULL,
  FOREIGN KEY(experiment_id) REFERENCES experiments(experiment_id),
  FOREIGN KEY(producer_action_id) REFERENCES actions(action_id),
  FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id),
  FOREIGN KEY(world_id) REFERENCES worlds(world_id)
) STRICT;

CREATE TABLE evaluations (
  evaluation_id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL,
  evaluator_artifact_id TEXT NOT NULL, evidence_ids_json BLOB NOT NULL,
  result_artifact_id TEXT NOT NULL, decision TEXT NOT NULL CHECK(decision IN ('ACCEPT','REJECT')),
  created_at_us INTEGER NOT NULL, FOREIGN KEY(experiment_id) REFERENCES experiments(experiment_id)
) STRICT;

CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, checksum TEXT NOT NULL,
  applied_at_us INTEGER NOT NULL, runtime_version TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX uq_artifact_encryption_active
ON artifact_encryption(artifact_id, realm_id) WHERE status='ACTIVE';
CREATE UNIQUE INDEX uq_artifact_plain_blob
ON artifact_blobs(artifact_id) WHERE storage_class='PLAIN_CAS' AND status='ACTIVE';
CREATE UNIQUE INDEX uq_epoch_active
ON epochs(realm_id) WHERE status='ACTIVE';
CREATE UNIQUE INDEX uq_command_auth_nonce
ON commands(realm_id, auth_nonce_hash) WHERE auth_nonce_hash IS NOT NULL;
CREATE INDEX ix_fact_entity ON facts(realm_id, entity_type, entity_id, seq);
CREATE INDEX ix_fact_action ON facts(action_id, seq);
CREATE INDEX ix_fact_transaction ON facts(transaction_id, seq);
CREATE INDEX ix_task_queue ON tasks(realm_id, status, accepted_at_us, task_id);
CREATE INDEX ix_action_task ON actions(task_id, created_at_us);
CREATE INDEX ix_invocation_action ON invocations(action_id, started_at_us);
CREATE INDEX ix_edge_to ON causal_edges(realm_id, to_id, edge_type);
CREATE INDEX ix_outbox_dispatch ON outbox(state, available_at_us, lease_expires_at_us);
CREATE INDEX ix_binding_request ON execution_bindings(backend_id, request_id);
CREATE INDEX ix_harness_status ON harness_installations(realm_id, status, package_name);
CREATE INDEX ix_harness_history ON harness_installation_history(harness_id, meta_revision DESC);
CREATE INDEX ix_comp_ref_history ON composition_ref_history(realm_id, meta_revision DESC);
CREATE INDEX ix_state_ref_history ON state_ref_history(state_id, meta_revision DESC);
CREATE INDEX ix_evidence_experiment ON evidence(experiment_id, observed_at_us);
CREATE INDEX ix_operation_status ON operations(realm_id, status, created_at_us);
CREATE INDEX ix_workspace_status ON workspaces(realm_id, status, expires_at_us);

CREATE TRIGGER facts_no_update BEFORE UPDATE ON facts BEGIN
  SELECT RAISE(ABORT, 'FACT_APPEND_ONLY');
END;
CREATE TRIGGER facts_no_delete BEFORE DELETE ON facts BEGIN
  SELECT RAISE(ABORT, 'FACT_APPEND_ONLY');
END;
CREATE TRIGGER compositions_no_update BEFORE UPDATE ON compositions BEGIN
  SELECT RAISE(ABORT, 'COMPOSITION_IMMUTABLE');
END;
CREATE TRIGGER compositions_no_delete BEFORE DELETE ON compositions BEGIN
  SELECT RAISE(ABORT, 'COMPOSITION_IMMUTABLE');
END;
CREATE TRIGGER state_revisions_no_update BEFORE UPDATE ON state_revisions BEGIN
  SELECT RAISE(ABORT, 'STATE_REVISION_IMMUTABLE');
END;
CREATE TRIGGER state_revisions_no_delete BEFORE DELETE ON state_revisions BEGIN
  SELECT RAISE(ABORT, 'STATE_REVISION_IMMUTABLE');
END;
CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence BEGIN
  SELECT RAISE(ABORT, 'EVIDENCE_IMMUTABLE');
END;
CREATE TRIGGER evidence_no_delete BEFORE DELETE ON evidence BEGIN
  SELECT RAISE(ABORT, 'EVIDENCE_IMMUTABLE');
END;
CREATE TRIGGER evaluations_no_update BEFORE UPDATE ON evaluations BEGIN
  SELECT RAISE(ABORT, 'EVALUATION_IMMUTABLE');
END;
CREATE TRIGGER evaluations_no_delete BEFORE DELETE ON evaluations BEGIN
  SELECT RAISE(ABORT, 'EVALUATION_IMMUTABLE');
END;
CREATE TRIGGER capabilities_no_update BEFORE UPDATE ON capabilities BEGIN
  SELECT RAISE(ABORT, 'CAPABILITY_REVISION_IMMUTABLE');
END;
CREATE TRIGGER capabilities_no_delete BEFORE DELETE ON capabilities BEGIN
  SELECT RAISE(ABORT, 'CAPABILITY_REVISION_IMMUTABLE');
END;
CREATE TRIGGER harness_identity_immutable BEFORE UPDATE ON harness_installations
WHEN OLD.harness_id IS NOT NEW.harness_id OR OLD.realm_id IS NOT NEW.realm_id
  OR OLD.package_name IS NOT NEW.package_name OR OLD.package_version IS NOT NEW.package_version
  OR OLD.package_artifact_id IS NOT NEW.package_artifact_id
  OR OLD.manifest_artifact_id IS NOT NEW.manifest_artifact_id
  OR OLD.contract_fingerprint IS NOT NEW.contract_fingerprint
  OR OLD.installed_by IS NOT NEW.installed_by OR OLD.installed_at_us IS NOT NEW.installed_at_us
BEGIN SELECT RAISE(ABORT, 'HARNESS_IDENTITY_IMMUTABLE'); END;
CREATE TRIGGER harness_uninstalled_terminal BEFORE UPDATE ON harness_installations
WHEN OLD.status='UNINSTALLED' AND NEW.status IS NOT OLD.status
BEGIN SELECT RAISE(ABORT, 'HARNESS_UNINSTALLED_TERMINAL'); END;
CREATE TRIGGER harness_status_transition BEFORE UPDATE OF status ON harness_installations
WHEN NOT (
  OLD.status=NEW.status
  OR (OLD.status='INSTALLED' AND NEW.status IN ('ACTIVE','UNINSTALLED'))
  OR (OLD.status='INACTIVE' AND NEW.status IN ('ACTIVE','UNINSTALLED'))
  OR (OLD.status='ACTIVE' AND NEW.status='INACTIVE')
)
BEGIN SELECT RAISE(ABORT, 'INVALID_HARNESS_STATUS_TRANSITION'); END;
CREATE TRIGGER harness_no_delete BEFORE DELETE ON harness_installations BEGIN
  SELECT RAISE(ABORT, 'HARNESS_HISTORY_REQUIRED');
END;
CREATE TRIGGER harness_history_no_update BEFORE UPDATE ON harness_installation_history BEGIN
  SELECT RAISE(ABORT, 'HARNESS_HISTORY_IMMUTABLE');
END;
CREATE TRIGGER harness_history_no_delete BEFORE DELETE ON harness_installation_history BEGIN
  SELECT RAISE(ABORT, 'HARNESS_HISTORY_IMMUTABLE');
END;
CREATE TRIGGER worlds_no_update BEFORE UPDATE ON worlds BEGIN
  SELECT RAISE(ABORT, 'WORLD_IMMUTABLE');
END;
CREATE TRIGGER worlds_no_delete BEFORE DELETE ON worlds BEGIN
  SELECT RAISE(ABORT, 'WORLD_IMMUTABLE');
END;
CREATE TRIGGER artifacts_identity_immutable BEFORE UPDATE ON artifacts
WHEN OLD.artifact_id IS NOT NEW.artifact_id OR OLD.kind IS NOT NEW.kind
  OR OLD.media_type IS NOT NEW.media_type OR OLD.size_bytes IS NOT NEW.size_bytes
  OR OLD.schema_version IS NOT NEW.schema_version OR OLD.created_by IS NOT NEW.created_by
  OR OLD.created_at_us IS NOT NEW.created_at_us OR OLD.parents_json IS NOT NEW.parents_json
  OR OLD.manifest_json IS NOT NEW.manifest_json
BEGIN SELECT RAISE(ABORT, 'ARTIFACT_IDENTITY_IMMUTABLE'); END;
CREATE TRIGGER artifacts_no_delete BEFORE DELETE ON artifacts BEGIN
  SELECT RAISE(ABORT, 'ARTIFACT_MANIFEST_IMMUTABLE');
END;
CREATE TRIGGER authority_grant_definition_immutable BEFORE UPDATE ON authority_grants
WHEN OLD.grant_id IS NOT NEW.grant_id OR OLD.epoch_id IS NOT NEW.epoch_id
  OR OLD.issuer_id IS NOT NEW.issuer_id OR OLD.subject_id IS NOT NEW.subject_id
  OR OLD.parent_grant_id IS NOT NEW.parent_grant_id
  OR OLD.permissions_json IS NOT NEW.permissions_json OR OLD.scope_json IS NOT NEW.scope_json
  OR OLD.constraints_json IS NOT NEW.constraints_json OR OLD.delegable IS NOT NEW.delegable
  OR OLD.delegation_depth IS NOT NEW.delegation_depth OR OLD.issued_at_us IS NOT NEW.issued_at_us
  OR OLD.expires_at_us IS NOT NEW.expires_at_us
BEGIN SELECT RAISE(ABORT, 'GRANT_DEFINITION_IMMUTABLE'); END;
CREATE TRIGGER task_frozen_fields_immutable BEFORE UPDATE ON tasks
WHEN OLD.realm_id IS NOT NEW.realm_id OR OLD.actor_id IS NOT NEW.actor_id
  OR OLD.authority_grant_id IS NOT NEW.authority_grant_id
  OR OLD.input_artifact_id IS NOT NEW.input_artifact_id
  OR OLD.serving_composition_id IS NOT NEW.serving_composition_id
  OR OLD.serving_revision IS NOT NEW.serving_revision
  OR OLD.capability_surface_revision IS NOT NEW.capability_surface_revision
  OR OLD.capability_surface_artifact_id IS NOT NEW.capability_surface_artifact_id
  OR OLD.state_snapshot_json IS NOT NEW.state_snapshot_json
  OR OLD.budget_json IS NOT NEW.budget_json OR OLD.root_action_id IS NOT NEW.root_action_id
  OR OLD.accepted_at_us IS NOT NEW.accepted_at_us OR OLD.deadline_at_us IS NOT NEW.deadline_at_us
BEGIN SELECT RAISE(ABORT, 'TASK_FROZEN_FIELDS_IMMUTABLE'); END;
CREATE TRIGGER action_identity_immutable BEFORE UPDATE ON actions
WHEN OLD.task_id IS NOT NEW.task_id OR OLD.actor_id IS NOT NEW.actor_id
  OR OLD.intent IS NOT NEW.intent OR OLD.composition_id IS NOT NEW.composition_id
  OR OLD.grant_id IS NOT NEW.grant_id OR OLD.causal_parent_action_id IS NOT NEW.causal_parent_action_id
  OR OLD.budget_json IS NOT NEW.budget_json OR OLD.created_at_us IS NOT NEW.created_at_us
BEGIN SELECT RAISE(ABORT, 'ACTION_IDENTITY_IMMUTABLE'); END;
CREATE TRIGGER invocation_identity_immutable BEFORE UPDATE ON invocations
WHEN OLD.action_id IS NOT NEW.action_id OR OLD.kind IS NOT NEW.kind
  OR OLD.target IS NOT NEW.target OR OLD.attempt IS NOT NEW.attempt
  OR OLD.input_artifact_id IS NOT NEW.input_artifact_id
  OR OLD.context_projection_id IS NOT NEW.context_projection_id
BEGIN SELECT RAISE(ABORT, 'INVOCATION_IDENTITY_IMMUTABLE'); END;
CREATE TRIGGER effect_intent_identity_immutable BEFORE UPDATE ON effect_intents
WHEN OLD.action_id IS NOT NEW.action_id OR OLD.kind IS NOT NEW.kind
  OR OLD.target_scope_json IS NOT NEW.target_scope_json
  OR OLD.payload_artifact_id IS NOT NEW.payload_artifact_id
  OR OLD.idempotency_class IS NOT NEW.idempotency_class
  OR OLD.reversibility IS NOT NEW.reversibility
  OR OLD.required_permissions_json IS NOT NEW.required_permissions_json
  OR OLD.required_features_json IS NOT NEW.required_features_json
  OR OLD.reservation_json IS NOT NEW.reservation_json OR OLD.request_id IS NOT NEW.request_id
BEGIN SELECT RAISE(ABORT, 'EFFECT_INTENT_IMMUTABLE'); END;
CREATE TRIGGER experiment_frozen_fields_immutable BEFORE UPDATE ON experiments
WHEN OLD.candidate_id IS NOT NEW.candidate_id OR OLD.baseline_id IS NOT NEW.baseline_id
  OR OLD.world_id IS NOT NEW.world_id OR OLD.criteria_artifact_id IS NOT NEW.criteria_artifact_id
  OR OLD.budget_json IS NOT NEW.budget_json OR OLD.created_at_us IS NOT NEW.created_at_us
BEGIN SELECT RAISE(ABORT, 'EXPERIMENT_FROZEN_FIELDS_IMMUTABLE'); END;
CREATE TRIGGER task_terminal_immutable BEFORE UPDATE ON tasks
WHEN OLD.status IN ('SUCCEEDED','FAILED','FAILED_RECOVERY','TIMED_OUT','CANCELLED')
  AND NEW.status IS NOT OLD.status
BEGIN SELECT RAISE(ABORT, 'TASK_TERMINAL_IMMUTABLE'); END;
CREATE TRIGGER action_terminal_immutable BEFORE UPDATE ON actions
WHEN OLD.status IN ('SUCCEEDED','FAILED','TIMED_OUT','CANCELLED') AND NEW.status IS NOT OLD.status
BEGIN SELECT RAISE(ABORT, 'ACTION_TERMINAL_IMMUTABLE'); END;
CREATE TRIGGER invocation_terminal_immutable BEFORE UPDATE ON invocations
WHEN OLD.status IN ('SUCCEEDED','FAILED','TIMED_OUT','CANCELLED') AND NEW.status IS NOT OLD.status
BEGIN SELECT RAISE(ABORT, 'INVOCATION_TERMINAL_IMMUTABLE'); END;
CREATE TRIGGER operation_terminal_immutable BEFORE UPDATE ON operations
WHEN OLD.status IN ('SUCCEEDED','FAILED','FAILED_RECOVERY','CANCELLED') AND NEW.status IS NOT OLD.status
BEGIN SELECT RAISE(ABORT, 'OPERATION_TERMINAL_IMMUTABLE'); END;
"""

MIGRATION_CHECKSUM = hashlib.sha256(MIGRATION_SQL.encode("utf-8")).hexdigest()
