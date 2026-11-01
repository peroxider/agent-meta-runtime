"""SQLite implementation of the reconciliation persistence port.

The daemon supplies its actual Service command runner. The explicit standalone
runner supports lower-level store conformance tests; it is never selected by
the production composition root.
"""

from .composition import SetRealizedRequest, SetServingRequest, set_realized, set_serving
from .harness import fail_harness_activation, settle_harness_for_cutover
from .state import StateMigrationCutoverRequest, StateRevisionRegistration, migrate_state_cutover
from .uow import execute_command


class SqliteReconcilePersistence:
    def __init__(self, *, run_command=None):
        self._run_command = run_command

    def execute(self, conn, envelope, mutator, *, deadline):
        if self._run_command is not None:
            return self._run_command(mutator)
        result = execute_command(conn, envelope, mutator, deadline=deadline)
        if getattr(result, "error", None) is not None:
            raise result.error
        return dict(result.receipt)

    def migrate(self, txn, bindings):
        migrate_state_cutover(StateMigrationCutoverRequest(bindings=[StateRevisionRegistration(
            state_id=item["state_id"], source_revision_id=item["source_revision_id"],
            schema_id=item.get("schema_id", ""), artifact_id=item.get("artifact_id", ""),
            state_revision_id=item["state_revision_id"]) for item in bindings]))(txn)

    def set_serving(self, txn, realm_id, revision, expected_cas):
        return set_serving(SetServingRequest(realm_id, revision, expected_cas))(txn)

    def set_realized(self, txn, realm_id, revision, expected_cas):
        return set_realized(SetRealizedRequest(realm_id, revision, expected_cas))(txn)

    def settle_harness(self, txn, realm_id, composition_id):
        return settle_harness_for_cutover(realm_id, composition_id)(txn)

    def fail_activation(self, txn, composition_id, reason_code):
        return fail_harness_activation(composition_id, reason_code=reason_code)(txn)
