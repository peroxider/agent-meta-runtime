"""Public mutation registry mapped to the frozen permission vocabulary."""

COMMAND_METHODS = {
    "agent_meta.public.v1.Authority.CreatePrincipal": ("authority.principal.create/v1", "authority.grant"),
    "agent_meta.public.v1.Authority.Delegate": ("authority.delegate/v1", "authority.delegate"),
    "agent_meta.public.v1.Authority.Revoke": ("authority.revoke/v1", "authority.revoke"),
    "agent_meta.public.v1.Runtime.Stop": ("runtime.stop/v1", "runtime.admin.stop"),
    "agent_meta.public.v1.Task.Submit": ("task.submit/v1", "task.submit"),
    "agent_meta.public.v1.Task.Cancel": ("task.cancel/v1", "task.cancel"),
    "agent_meta.public.v1.Artifact.Put": ("artifact.put/v1", "artifact.put"),
    "agent_meta.public.v1.Composition.Commit": ("composition.commit/v1", "composition.commit"),
    "agent_meta.public.v1.Harness.Install": ("harness.install/v1", "harness.install"),
    "agent_meta.public.v1.Harness.Activate": ("harness.activate/v1", "harness.activate"),
    "agent_meta.public.v1.Harness.ConfigureProvider": ("harness.configure-provider/v1", "harness.activate"),
    "agent_meta.public.v1.Harness.Deactivate": ("harness.deactivate/v1", "harness.deactivate"),
    "agent_meta.public.v1.Harness.Uninstall": ("harness.uninstall/v1", "harness.uninstall"),
    "agent_meta.public.v1.Evolution.Propose": ("evolution.propose/v1", "experiment.run"),
    "agent_meta.public.v1.Evolution.RunExperiment": ("experiment.run/v1", "experiment.run"),
    "agent_meta.public.v1.Evolution.Promote": ("candidate.promote/v1", "composition.promote"),
    "agent_meta.public.v1.Evolution.Rollback": ("composition.rollback/v1", "composition.rollback"),
    "agent_meta.public.v1.Operations.Backup": ("operations.backup/v1", "operations.backup"),
    "agent_meta.public.v1.Operations.GcPlan": ("operations.gc-plan/v1", "operations.gc"),
    "agent_meta.public.v1.Operations.GcApply": ("operations.gc-apply/v1", "operations.gc"),
}
COMMAND_PERMISSIONS = {payload: permission for payload, permission in COMMAND_METHODS.values()}
