# Provider operator workflow (development checkpoint)

This procedure imports a credential and records a reviewed binding. Configured
model execution remains unavailable. No step below sends a model request.
The Runtime must already be initialized, and its current Realm Root operator
must be available in the native protected key store. Use the installed wheel's
entry points; ordinary configuration requires the Runtime daemon to be running.

On Windows, import only the token from an explicitly selected settings file:

```powershell
agent-meta-provider-credential --data-dir C:\path\to\runtime-data --from-claude-settings C:\Users\chad\.claude\settings.json.volcano
```

The file's endpoint and model are not imported. The output contains a
`credential_handle` and security profile; retain the handle for the next step.
Alternatively, `--stdin` reads token bytes from a noninteractive binary pipe.
Do not place a token in argv or use an echoing interactive terminal. Linux
supports only explicitly selected insecure fixture storage via
`--insecure-dev-credential-file`; this is not a production credential path.

Review a configuration using the installed package's Harness ID, exact model
Capability ID and declared profile ArtifactId:

```console
agent-meta --data-dir <runtime-data> --dry-run harness configure-provider <harness-id> --capability <capability-id> --profile-artifact <profile-artifact-id> --credential-handle <returned-handle>
```

The review contains the signed command and public profile/egress/pricing data.
No approval, Authority use or invocation is created. The command requires the
current Root operator, `harness.activate` on that Harness, the installation's
declared profile and current Realm/configuration revisions. Omitted revision
options are read before signing. For scripted compare-and-set workflows,
supply `--expected-configuration-revision` and `--expected-meta-revision`.

Execute the returned signed envelope through the SDK's public
`execute_command` method to commit precisely that reviewed command. Running
the CLI again without `--dry-run` prepares and validates a new command before
committing it. Any intervening revision change makes an older command stale.
`Harness.Get` exposes the resulting secretless configuration metadata.

To rotate, provision a new item with `--previous-handle <old-handle>`, then
review and commit a guarded configuration for the new handle. The old item is
retained and no binding changes during provisioning. To disable, run the same
configuration command with `--disable` and the existing binding identifiers.
Backup includes published Provider items. Restoring Windows DPAPI items does
not make them decryptable by a different Windows user.

An enabled configuration records approval only. Exact tokenizer, frozen price,
execution placement and recovery evidence are still required before a real
Provider can run. Synthetic development prices or character counts must not
be substituted for the selected real model's accounting inputs.
