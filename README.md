# GitHub credential rotation audit

A value-safe inventory tool for finding credential references across GitHub repositories where the authenticated user has `maintain` or `admin` access.

The auditor combines:

- GitHub secret metadata: names and timestamps only; GitHub never returns secret values.
- Current source snapshots: environment-variable, workflow-secret, and configuration references.
- Rotation notes: repository settings links and provider-side credential-management links.
- Coverage notes: repositories and organization secret stores that could not be inspected.

## Safety properties

- Secret values are never written to the report, JSON, CSV, or console.
- Generated inventories are ignored by Git so repository names and private findings are not committed accidentally.
- Known credential formats are detected only to flag their locations; detected values are omitted.
- Temporary repository snapshots are created outside the project directory.

Always review generated findings before sharing them. An inventory can reveal private repository names, secret names, infrastructure details, and source locations even though it contains no secret values.

## Requirements

- Python 3.10 or newer
- Git
- [GitHub CLI](https://cli.github.com/) authenticated to the account being audited

Authenticate with the minimum useful scopes:

```shell
gh auth login -h github.com -p https --web --scopes repo,read:org,workflow
```

Listing organization-level secret names additionally requires organization-admin rights and the `admin:org` scope:

```shell
gh auth refresh -h github.com -s admin:org
```

The broader scope is optional. Without it, the report identifies inaccessible organization stores rather than silently treating them as empty.

## Run the audit

```shell
python3 audit_github_credentials.py
```

The script writes:

- `credential-rotation-inventory.md`: human-readable rotation runbook
- `credential-rotation-inventory.csv`: sortable credential-reference inventory
- `credential-rotation-inventory.json`: complete machine-readable results

Re-running the command refreshes these files. To reuse already downloaded snapshots during development, set `AUDIT_CLONE_ROOT` to their directory.

## Suggested coding-assistant prompt

> Run `python3 audit_github_credentials.py`, review the generated credential rotation inventory, and summarize urgent findings. Never print or copy secret values. Distinguish configured GitHub secrets from source-only references and call out every inaccessible organization store as a coverage gap.

The assistant should not rotate or revoke credentials unless the user separately authorizes those changes.

## Reading the results

- **Configured GitHub secrets** are names returned by repository, environment, Dependabot, or Codespaces metadata APIs.
- **Referenced credentials** are credential-shaped names found in source or automation but absent from the returned repository stores. They may be organization secrets, external deployment variables, local credentials, examples, or stale references.
- **Possible committed literals** need immediate manual review. Values remain omitted. Base64 is encoding, not encryption.
- **Organization coverage** explains whether each organization store was readable with the current role and token scopes.

## Limitations

This is a rotation inventory, not proof that a repository is credential-free. Dynamic names, encrypted files, binaries, external reusable workflows, large files, vendored dependencies, and credentials held only in systems such as Vault, Kubernetes, OpenShift, cloud CI, or deployment platforms may require separate inspection.
