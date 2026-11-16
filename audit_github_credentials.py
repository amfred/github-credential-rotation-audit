#!/usr/bin/env python3
"""Inventory credential names and rotation locations across maintained GitHub repos.

The script deliberately never prints or persists secret values. It combines GitHub's
secret metadata APIs (names and timestamps only) with a local scan of current source
snapshots for credential-shaped environment-variable and GitHub Actions references.
"""

from __future__ import annotations

import base64
import concurrent.futures
import csv
import datetime as dt
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPORT_PATH = ROOT / "credential-rotation-inventory.md"
JSON_PATH = ROOT / "credential-rotation-inventory.json"
CSV_PATH = ROOT / "credential-rotation-inventory.csv"
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LOCATIONS_PER_NAME = 12

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "third_party",
    "dist", "build", "target", ".next", ".cache", "coverage", "venv",
    ".venv", "__pycache__", "fixtures", "testdata",
}
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Cargo.lock", "go.sum", "composer.lock", "semgrep.yml", "semgrep.yaml",
}
TEXT_SUFFIXES = {
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".env", ".example", ".sample", ".template", ".md",
    ".txt", ".sh", ".bash", ".zsh", ".py", ".js", ".jsx", ".mjs",
    ".cjs", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".rb",
    ".php", ".tf", ".tfvars", ".hcl", ".xml", ".gradle", ".groovy",
    ".cs", ".ps1", ".sql",
}
SPECIAL_TEXT_NAMES = {
    "Jenkinsfile", "Dockerfile", "Makefile", "Procfile", ".travis.yml",
    "azure-pipelines.yml", "bitbucket-pipelines.yml",
}

NAME_TOKEN = r"[A-Za-z_][A-Za-z0-9_.-]*"
REF_PATTERNS = [
    ("github-actions", re.compile(r"\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)")),
    ("github-actions", re.compile(r"\bsecrets\[['\"]([^'\"]+)['\"]\]")),
    ("python-env", re.compile(r"(?:os\.getenv|os\.environ\.get)\(\s*['\"](" + NAME_TOKEN + r")[\"']")),
    ("python-env", re.compile(r"os\.environ\[\s*['\"](" + NAME_TOKEN + r")[\"']\s*\]")),
    ("node-env", re.compile(r"\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)")),
    ("node-env", re.compile(r"\bprocess\.env\[['\"]([^'\"]+)['\"]\]")),
    ("java-env", re.compile(r"System\.getenv\(\s*['\"](" + NAME_TOKEN + r")[\"']")),
    ("ruby-env", re.compile(r"\bENV\[['\"]([^'\"]+)['\"]\]")),
    ("shell-template", re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")),
]
ASSIGNMENT_RE = re.compile(
    r"^\s*(?:export\s+)?[\"']?([A-Za-z_][A-Za-z0-9_.-]*)[\"']?\s*[:=]\s*(.*)$"
)

PROVIDERS = [
    (re.compile(r"OPENAI", re.I), "OpenAI", "https://platform.openai.com/settings/organization/api-keys"),
    (re.compile(r"ANTHROPIC|CLAUDE", re.I), "Anthropic", "https://console.anthropic.com/settings/keys"),
    (re.compile(r"TAVILY", re.I), "Tavily", "https://app.tavily.com/home"),
    (re.compile(r"WOLFRAM", re.I), "Wolfram|Alpha", "https://developer.wolframalpha.com/portal/myapps/"),
    (re.compile(r"FIREWORKS", re.I), "Fireworks AI", "https://app.fireworks.ai/account/api-keys"),
    (re.compile(r"NVD_", re.I), "NIST NVD", "https://nvd.nist.gov/developers/request-an-api-key"),
    (re.compile(r"NVIDIA|NGC_", re.I), "NVIDIA / NGC", "https://org.ngc.nvidia.com/setup/api-keys"),
    (re.compile(r"TOGETHER", re.I), "Together AI", "https://api.together.ai/settings/api-keys"),
    (re.compile(r"BRAVE", re.I), "Brave Search", "https://api-dashboard.search.brave.com/app/keys"),
    (re.compile(r"FLY_API_TOKEN", re.I), "Fly.io", "https://fly.io/dashboard/personal/tokens"),
    (re.compile(r"JIRA|ATLASSIAN", re.I), "Atlassian / Jira", "https://id.atlassian.com/manage-profile/security/api-tokens"),
    (re.compile(r"CURSOR_API_KEY", re.I), "Cursor", "https://cursor.com/dashboard"),
    (re.compile(r"GITLAB", re.I), "GitLab", "https://gitlab.com/-/user_settings/personal_access_tokens"),
    (re.compile(r"GLOBUS", re.I), "Globus", "https://app.globus.org/settings/developers"),
    (re.compile(r"MAILCHIMP", re.I), "Mailchimp", "https://admin.mailchimp.com/account/api/"),
    (re.compile(r"SERPAPI", re.I), "SerpAPI", "https://serpapi.com/manage-api-key"),
    (re.compile(r"ROX_API_TOKEN|STACKROX", re.I), "Red Hat Advanced Cluster Security", "https://console.redhat.com/application-services/acs/instances"),
    (re.compile(r"TWILIO", re.I), "Twilio", "https://console.twilio.com/us1/account/keys-credentials/api-keys"),
    (re.compile(r"CEREBRAS", re.I), "Cerebras", "https://cloud.cerebras.ai/platform"),
    (re.compile(r"SAMBANOVA", re.I), "SambaNova Cloud", "https://cloud.sambanova.ai/apis"),
    (re.compile(r"READTHEDOCS", re.I), "Read the Docs", "https://readthedocs.org/accounts/tokens/"),
    (re.compile(r"COVERALLS", re.I), "Coveralls", "https://coveralls.io/"),
    (re.compile(r"CACHIX", re.I), "Cachix", "https://app.cachix.org/personal-auth-tokens"),
    (re.compile(r"SNAPCRAFT", re.I), "Snapcraft", "https://snapcraft.io/account/credentials"),
    (re.compile(r"FERN_TOKEN", re.I), "Fern", "https://dashboard.buildwithfern.com/"),
    (re.compile(r"MONGODB", re.I), "MongoDB Atlas", "https://cloud.mongodb.com/v2#/account/users"),
    (re.compile(r"AWS|AMAZON", re.I), "AWS", "https://console.aws.amazon.com/iam/home#/security_credentials"),
    (re.compile(r"AZURE|ENTRA", re.I), "Microsoft Azure / Entra", "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"),
    (re.compile(r"GCP|GOOGLE|GEMINI", re.I), "Google Cloud", "https://console.cloud.google.com/apis/credentials"),
    (re.compile(r"IBM.*CLOUD|IBMCLOUD|BLUEMIX", re.I), "IBM Cloud", "https://cloud.ibm.com/iam/apikeys"),
    (re.compile(r"HUGGING.?FACE|HF_TOKEN", re.I), "Hugging Face", "https://huggingface.co/settings/tokens"),
    (re.compile(r"NPM|NODE_AUTH_TOKEN", re.I), "npm", "https://www.npmjs.com/settings/~/tokens"),
    (re.compile(r"PYPI|TWINE", re.I), "PyPI", "https://pypi.org/manage/account/token/"),
    (re.compile(r"DOCKER", re.I), "Docker Hub", "https://hub.docker.com/settings/security"),
    (re.compile(r"QUAY", re.I), "Quay", "https://quay.io/"),
    (re.compile(r"SLACK", re.I), "Slack", "https://api.slack.com/apps"),
    (re.compile(r"LANGSMITH|LANGCHAIN", re.I), "LangSmith", "https://smith.langchain.com/settings"),
    (re.compile(r"SONAR", re.I), "Sonar", "https://sonarcloud.io/account/security"),
    (re.compile(r"SNYK", re.I), "Snyk", "https://app.snyk.io/account"),
    (re.compile(r"CODECOV", re.I), "Codecov", "https://app.codecov.io/"),
    (re.compile(r"VERCEL", re.I), "Vercel", "https://vercel.com/account/tokens"),
    (re.compile(r"NETLIFY", re.I), "Netlify", "https://app.netlify.com/user/applications#personal-access-tokens"),
    (re.compile(r"GITHUB|GH_TOKEN|GHCR|GHSA", re.I), "GitHub", "https://github.com/settings/tokens"),
]


def run(args: list[str], *, timeout: int = 240, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout, env=merged_env)


def gh_json(endpoint: str, *, slurp_pages: bool = False) -> tuple[object | None, str | None]:
    args = ["gh", "api"]
    if slurp_pages:
        args += ["--paginate", "--slurp"]
    args.append(endpoint)
    cp = run(args)
    if cp.returncode:
        message = cp.stderr.strip().splitlines()[-1] if cp.stderr.strip() else "GitHub API request failed"
        return None, message
    try:
        return json.loads(cp.stdout), None
    except json.JSONDecodeError:
        return None, "GitHub API returned non-JSON output"


def provider_for(name: str) -> tuple[str, str]:
    for pattern, provider, url in PROVIDERS:
        if pattern.search(name):
            return provider, url
    return "Unknown / inspect usage", ""


def credentialish(name: str) -> bool:
    # Normalize camelCase, punctuation, and casing before testing whole concepts.
    # This avoids treating ordinary terms such as max_tokens, author, username,
    # tokenizer, or secretKeyRef as credentials.
    canonical = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    canonical = re.sub(r"[^A-Za-z0-9]+", "_", canonical).strip("_").upper()
    if not canonical:
        return False
    if canonical in {"SECRET", "SECRETS", "SECRET_KEY_REF", "ID_TOKEN", "TOKEN", "PASSWORD"}:
        return False
    reference_or_control_terms = (
        "SECRET_NAME", "SECRET_REF", "SECRET_PATH", "SECRET_TMP", "TOKEN_PATH",
        "TOKEN_URL", "TOKEN_ENDPOINT", "TOKEN_CLAIM", "TOKEN_SCOPE", "TOKEN_LIFESPAN",
        "CREDENTIAL_REF", "CREDENTIAL_PATH", "CREDENTIAL_FILE", "CREDENTIAL_MODE",
        "CREDENTIAL_DRIVER", "PERSIST_CREDENTIALS", "ALLOW_CREDENTIALS",
        "AUTOMOUNT_SERVICE_ACCOUNT_TOKEN", "SERVICE_ACCOUNT_TOKEN_PATH",
        "RESET_PASSWORD", "REQUIRE_PASSWORD", "PASSWORD_ALLOWED", "MAX_API_KEYS",
    )
    if any(marker in canonical for marker in reference_or_control_terms):
        return False
    token_noncredentials = (
        "MAX_TOKEN", "MIN_TOKEN", "NUM_TOKEN", "INPUT_TOKEN", "OUTPUT_TOKEN",
        "TOTAL_TOKEN", "TOKEN_COUNT", "TOKEN_LIMIT", "TOKEN_BUDGET", "TOKEN_SIZE",
        "TOKEN_LENGTH", "TOKEN_TYPE", "TOKEN_NAME", "TOKEN_INDEX", "TOKENIZER",
        "TOKENS_PER", "TOKEN_USAGE", "TOKEN_TTL", "CHUNK_TOKEN", "CONTEXT_TOKEN",
    )
    if any(marker in canonical for marker in token_noncredentials):
        return False
    concepts = (
        "API_KEY", "APIKEY", "API_TOKEN", "ACCESS_TOKEN", "AUTH_TOKEN", "BEARER_TOKEN",
        "REFRESH_TOKEN", "PERSONAL_ACCESS_TOKEN", "GITHUB_TOKEN", "GITLAB_TOKEN",
        "PASSWORD", "PASSWD", "CLIENT_SECRET", "APP_SECRET", "APPLICATION_SECRET",
        "CREDENTIAL", "ACCESS_KEY", "PRIVATE_KEY", "SIGNING_KEY", "ENCRYPTION_KEY",
        "WEBHOOK_SECRET", "WEBHOOK_TOKEN", "CONNECTION_STRING", "DATABASE_URL", "DB_DSN",
        "DATABASE_DSN", "SERVICE_ACCOUNT_KEY", "APPLICATION_CREDENTIALS", "KUBECONFIG",
    )
    if any(concept in canonical for concept in concepts):
        return True
    return bool(re.search(r"(?:^|_)(?:TOKEN|SECRET)(?:$|_)", canonical))


def looks_like_literal(value: str) -> bool:
    value = value.strip().strip(",").strip().strip("'\"")
    if not value or len(value) < 16 or any(ch.isspace() for ch in value):
        return False
    lowered = value.lower()
    placeholders = (
        "example", "sample", "placeholder", "changeme", "change-me", "replace",
        "your_", "your-", "dummy", "test", "fake", "xxxx", "<", "${", "{{",
        "secrets.", "process.env", "os.getenv", "none", "null", "true", "false",
        "config.", "config[", "settings.", "getenv", "secretkeyref", "valuefrom",
    )
    if any(marker in lowered for marker in placeholders):
        return False
    if value.startswith(("/", ".", "http://", "https://")) or "/" in value or "\\" in value:
        return False
    known_secret_shapes = (
        r"AKIA[0-9A-Z]{16}",
        r"(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}",
        r"sk-[A-Za-z0-9_-]{20,}",
        r"xox[baprs]-[A-Za-z0-9-]{20,}",
        r"sk_live_[A-Za-z0-9]{16,}",
    )
    if any(re.fullmatch(pattern, value) for pattern in known_secret_shapes):
        return True
    if not re.fullmatch(r"[A-Za-z0-9_+=.@:-]{24,256}", value):
        return False
    counts = {ch: value.count(ch) for ch in set(value)}
    entropy = -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())
    return entropy >= 3.8


def literal_candidate_file(path: Path) -> bool:
    return path.name.startswith(".env") or path.suffix.lower() in {
        ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
        ".properties", ".tfvars",
    }


def config_declaration_candidate(path: Path, name: str) -> bool:
    lowered = path.name.lower()
    if lowered.startswith(".env") or path.suffix.lower() in {".example", ".sample", ".template"}:
        return True
    if "secret" in lowered and path.suffix.lower() in {".yml", ".yaml", ".json", ".toml", ".ini", ".conf"}:
        return True
    # Uppercase names in configuration commonly denote environment variables.
    return name == name.upper() and path.suffix.lower() in {
        ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".tfvars",
    }


def should_scan(path: Path) -> bool:
    if path.name in SKIP_FILES:
        return False
    if path.name in SPECIAL_TEXT_NAMES:
        return True
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    return path.name.startswith(".env")


def scan_checkout(checkout: Path) -> tuple[list[dict], list[dict], dict]:
    refs: dict[tuple[str, str], list[str]] = defaultdict(list)
    possible_literals: dict[str, list[str]] = defaultdict(list)
    stats = {"files_scanned": 0, "files_skipped_large": 0, "files_unreadable": 0}

    for current, dirnames, filenames in os.walk(checkout):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        current_path = Path(current)
        for filename in filenames:
            path = current_path / filename
            if not should_scan(path):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    stats["files_skipped_large"] += 1
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                stats["files_unreadable"] += 1
                continue
            stats["files_scanned"] += 1
            rel = path.relative_to(checkout).as_posix()
            for line_no, line in enumerate(text.splitlines(), 1):
                location = f"{rel}:{line_no}"
                for kind, pattern in REF_PATTERNS:
                    for match in pattern.finditer(line):
                        name = match.group(1)
                        if kind == "github-actions" and not (rel.startswith(".github/workflows/") or "${{" in line):
                            continue
                        if kind == "github-actions" or credentialish(name):
                            key = (name, kind)
                            if location not in refs[key] and len(refs[key]) < MAX_LOCATIONS_PER_NAME:
                                refs[key].append(location)
                assignment = ASSIGNMENT_RE.match(line)
                if assignment:
                    name, value = assignment.groups()
                    if credentialish(name) and config_declaration_candidate(path, name):
                        key = (name, "config-declaration")
                        if location not in refs[key] and len(refs[key]) < MAX_LOCATIONS_PER_NAME:
                            refs[key].append(location)
                        if literal_candidate_file(path) and looks_like_literal(value):
                            if location not in possible_literals[name] and len(possible_literals[name]) < MAX_LOCATIONS_PER_NAME:
                                possible_literals[name].append(location)

    ref_rows = [
        {"name": name, "kind": kind, "locations": locations}
        for (name, kind), locations in sorted(refs.items(), key=lambda item: (item[0][0].upper(), item[0][1]))
    ]
    literal_rows = [
        {"name": name, "locations": locations}
        for name, locations in sorted(possible_literals.items())
    ]
    return ref_rows, literal_rows, stats


def list_secret_store(endpoint: str, store: str, environment: str | None = None) -> tuple[list[dict], str | None]:
    payload, error = gh_json(endpoint)
    if error:
        return [], error
    assert isinstance(payload, dict)
    rows = []
    for secret in payload.get("secrets", []):
        rows.append({
            "name": secret.get("name", ""),
            "store": store,
            "environment": environment,
            "created_at": secret.get("created_at"),
            "updated_at": secret.get("updated_at"),
        })
    return rows, None


def audit_repo(repo: dict, clone_root: Path) -> dict:
    full_name = repo["full_name"]
    owner, name = full_name.split("/", 1)
    encoded_repo = f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}"
    result = {
        "repository": full_name,
        "url": repo["html_url"],
        "visibility": repo["visibility"],
        "archived": repo["archived"],
        "default_branch": repo["default_branch"],
        "permission": "admin" if repo.get("permissions", {}).get("admin") else "maintain",
        "configured_secrets": [],
        "references": [],
        "possible_literals": [],
        "api_errors": {},
        "clone_error": None,
        "scan_stats": {},
    }

    stores = [
        (f"repos/{encoded_repo}/actions/secrets?per_page=100", "actions", None),
        (f"repos/{encoded_repo}/dependabot/secrets?per_page=100", "dependabot", None),
        (f"repos/{encoded_repo}/codespaces/secrets?per_page=100", "codespaces", None),
    ]
    for endpoint, store, environment in stores:
        rows, error = list_secret_store(endpoint, store, environment)
        result["configured_secrets"].extend(rows)
        if error:
            result["api_errors"][store] = error

    env_payload, env_error = gh_json(f"repos/{encoded_repo}/environments?per_page=100")
    if env_error:
        result["api_errors"]["environments"] = env_error
    elif isinstance(env_payload, dict):
        for environment in env_payload.get("environments", []):
            env_name = environment.get("name", "")
            encoded_env = urllib.parse.quote(env_name, safe="")
            rows, error = list_secret_store(
                f"repos/{encoded_repo}/environments/{encoded_env}/secrets?per_page=100",
                "environment",
                env_name,
            )
            result["configured_secrets"].extend(rows)
            if error:
                result["api_errors"][f"environment:{env_name}"] = error

    destination = clone_root / (full_name.replace("/", "__"))
    if (destination / ".git").is_dir():
        refs, literals, stats = scan_checkout(destination)
        result["references"] = refs
        result["possible_literals"] = literals
        result["scan_stats"] = stats
    else:
        cp = run(
            ["gh", "repo", "clone", full_name, str(destination), "--", "--depth", "1", "--single-branch", "--no-tags", "--quiet"],
            timeout=360,
            env={"GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0"},
        )
        if cp.returncode:
            result["clone_error"] = cp.stderr.strip().splitlines()[-1] if cp.stderr.strip() else "clone failed"
        else:
            refs, literals, stats = scan_checkout(destination)
            result["references"] = refs
            result["possible_literals"] = literals
            result["scan_stats"] = stats

    for secret in result["configured_secrets"]:
        provider, provider_url = provider_for(secret["name"])
        secret["provider"] = provider
        secret["provider_url"] = provider_url
    for reference in result["references"]:
        provider, provider_url = provider_for(reference["name"])
        reference["provider"] = provider
        reference["provider_url"] = provider_url
    return result


def md_link(label: str, url: str) -> str:
    return f"[{label}]({url})" if url else label


def github_settings_url(repo: str, store: str, environment: str | None = None) -> str:
    base = f"https://github.com/{repo}/settings"
    if store == "actions":
        return f"{base}/secrets/actions"
    if store == "dependabot":
        return f"{base}/secrets/dependabot"
    if store == "codespaces":
        return f"{base}/secrets/codespaces"
    if store == "environment":
        return f"{base}/environments/{urllib.parse.quote(environment or '', safe='')}"
    return base


def render_markdown(identity: str, results: list[dict], organization_audit: list[dict], generated_at: str) -> str:
    configured_count = sum(len(r["configured_secrets"]) for r in results)
    repos_with_configured = sum(bool(r["configured_secrets"]) for r in results)
    repos_with_refs = sum(bool(r["references"]) for r in results)
    literal_count = sum(len(r["possible_literals"]) for r in results)
    clone_failures = [r for r in results if r["clone_error"]]
    active = sum(not r["archived"] for r in results)
    private = sum(r["visibility"] == "private" for r in results)
    lines = [
        "# GitHub credential rotation inventory",
        "",
        f"Generated {generated_at} for GitHub account `{identity}`.",
        "",
        "> Safety: this report contains credential names and source locations only. It does not retrieve or store secret values.",
        "",
        "## Summary",
        "",
        f"- Maintained repositories: **{len(results)}** ({active} active, {len(results) - active} archived; {private} private).",
        f"- GitHub-configured secrets: **{configured_count}** across {repos_with_configured} repositories.",
        f"- Organizations checked for inherited secrets: **{len({item['organization'] for item in organization_audit})}** (access depends on role and CLI token scope).",
        f"- Repositories with credential-shaped source/config references: **{repos_with_refs}**.",
        f"- Possible literal credential assignments needing manual review: **{literal_count}** names (values intentionally omitted).",
        f"- Source snapshots that could not be scanned: **{len(clone_failures)}**.",
        "",
        "## Rapid-response procedure",
        "",
        "1. Revoke or regenerate the credential at the provider first. Keep the old credential active briefly only when zero-downtime overlap is required.",
        "2. Update every GitHub secret store listed below. A repository may use the same name in organization, repository, environment, Dependabot, or Codespaces stores.",
        "3. Re-run affected workflows/deployments, verify success, then revoke the old credential if it was temporarily retained.",
        "4. Check provider audit logs and GitHub workflow history for unexpected use. Rotate signing/private keys by replacing the key pair, not merely re-saving the old value.",
        "5. Re-run `python3 audit_github_credentials.py` to refresh this inventory.",
        "",
        "## Configured GitHub secrets",
        "",
    ]
    configured_rows = []
    for repo in results:
        for secret in repo["configured_secrets"]:
            configured_rows.append((repo, secret))
    if configured_rows:
        lines += [
            "| Repository | Store | Secret name | Provider rotation | GitHub update | Last updated |",
            "|---|---|---|---|---|---|",
        ]
        for repo, secret in configured_rows:
            store = secret["store"]
            if secret.get("environment"):
                store += f" (`{secret['environment']}`)"
            provider = md_link(secret["provider"], secret["provider_url"])
            settings = md_link("Update secret", github_settings_url(repo["repository"], secret["store"], secret.get("environment")))
            lines.append(
                f"| `{repo['repository']}` | {store} | `{secret['name']}` | {provider} | {settings} | {secret.get('updated_at') or 'unknown'} |"
            )
    else:
        lines.append("No repository-level, environment, Dependabot, or Codespaces secrets were returned by GitHub's APIs.")

    lines += ["", "## Organization secret coverage", ""]
    if organization_audit:
        lines += [
            "| Organization | Your role | Store | Result | Settings |",
            "|---|---|---|---|---|",
        ]
        for item in organization_audit:
            if item["error"]:
                result_text = f"Not readable: {item['error']}"
            elif item["secrets"]:
                names = ", ".join(f"`{secret['name']}` ({secret.get('visibility', 'unknown')})" for secret in item["secrets"])
                result_text = names
            else:
                result_text = "0 secrets"
            settings_url = f"https://github.com/organizations/{item['organization']}/settings/secrets/{item['store']}"
            lines.append(
                f"| `{item['organization']}` | {item['role']} | {item['store']} | {result_text} | {md_link('Open settings', settings_url)} |"
            )
    else:
        lines.append("No organization-owned repositories were in scope.")

    lines += ["", "## Referenced credentials not present in a returned GitHub secret store", ""]
    missing_rows = []
    for repo in results:
        configured_names = {s["name"] for s in repo["configured_secrets"]}
        for ref in repo["references"]:
            if ref["name"] not in configured_names and ref["name"] != "GITHUB_TOKEN":
                missing_rows.append((repo, ref))
    if missing_rows:
        lines += [
            "These may be organization secrets, caller-provided reusable-workflow secrets, deployment-platform variables, local-only credentials, or stale references. Confirm the owning store before an incident.",
            "",
            "| Repository | Name | Reference type | Locations | Likely provider | Where to check |",
            "|---|---|---|---|---|---|",
        ]
        for repo, ref in missing_rows:
            owner = repo["repository"].split("/", 1)[0]
            if owner == identity:
                check_url = f"https://github.com/{repo['repository']}/settings/secrets/actions"
                check_label = "Repo/environments"
            else:
                check_url = f"https://github.com/organizations/{owner}/settings/secrets/actions"
                check_label = "Org + repo/environments"
            locations = "<br>".join(f"`{loc}`" for loc in ref["locations"])
            lines.append(
                f"| `{repo['repository']}` | `{ref['name']}` | {ref['kind']} | {locations} | {md_link(ref['provider'], ref['provider_url'])} | {md_link(check_label, check_url)} |"
            )
    else:
        lines.append("None found.")

    lines += ["", "## Possible committed literal values — review and rotate urgently", ""]
    literal_rows = [(repo, item) for repo in results for item in repo["possible_literals"]]
    if literal_rows:
        lines += [
            "This is a conservative heuristic and can include sample/test values. Values are omitted. Base64 encoding is not encryption. If any location contains a real credential, revoke it at the provider even if the file was later deleted, because Git history may retain it.",
            "",
            "| Repository | Visibility | Name | Locations | Provider rotation |",
            "|---|---|---|---|---|",
        ]
        for repo, item in literal_rows:
            locations = "<br>".join(f"`{loc}`" for loc in item["locations"])
            provider, provider_url = provider_for(item["name"])
            lines.append(
                f"| `{repo['repository']}` | {repo['visibility']} | `{item['name']}` | {locations} | {md_link(provider, provider_url)} |"
            )
    else:
        lines.append("No likely literal credential assignments were detected by the heuristic scan.")

    lines += ["", "## Repository coverage", "", "| Repository | Access | Visibility | Configured secrets | References | Scan status |", "|---|---|---|---:|---:|---|"]
    for repo in results:
        scan_status = f"failed: {repo['clone_error']}" if repo["clone_error"] else f"{repo['scan_stats'].get('files_scanned', 0)} files"
        archived = "; archived" if repo["archived"] else ""
        lines.append(
            f"| {md_link(repo['repository'], repo['url'])} | {repo['permission']} | {repo['visibility']}{archived} | {len(repo['configured_secrets'])} | {len(repo['references'])} | {scan_status} |"
        )

    lines += [
        "",
        "## Important limitations",
        "",
        "- GitHub does not expose secret values; this audit intentionally uses names and timestamps only.",
        "- Organization secrets are checked separately. GitHub requires organization-admin rights and an `admin:org`-capable token to list their names; inaccessible stores are identified above.",
        "- Runtime credentials stored outside GitHub (for example OpenShift/Kubernetes, Vault, cloud CI, Vercel, or a developer machine) can only be inferred from source references. Confirm those systems separately.",
        "- Source scanning is heuristic. Dynamic secret names, encrypted files, binaries, large files, vendored dependencies, and external reusable workflows may not be detected.",
        "- A clean result means no indicator was found; it does not prove a repository never uses credentials.",
    ]
    if clone_failures:
        lines += ["", "### Snapshot scan failures", ""]
        for repo in clone_failures:
            lines.append(f"- `{repo['repository']}`: {repo['clone_error']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    identity_cp = run(["gh", "api", "user", "--jq", ".login"])
    if identity_cp.returncode:
        print(identity_cp.stderr.strip(), file=sys.stderr)
        return 1
    identity = identity_cp.stdout.strip()

    pages, error = gh_json(
        "user/repos?per_page=100&affiliation=owner,collaborator,organization_member&sort=full_name",
        slurp_pages=True,
    )
    if error:
        print(error, file=sys.stderr)
        return 1
    repos = [repo for page in pages for repo in page if repo.get("permissions", {}).get("admin") or repo.get("permissions", {}).get("maintain")]
    repos.sort(key=lambda repo: repo["full_name"].lower())

    memberships_payload, memberships_error = gh_json("user/memberships/orgs?state=active&per_page=100")
    membership_roles = {}
    if not memberships_error and isinstance(memberships_payload, list):
        membership_roles = {
            membership.get("organization", {}).get("login", ""): membership.get("role", "unknown")
            for membership in memberships_payload
        }
    organizations = sorted({
        repo["full_name"].split("/", 1)[0]
        for repo in repos
        if repo["full_name"].split("/", 1)[0] != identity
    })
    organization_audit = []
    for organization in organizations:
        for store in ("actions", "dependabot", "codespaces"):
            payload, store_error = gh_json(f"orgs/{urllib.parse.quote(organization, safe='')}/{store}/secrets?per_page=100")
            secrets = []
            if isinstance(payload, dict):
                secrets = [
                    {
                        "name": item.get("name", ""),
                        "visibility": item.get("visibility", "unknown"),
                        "created_at": item.get("created_at"),
                        "updated_at": item.get("updated_at"),
                    }
                    for item in payload.get("secrets", [])
                ]
            organization_audit.append({
                "organization": organization,
                "role": membership_roles.get(organization, "unknown"),
                "store": store,
                "secrets": secrets,
                "error": store_error,
            })
    configured_clone_root = os.environ.get("AUDIT_CLONE_ROOT")
    clone_root = Path(configured_clone_root) if configured_clone_root else Path(tempfile.mkdtemp(prefix="github-credential-audit-"))
    clone_root.mkdir(parents=True, exist_ok=True)
    print(f"Auditing {len(repos)} repositories as {identity}; temporary snapshots: {clone_root}", flush=True)

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(audit_repo, repo, clone_root): repo["full_name"] for repo in repos}
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            name = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # Preserve coverage even if one repository behaves unexpectedly.
                result = {
                    "repository": name, "url": f"https://github.com/{name}", "visibility": "unknown",
                    "archived": False, "default_branch": "unknown", "permission": "unknown",
                    "configured_secrets": [], "references": [], "possible_literals": [],
                    "api_errors": {"audit": str(exc)}, "clone_error": str(exc), "scan_stats": {},
                }
            results.append(result)
            print(f"[{index:02d}/{len(repos):02d}] {name}: {len(result['configured_secrets'])} configured, {len(result['references'])} references", flush=True)

    results.sort(key=lambda item: item["repository"].lower())
    generated_at = dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")
    payload = {
        "schema_version": 1,
        "generated_at": generated_at,
        "github_identity": identity,
        "safety": "Names and locations only; no secret values retrieved or stored.",
        "organization_secret_audit": organization_audit,
        "repositories": results,
    }
    JSON_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    REPORT_PATH.write_text(render_markdown(identity, results, organization_audit, generated_at), encoding="utf-8")

    with CSV_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "record_type", "repository", "visibility", "permission", "store", "environment",
            "name", "reference_type", "locations", "provider", "github_update_url",
            "provider_rotation_url", "updated_at",
        ])
        writer.writeheader()
        for repo in results:
            for secret in repo["configured_secrets"]:
                writer.writerow({
                    "record_type": "configured-secret",
                    "repository": repo["repository"],
                    "visibility": repo["visibility"],
                    "permission": repo["permission"],
                    "store": secret["store"],
                    "environment": secret.get("environment") or "",
                    "name": secret["name"],
                    "reference_type": "",
                    "locations": "",
                    "provider": secret["provider"],
                    "github_update_url": github_settings_url(repo["repository"], secret["store"], secret.get("environment")),
                    "provider_rotation_url": secret["provider_url"],
                    "updated_at": secret.get("updated_at") or "",
                })
            for reference in repo["references"]:
                writer.writerow({
                    "record_type": "source-reference",
                    "repository": repo["repository"],
                    "visibility": repo["visibility"],
                    "permission": repo["permission"],
                    "store": "",
                    "environment": "",
                    "name": reference["name"],
                    "reference_type": reference["kind"],
                    "locations": "; ".join(reference["locations"]),
                    "provider": reference["provider"],
                    "github_update_url": github_settings_url(repo["repository"], "actions"),
                    "provider_rotation_url": reference["provider_url"],
                    "updated_at": "",
                })

    print(f"Wrote {REPORT_PATH}", flush=True)
    print(f"Wrote {JSON_PATH}", flush=True)
    print(f"Wrote {CSV_PATH}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
