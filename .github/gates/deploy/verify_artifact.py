#!/usr/bin/env python3
"""Verify an artifact's build provenance before it is deployed (ticket P4.5).

Usage:
  verify_artifact.py ARTIFACT --repo OWNER/NAME --signer-workflow .github/workflows/FILE.yml
                     [--source-ref refs/heads/main] [--source-digest COMMIT_SHA]
                     [--expected-digest sha256:HEX] [--repo-id ID] [--incident FILE]

Exit 0 when the artifact verifies, 1 when it doesn't, 2 on a usage error.

It runs `gh attestation verify` with every restriction GitHub supports, then
checks the verified statement again itself:

- the SLSA provenance subject lists this artifact's SHA-256;
- it was signed by the named workflow in the named repo, on the source ref,
  at the source commit, on a GitHub-hosted runner;
- the digest equals the one the build job recorded, so the artifact wasn't
  swapped between build and deploy.

On failure, --incident writes a Markdown summary that the workflow files as
an incident (P0.12). The artifact must not be deployed.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

SLSA_V1 = "https://slsa.dev/provenance/v1"
ISSUER = "https://token.actions.githubusercontent.com"


class VerifyError(Exception):
    pass


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def gh_verify(path, repo, signer_workflow, source_ref, source_digest=None, gh="gh"):
    """Run gh attestation verify; return its parsed JSON results."""
    command = [gh, "attestation", "verify", path, "--repo", repo,
               "--signer-workflow", f"{repo}/{signer_workflow}", "--predicate-type", SLSA_V1,
               "--cert-oidc-issuer", ISSUER, "--deny-self-hosted-runners", "--format", "json"]
    if source_ref:
        command += ["--source-ref", source_ref]
    if source_digest:
        command += ["--source-digest", source_digest]
    result = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    if result.returncode:
        raise VerifyError("gh attestation verify refused it: " + (result.stderr.strip() or "no output")[-600:])
    try:
        results = json.loads(result.stdout)
    except ValueError as exc:
        raise VerifyError(f"gh attestation verify printed something other than JSON: {exc}") from exc
    if not isinstance(results, list) or not results:
        raise VerifyError("gh attestation verify returned no verified attestation")
    return results


def problems_with(result, digest, repo, signer_workflow, source_ref, source_digest=None, repo_id=None):
    """Why one verified attestation doesn't cover this artifact, or [] if it does."""
    found = []
    vr = result.get("verificationResult") or {}
    statement = vr.get("statement") or {}
    cert = (vr.get("signature") or {}).get("certificate") or {}
    if statement.get("predicateType") != SLSA_V1:
        found.append(f"predicate type is {statement.get('predicateType')}, not SLSA provenance v1")
    subjects = {(s.get("digest") or {}).get("sha256") for s in statement.get("subject") or []}
    if digest not in subjects:
        found.append("the attestation doesn't list this artifact's SHA-256")
    if cert.get("issuer") != ISSUER:
        found.append(f"certificate issuer is {cert.get('issuer')}")
    if cert.get("sourceRepositoryURI") != f"https://github.com/{repo}":
        found.append(f"built from {cert.get('sourceRepositoryURI')}, not {repo}")
    signer = f"https://github.com/{repo}/{signer_workflow}@"
    if not str(cert.get("buildSignerURI", "")).startswith(signer):
        found.append(f"signed by {cert.get('buildSignerURI')}, not {repo}/{signer_workflow}")
    if source_ref and cert.get("sourceRepositoryRef") != source_ref:
        found.append(f"built from ref {cert.get('sourceRepositoryRef')}, not {source_ref}")
    if source_ref and not str(cert.get("buildSignerURI", "")).endswith("@" + source_ref):
        found.append(f"signer workflow ran from {cert.get('buildSignerURI')}, not {source_ref}")
    if source_digest and cert.get("sourceRepositoryDigest") != source_digest:
        found.append(f"built from commit {cert.get('sourceRepositoryDigest')}, not {source_digest}")
    if repo_id and str(cert.get("sourceRepositoryIdentifier")) != str(repo_id):
        found.append(f"source repository id is {cert.get('sourceRepositoryIdentifier')}, not {repo_id}")
    if cert.get("runnerEnvironment") != "github-hosted":
        found.append(f"built on a {cert.get('runnerEnvironment')} runner")
    return found


def verify(path, repo, signer_workflow, source_ref="refs/heads/main", source_digest=None,
           expected_digest=None, repo_id=None, gh="gh"):
    """Return the artifact's sha256 hex if it verifies; raise VerifyError otherwise."""
    if not os.path.isfile(path):
        raise VerifyError(f"{path} isn't a file")
    digest = sha256_of(path)
    if expected_digest is not None:
        want = expected_digest.split(":", 1)[-1].lower()
        if want != digest:
            raise VerifyError(f"SHA-256 is {digest}, but the build recorded {want}: the artifact changed "
                              "between build and deploy")
    results = gh_verify(path, repo, signer_workflow, source_ref, source_digest, gh)
    reasons = []
    for result in results:
        found = problems_with(result, digest, repo, signer_workflow, source_ref, source_digest, repo_id)
        if not found:
            return digest
        reasons.extend(found)
    raise VerifyError("no attestation covers this artifact: " + "; ".join(dict.fromkeys(reasons)))


def incident_text(path, reason, expected_digest=None):
    run = "{}/{}/actions/runs/{}".format(os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
                                         os.environ.get("GITHUB_REPOSITORY", "?"), os.environ.get("GITHUB_RUN_ID", "?"))
    try:
        digest = sha256_of(path)
    except OSError:
        digest = "unreadable"
    lines = [
        "An artifact failed provenance verification and was not deployed (P4.5).",
        "",
        ("Handle this as an incident: follow kit/runbooks/incident-response.md, "
         "section \"An artifact fails provenance verification\"."),
        "",
        f"- **Artifact:** `{os.path.basename(path)}`",
        f"- **SHA-256:** `{digest}`",
        f"- **Expected:** `{expected_digest or 'not recorded'}`",
        f"- **Environment:** `{os.environ.get('DEPLOY_ENVIRONMENT', '?')}`",
        f"- **Run:** {run}",
        f"- **Commit:** `{os.environ.get('GITHUB_SHA', '?')}`",
        "",
        "Reason:",
        "",
        "```",
        reason,
        "```",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("artifact")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--signer-workflow", required=True, help="path in the repo, such as .github/workflows/deploy.yml")
    parser.add_argument("--source-ref", default="refs/heads/main")
    parser.add_argument("--source-digest", help="the commit the artifact must be built from")
    parser.add_argument("--expected-digest", help="sha256:HEX recorded by the build job")
    parser.add_argument("--repo-id", help="numeric repository id, which survives a rename")
    parser.add_argument("--incident", help="write an incident summary here on failure")
    args = parser.parse_args(argv)
    if args.signer_workflow.startswith(("/", "http")) or "@" in args.signer_workflow:
        parser.error("--signer-workflow is a path in the repo, such as .github/workflows/deploy.yml")
    try:
        digest = verify(args.artifact, args.repo, args.signer_workflow, args.source_ref, args.source_digest,
                        args.expected_digest, args.repo_id)
    except VerifyError as exc:
        print(f"verify_artifact: NOT VERIFIED: {exc}", file=sys.stderr)
        if args.incident:
            with open(args.incident, "w", encoding="utf-8") as handle:
                handle.write(incident_text(args.artifact, str(exc), args.expected_digest))
        return 1
    print(f"verified {os.path.basename(args.artifact)} sha256:{digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
