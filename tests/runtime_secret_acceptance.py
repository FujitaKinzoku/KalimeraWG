#!/usr/bin/env python3
"""Приёмка порогового runtime-хранилища на одноразовых путях."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys


def run(command: list[str], *, env: dict[str, str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        command, env=env, text=True, capture_output=True, check=False
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"acceptance command failed with rc={result.returncode}: {result.stderr.strip()}"
        )
    return result


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: runtime_secret_acceptance.py SECRETCTL")
    secretctl = pathlib.Path(sys.argv[1])
    root = pathlib.Path("/tmp/kalimerawg-runtime-acceptance")
    runtime = pathlib.Path("/run/kalimerawg-runtime-acceptance")
    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(runtime, ignore_errors=True)
    root.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)
    try:
        key_hex = os.urandom(32).hex()
        split = subprocess.run(
            [
                "/usr/bin/ssss-split", "-t", "2", "-n", "3", "-s", "256",
                "-x", "-Q", "-w", "kalimerawgruntimev1",
            ],
            input=key_hex + "\n",
            text=True,
            capture_output=True,
            check=True,
        )
        shares = [line for line in split.stdout.splitlines() if line]
        if len(shares) != 3:
            raise RuntimeError("ssss-split did not create three shares")

        source = root / "persistent" / "secret.conf"
        source.parent.mkdir(mode=0o700)
        source.write_text("acceptance-secret\n", encoding="utf-8")
        source.chmod(0o600)
        hidden_source = root / "persistent" / ".hidden-secret"
        hidden_source.write_text("hidden-acceptance-secret\n", encoding="utf-8")
        hidden_source.chmod(0o600)
        local_share = root / "local.share"
        recovery_share = root / "recovery.share"
        identity = root / "identity"
        known_hosts = root / "known_hosts"
        for path, value in (
            (local_share, shares[0]),
            (recovery_share, shares[1]),
            (identity, "acceptance-identity"),
            (known_hosts, ""),
        ):
            path.write_text(value + "\n", encoding="ascii")
            path.chmod(0o400)

        config_path = root / "config.json"
        bundle_path = root / "bundle.v1.json"
        config = {
            "cluster_id": os.urandom(16).hex(),
            "threshold": 2,
            "total_shares": 3,
            "key_sha256": hashlib.sha256(bytes.fromhex(key_hex)).hexdigest(),
            "runtime_root": str(runtime),
            "bundle_path": str(bundle_path),
            "local_share_path": str(local_share),
            "identity_path": str(identity),
            "known_hosts_path": str(known_hosts),
            "peer_timeout_seconds": 2,
            "peers": [],
            "mappings": [
                {"source": str(source), "target": "test/secret.conf"},
                {"source": str(hidden_source), "target": "test/.hidden-secret"},
            ],
        }
        config_path.write_text(json.dumps(config), encoding="ascii")
        config_path.chmod(0o600)
        environment = dict(os.environ, KALIMERA_SECRET_CONFIG=str(config_path))
        recovery = ["--recovery-share-file", str(recovery_share)]

        run([str(secretctl), "adopt"], env=environment)
        first_seal = run([str(secretctl), "seal", *recovery], env=environment)
        if "changed" not in first_seal.stdout:
            raise RuntimeError("first seal was not reported as changed")
        run([str(secretctl), "link"], env=environment)
        run([str(secretctl), "verify"], env=environment)
        run([str(secretctl), "check", *recovery], env=environment)
        second_seal = run([str(secretctl), "seal", *recovery], env=environment)
        if "unchanged" not in second_seal.stdout:
            raise RuntimeError("idempotent seal changed an identical bundle")

        shutil.rmtree(runtime)
        run([str(secretctl), "unlock", *recovery], env=environment)
        run([str(secretctl), "verify"], env=environment)
        run([str(secretctl), "check", *recovery], env=environment)
        if source.read_text(encoding="utf-8") != "acceptance-secret\n":
            raise RuntimeError("unlocked content does not match")
        if hidden_source.read_text(encoding="utf-8") != "hidden-acceptance-secret\n":
            raise RuntimeError("hidden unlocked content does not match")

        hidden_source.unlink()
        hidden_source.write_text("plaintext-copy-must-fail\n", encoding="utf-8")
        plaintext_check = run(
            [str(secretctl), "verify"], env=environment, check=False
        )
        if plaintext_check.returncode == 0:
            raise RuntimeError("verify accepted a plaintext copy outside /run")
        hidden_source.unlink()
        hidden_source.symlink_to(runtime / "test" / ".hidden-secret")
        run([str(secretctl), "verify"], env=environment)

        original_bundle = bundle_path.read_bytes()
        document = json.loads(original_bundle)
        ciphertext = document["ciphertext"]
        document["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
        bundle_path.write_text(json.dumps(document), encoding="ascii")
        bundle_path.chmod(0o600)
        shutil.rmtree(runtime)
        failed = run(
            [str(secretctl), "unlock", *recovery], env=environment, check=False
        )
        if failed.returncode == 0 or (runtime / ".unlocked").exists():
            raise RuntimeError("tampered bundle did not fail closed")
        if not source.is_symlink():
            raise RuntimeError("persistent source stopped being a runtime symlink")

        bundle_path.write_bytes(original_bundle)
        bundle_path.chmod(0o600)
        run([str(secretctl), "unlock", *recovery], env=environment)
        run([str(secretctl), "verify"], env=environment)
        print("runtime secret acceptance: OK")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(runtime, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
