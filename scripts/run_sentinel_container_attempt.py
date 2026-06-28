#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import re
import select
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import textwrap
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DATASET = "ScaleAI/SWE-bench_Pro"
CONTAINER_CWD = "/app"
DEFAULT_DOCKERHUB_USERNAME = "jefzda"
DEFAULT_PLATFORM = "linux/amd64"
CODEX_WEB_SEARCH_DISABLED_CONFIG = 'web_search="disabled"'
DEFAULT_EGRESS_NETWORK = "sentinel-egress"
DEFAULT_EGRESS_SUBNET = "172.31.250.0/24"
DEFAULT_EGRESS_GATEWAY = "172.31.250.1"
DEFAULT_EGRESS_ALLOW_DOMAINS = (
    "chatgpt.com",
    ".chatgpt.com",
    ".openai.com",
)
EGRESS_STATE_ROOT = Path("/tmp/sentinel-egress-isolation")


@dataclass(frozen=True)
class RunPaths:
    root: Path
    private: Path
    build: Path
    attempt: Path
    attempt_input: Path
    attempt_output: Path
    artifacts: Path
    rollouts: Path
    scoring: Path


@dataclass(frozen=True)
class EgressConfig:
    network_name: str
    subnet: str
    gateway: str
    proxy_port: int
    allow_domains: tuple[str, ...]


@dataclass(frozen=True)
class EgressRuntime:
    network_name: str
    subnet: str
    gateway: str
    proxy_port: int
    proxy_url: str
    allow_domains: tuple[str, ...]
    common_iptables_rules: tuple[tuple[str, ...], ...]
    proxy_iptables_rule: tuple[str, ...]


def main() -> int:
    args = parse_args()
    sentinel_src = args.sentinel_src.resolve()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    results_root = (args.results_root or Path.home() / "Desktop" / f"sentinel-container-run-{timestamp}").resolve()
    paths = make_paths(results_root)
    for path in paths.__dict__.values():
        path.mkdir(parents=True, exist_ok=True)

    instance = load_instance(args)
    task_id = instance["instance_id"]
    if args.task_id and args.task_id != task_id:
        raise SystemExit(f"--task-id {args.task_id!r} does not match instance JSON {task_id!r}")

    write_json(paths.private / "instance.json", instance)
    task_text = compose_task_text(instance)
    (paths.attempt_input / "TASK.md").write_text(task_text, encoding="utf-8")
    if args.agent_mode == "raw-codex":
        assert args.raw_prompt_file is not None
        raw_prompt_text = args.raw_prompt_file.expanduser().resolve().read_text(encoding="utf-8")
        (paths.attempt_input / "RAW_CODEX_PROMPT.md").write_text(
            compose_raw_codex_prompt(raw_prompt_text),
            encoding="utf-8",
        )
    runtime_config = prepare_codex_runtime_config(args.auth_dir.expanduser().resolve(), paths)

    base_image = args.base_image or dockerhub_image(instance, args.dockerhub_username)
    run_token = make_run_token(task_id, paths.root, timestamp)
    container_name = f"sentinel-attempt-{run_token}"
    attempt_image = args.attempt_image or f"sentinel-attempt:{safe_tag(task_id)[:72]}-{run_token[-16:]}"
    codex_version = args.codex_version or detect_codex_version()
    write_json(
        paths.attempt / "runner-identity.json",
        {
            "run_token": run_token,
            "container_name": container_name,
            "attempt_image": attempt_image,
            "agent_mode": args.agent_mode,
        },
    )

    print(f"results_root={paths.root}")
    print(f"agent_mode={args.agent_mode}")
    print(f"container_name={container_name}")
    print(f"base_image={base_image}")
    print(f"attempt_image={attempt_image}")
    print(f"codex_version={codex_version}")
    print("feasibility=using host ~/.codex/auth.json and config.toml as read-only runtime mounts")

    check_inputs(args, sentinel_src, paths, instance)
    if not args.skip_build:
        build_attempt_image(
            base_image=base_image,
            attempt_image=attempt_image,
            codex_version=codex_version,
            sentinel_src=sentinel_src,
            build_dir=paths.build,
            platform=args.platform,
        )

    egress_config = None
    if not args.disable_egress_isolation:
        allow_domains = tuple(args.egress_allow_domain or DEFAULT_EGRESS_ALLOW_DOMAINS)
        egress_config = EgressConfig(
            network_name=args.egress_network_name,
            subnet=args.egress_subnet,
            gateway=args.egress_gateway,
            proxy_port=args.egress_proxy_port,
            allow_domains=allow_domains,
        )

    start_utc = datetime.now(timezone.utc)
    with egress_isolation(paths, egress_config, run_token=run_token) as egress:
        sentinel_rc = run_attempt_container(
            image=attempt_image,
            container_name=container_name,
            paths=paths,
            instance=instance,
            auth_dir=args.auth_dir.expanduser().resolve(),
            runtime_config=runtime_config,
            model=args.model,
            platform=args.platform,
            extra_supervisor_args=args.supervisor_args,
            egress=egress,
            agent_mode=args.agent_mode,
        )
    end_utc = datetime.now(timezone.utc)

    summary = collect_rollouts(paths, container_cwd=CONTAINER_CWD, start_utc=start_utc, end_utc=end_utc)
    test_evidence = scan_test_evidence(paths)
    write_json(paths.rollouts / "rollout_collection_summary.json", summary)
    (paths.attempt / "sentinel-exit-code.txt").write_text(f"{sentinel_rc}\n", encoding="utf-8")

    scoring_rc = score_attempt_if_sentinel_succeeded(
        args=args,
        paths=paths,
        instance=instance,
        sentinel_rc=sentinel_rc,
    )
    if sentinel_rc == 0 and not args.skip_score:
        summarize_scoring(paths, instance)

    write_run_report(paths, instance, base_image, attempt_image, codex_version, sentinel_rc, scoring_rc, summary, test_evidence)
    print(f"run_report={paths.root / 'run_report.md'}")
    return 0 if sentinel_rc == 0 and scoring_rc == 0 else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one Sentinel attempt inside a SWE-bench Pro instance container.")
    parser.add_argument("--task-id", help="SWE-bench Pro instance_id to fetch from HuggingFace.")
    parser.add_argument("--instance-json", type=Path, help="Path to a JSON file containing one SWE-bench Pro instance row.")
    parser.add_argument("--results-root", type=Path, help="Directory for all run outputs.")
    parser.add_argument("--sentinel-src", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--swe-bench-pro-dir", type=Path, help="Path to the SWE-bench_Pro-os checkout used for scoring.")
    parser.add_argument("--dockerhub-username", default=DEFAULT_DOCKERHUB_USERNAME)
    parser.add_argument("--base-image", help="Full Docker image to use as the attempt base. Defaults to dockerhub_tag.")
    parser.add_argument("--attempt-image", help="Docker tag for the built attempt image.")
    parser.add_argument("--codex-version", help="Version of @openai/codex to install. Defaults to local codex --version.")
    parser.add_argument("--auth-dir", type=Path, default=Path.home() / ".codex")
    parser.add_argument("--platform", default=DEFAULT_PLATFORM)
    parser.add_argument("--model", help="Optional model passed to supervisor.")
    parser.add_argument(
        "--agent-mode",
        choices=["supervisor", "raw-codex"],
        default="supervisor",
        help="Run either Sentinel supervisor+coder or a single raw Codex coder inside the same harness.",
    )
    parser.add_argument(
        "--raw-prompt-file",
        type=Path,
        help="Prompt file used for --agent-mode raw-codex. The canonical TASK.md is still written separately.",
    )
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-score", action="store_true")
    parser.add_argument(
        "--disable-egress-isolation",
        action="store_true",
        help="Run the attempt container with Docker's default networking and no host egress filter.",
    )
    parser.add_argument("--egress-network-name", default=DEFAULT_EGRESS_NETWORK)
    parser.add_argument("--egress-subnet", default=DEFAULT_EGRESS_SUBNET)
    parser.add_argument("--egress-gateway", default=DEFAULT_EGRESS_GATEWAY)
    parser.add_argument("--egress-container-ip", help=argparse.SUPPRESS)
    parser.add_argument("--egress-proxy-port", type=int, default=0, help="Host proxy port; 0 picks a free port.")
    parser.add_argument(
        "--egress-allow-domain",
        action="append",
        help="Allowed CONNECT domain for the host egress proxy. Repeat to replace the default allowlist.",
    )
    parser.add_argument("supervisor_args", nargs=argparse.REMAINDER, help="Extra args after -- are passed to supervisor.")
    args = parser.parse_args()
    if not args.instance_json and not args.task_id:
        parser.error("provide --instance-json or --task-id")
    if args.supervisor_args and args.supervisor_args[0] == "--":
        args.supervisor_args = args.supervisor_args[1:]
    if args.agent_mode == "raw-codex" and args.raw_prompt_file is None:
        parser.error("--raw-prompt-file is required with --agent-mode raw-codex")
    if args.agent_mode == "raw-codex" and args.supervisor_args:
        parser.error("extra supervisor args are only valid with --agent-mode supervisor")
    return args


def make_paths(root: Path) -> RunPaths:
    return RunPaths(
        root=root,
        private=root / "private",
        build=root / "build",
        attempt=root / "attempt",
        attempt_input=root / "attempt" / "input",
        attempt_output=root / "attempt" / "output",
        artifacts=root / "attempt" / "output" / "artifacts",
        rollouts=root / "rollouts",
        scoring=root / "scoring",
    )


def load_instance(args: argparse.Namespace) -> dict[str, Any]:
    if args.instance_json:
        data = json.loads(args.instance_json.read_text(encoding="utf-8"))
        return data["row"] if isinstance(data, dict) and isinstance(data.get("row"), dict) else data
    assert args.task_id
    return fetch_instance(args.task_id)


def fetch_instance(task_id: str) -> dict[str, Any]:
    offset = 0
    length = 100
    while True:
        query = urllib.parse.urlencode(
            {"dataset": DATASET, "config": "default", "split": "test", "offset": offset, "length": length}
        )
        url = f"https://datasets-server.huggingface.co/rows?{query}"
        with urllib.request.urlopen(url, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
        rows = payload.get("rows") or []
        for item in rows:
            row = item.get("row") or {}
            if row.get("instance_id") == task_id:
                row["_row_idx"] = item.get("row_idx")
                return row
        if len(rows) < length:
            raise SystemExit(f"instance_id not found in {DATASET}: {task_id}")
        offset += length


def check_inputs(args: argparse.Namespace, sentinel_src: Path, paths: RunPaths, instance: dict[str, Any]) -> None:
    required = ["instance_id", "repo", "base_commit", "dockerhub_tag", "problem_statement"]
    missing = [key for key in required if not instance.get(key)]
    if missing:
        raise SystemExit(f"instance row missing required fields: {', '.join(missing)}")
    if not (sentinel_src / "pyproject.toml").exists():
        raise SystemExit(f"sentinel source does not look like a Python project: {sentinel_src}")
    auth_dir = args.auth_dir.expanduser().resolve()
    for name in ["auth.json", "config.toml"]:
        if not (auth_dir / name).exists():
            raise SystemExit(f"missing Codex auth/config file: {auth_dir / name}")
    if not args.skip_score and not args.swe_bench_pro_dir:
        raise SystemExit("--swe-bench-pro-dir is required unless --skip-score is set")
    if args.swe_bench_pro_dir and not (args.swe_bench_pro_dir / "swe_bench_pro_eval.py").exists():
        raise SystemExit(f"missing swe_bench_pro_eval.py under {args.swe_bench_pro_dir}")
    for rel in ["codex-home/sessions", "codex-home/archived_sessions", "codex-home/.tmp"]:
        (paths.rollouts / rel).mkdir(parents=True, exist_ok=True)


def prepare_codex_runtime_config(auth_dir: Path, paths: RunPaths) -> Path:
    source = auth_dir / "config.toml"
    text = source.read_text(encoding="utf-8")
    if not re.search(r"(?m)^\s*zsh_path\s*=", text):
        text = 'zsh_path = "/usr/bin/zsh"\n' + text
    if re.search(r"(?m)^\s*web_search\s*=", text):
        text = re.sub(r"(?m)^\s*web_search\s*=.*$", 'web_search = "disabled"', text, count=1)
    else:
        text = 'web_search = "disabled"\n' + text
    runtime_config = paths.private / "codex-container-config.toml"
    runtime_config.write_text(text, encoding="utf-8")
    return runtime_config


def build_attempt_image(
    *,
    base_image: str,
    attempt_image: str,
    codex_version: str,
    sentinel_src: Path,
    build_dir: Path,
    platform: str,
) -> None:
    context = build_dir / "context"
    if context.exists():
        shutil.rmtree(context)
    context.mkdir(parents=True)
    copy_sentinel_source(sentinel_src, context / "sentinel-src")
    dockerfile = context / "Dockerfile"
    dockerfile.write_text(
        textwrap.dedent(
            f"""
            FROM python:3.11-slim-bullseye AS sentinel-python
            FROM {base_image}
            ARG CODEX_VERSION={codex_version}
            ENV PIP_DISABLE_PIP_VERSION_CHECK=1
            RUN if command -v apt-get >/dev/null 2>&1; then \\
                    apt-get update \\
                    && apt-get install -y --no-install-recommends ca-certificates zsh bash python3 python3-venv python3-pip \\
                    && if ! command -v npm >/dev/null 2>&1; then apt-get install -y --no-install-recommends nodejs npm; fi \\
                    && rm -rf /var/lib/apt/lists/*; \\
                elif command -v apk >/dev/null 2>&1; then \\
                    apk add --no-cache ca-certificates zsh bash python3 py3-pip py3-virtualenv nodejs npm; \\
                else \\
                    echo "Unsupported base image: no apt-get or apk" >&2; exit 1; \\
                fi \\
                && if [ ! -x /usr/bin/zsh ] && command -v zsh >/dev/null 2>&1; then mkdir -p /usr/bin && ln -s "$(command -v zsh)" /usr/bin/zsh; fi
            RUN npm install -g @openai/codex@${{CODEX_VERSION}} --no-audit --no-fund
            COPY --from=sentinel-python /usr/local /opt/sentinel-python
            COPY sentinel-src /opt/sentinel-src
            RUN set -eu; \\
                sentinel_python=""; \\
                for py in /usr/bin/python3.12 /usr/bin/python3.11 /usr/bin/python3 python3 /opt/sentinel-python/bin/python3.11; do \\
                    if [ -x "$py" ] || command -v "$py" >/dev/null 2>&1; then \\
                        py_path="$py"; \\
                        if command -v "$py" >/dev/null 2>&1; then py_path="$(command -v "$py")"; fi; \\
                        if "$py_path" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then \\
                            sentinel_python="$py_path"; \\
                            break; \\
                        fi; \\
                    fi; \\
                done; \\
                if [ -z "$sentinel_python" ]; then echo "Python >=3.11 required for sentinel venv" >&2; exit 1; fi; \\
                "$sentinel_python" -m venv /opt/sentinel-venv \\
                && PIP_INDEX_URL=https://pypi.org/simple PIP_EXTRA_INDEX_URL= /opt/sentinel-venv/bin/python -m pip install --upgrade pip setuptools wheel \\
                && PIP_INDEX_URL=https://pypi.org/simple PIP_EXTRA_INDEX_URL= /opt/sentinel-venv/bin/python -m pip install /opt/sentinel-src
            ENV SHELL="/usr/bin/zsh"
            ENV PATH="/opt/sentinel-venv/bin:${{PATH}}"
            WORKDIR /app
            """
        ).lstrip(),
        encoding="utf-8",
    )
    run(
        [
            "docker",
            "build",
            "--platform",
            platform,
            "-t",
            attempt_image,
            str(context),
        ],
        cwd=build_dir,
        log_path=build_dir / "docker-build.log",
    )


def copy_sentinel_source(src: Path, dst: Path) -> None:
    ignored = {
        ".git",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".test-runtime",
        "build",
        "dist",
        "*.egg-info",
    }

    def ignore(_dir: str, names: list[str]) -> set[str]:
        skipped: set[str] = set()
        for name in names:
            if (
                name in ignored
                or name.endswith(".egg-info")
                or name.endswith(".pyc")
                or name.endswith(".pyo")
            ):
                skipped.add(name)
        return skipped

    shutil.copytree(src, dst, ignore=ignore)


class _AllowlistProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        assert isinstance(server, _AllowlistProxyServer)
        self.request.settimeout(10)
        header = b""
        while b"\r\n\r\n" not in header and len(header) < 16384:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            header += chunk
        first_line = header.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        parts = first_line.split()
        if len(parts) < 3 or parts[0].upper() != "CONNECT":
            server.record("block", first_line or "<empty>", "non-connect")
            self._send_status(405, "Method Not Allowed")
            return

        host, sep, port_text = parts[1].rpartition(":")
        if not sep:
            server.record("block", parts[1], "missing-port")
            self._send_status(400, "Bad Request")
            return
        try:
            port = int(port_text)
        except ValueError:
            server.record("block", parts[1], "bad-port")
            self._send_status(400, "Bad Request")
            return

        target = f"{host}:{port}"
        if port != 443 or not server.host_allowed(host):
            server.record("block", target, "not-allowlisted")
            self._send_status(403, "Forbidden")
            return

        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except OSError as exc:
            server.record("error", target, f"connect-failed:{exc.__class__.__name__}")
            self._send_status(502, "Bad Gateway")
            return

        server.record("allow", target, "allowlisted")
        try:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._tunnel(self.request, upstream)
        finally:
            with contextlib.suppress(OSError):
                upstream.close()

    def _send_status(self, code: int, reason: str) -> None:
        response = f"HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        with contextlib.suppress(OSError):
            self.request.sendall(response.encode("ascii"))

    @staticmethod
    def _tunnel(left: socket.socket, right: socket.socket) -> None:
        sockets = [left, right]
        while sockets:
            readable, _, _ = select.select(sockets, [], [], 120)
            if not readable:
                return
            for source in readable:
                try:
                    data = source.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                target = right if source is left else left
                try:
                    target.sendall(data)
                except OSError:
                    return


class _AllowlistProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], allow_domains: tuple[str, ...], log_path: Path):
        super().__init__(server_address, _AllowlistProxyHandler)
        self.allow_domains = tuple(domain.lower().rstrip(".") for domain in allow_domains)
        self.log_path = log_path
        self._log_lock = threading.Lock()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("", encoding="utf-8")

    def host_allowed(self, host: str) -> bool:
        normalized = host.lower().rstrip(".")
        for allowed in self.allow_domains:
            if allowed.startswith("."):
                if normalized.endswith(allowed):
                    return True
            elif normalized == allowed:
                return True
        return False

    def record(self, decision: str, target: str, reason: str) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "decision": decision,
            "target": target,
            "reason": reason,
        }
        with self._log_lock:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")


@contextlib.contextmanager
def egress_isolation(paths: RunPaths, config: EgressConfig | None, *, run_token: str | None = None):
    if config is None:
        yield None
        return

    proxy = _AllowlistProxyServer(("0.0.0.0", config.proxy_port), config.allow_domains, paths.attempt / "egress-proxy.log")
    proxy_port = int(proxy.server_address[1])
    thread = threading.Thread(target=proxy.serve_forever, name="sentinel-egress-proxy", daemon=True)
    thread.start()
    common_rules = egress_common_iptables_rules(config.subnet, config.gateway)
    proxy_rule = egress_proxy_iptables_rule(config.subnet, config.gateway, proxy_port)
    runtime = EgressRuntime(
        network_name=config.network_name,
        subnet=config.subnet,
        gateway=config.gateway,
        proxy_port=proxy_port,
        proxy_url=f"http://{config.gateway}:{proxy_port}",
        allow_domains=config.allow_domains,
        common_iptables_rules=tuple(tuple(rule) for rule in common_rules),
        proxy_iptables_rule=tuple(proxy_rule),
    )
    holder = run_token or f"pid-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    shared_state: dict[str, Any] = {}
    write_json(paths.attempt / "egress-isolation.json", {
        "holder": holder,
        "runtime": {
            "network_name": runtime.network_name,
            "subnet": runtime.subnet,
            "gateway": runtime.gateway,
            "proxy_url": runtime.proxy_url,
            "allow_domains": list(runtime.allow_domains),
            "common_iptables_rules": [" ".join(rule) for rule in runtime.common_iptables_rules],
            "proxy_iptables_rule": " ".join(runtime.proxy_iptables_rule),
        },
    })
    try:
        shared_state = acquire_egress_shared(config, paths, holder=holder, proxy_port=proxy_port)
        egress_info_path = paths.attempt / "egress-isolation.json"
        egress_info = json.loads(egress_info_path.read_text(encoding="utf-8"))
        egress_info["shared_state"] = shared_state
        write_json(egress_info_path, egress_info)
        yield runtime
    finally:
        if shared_state:
            release_egress_shared(config, paths, holder=holder, proxy_port=proxy_port)
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=5)


def ensure_docker_network(config: EgressConfig, paths: RunPaths) -> bool:
    inspect = inspect_docker_network(config.network_name)
    if inspect.returncode == 0:
        validate_docker_network(config, inspect.stdout)
        return False

    cmd = [
        "docker",
        "network",
        "create",
        "--driver",
        "bridge",
        "--subnet",
        config.subnet,
        "--gateway",
        config.gateway,
        config.network_name,
    ]
    log_path = paths.attempt / "egress-docker-network-create.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as log:
        log.write("$ " + " ".join(cmd) + "\n")
        log.flush()
        created = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, text=True)
    if created.returncode == 0:
        return True

    # Another parallel runner may have created the shared network after our
    # initial inspect. Re-inspect and accept it only if the IPAM config matches.
    inspect = inspect_docker_network(config.network_name)
    if inspect.returncode == 0:
        validate_docker_network(config, inspect.stdout)
        return False
    raise SystemExit(
        f"failed to create docker network {config.network_name!r}; "
        f"see {log_path}"
    )


def inspect_docker_network(network_name: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "network", "inspect", network_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def validate_docker_network(config: EgressConfig, inspect_stdout: str) -> None:
    data = json.loads(inspect_stdout)
    ipam_configs = ((data[0].get("IPAM") or {}).get("Config") or []) if data else []
    expected = {"Subnet": config.subnet, "Gateway": config.gateway}
    if expected not in [{key: item.get(key) for key in expected} for item in ipam_configs]:
        raise SystemExit(
            f"docker network {config.network_name!r} exists but does not match "
            f"subnet={config.subnet} gateway={config.gateway}"
        )


def egress_common_iptables_rules(subnet: str, gateway: str) -> list[list[str]]:
    return [
        ["-s", subnet, "-d", gateway, "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
        ["-s", subnet, "-d", gateway, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
        ["-s", subnet, "-j", "REJECT", "--reject-with", "icmp-port-unreachable"],
    ]


def egress_proxy_iptables_rule(subnet: str, gateway: str, proxy_port: int) -> list[str]:
    return ["-s", subnet, "-d", gateway, "-p", "tcp", "--dport", str(proxy_port), "-j", "ACCEPT"]


def install_iptables_rules(rules: list[list[str]], paths: RunPaths, *, append_log: bool = False) -> None:
    log_path = paths.attempt / "egress-iptables.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if not append_log:
        log_path.write_text("", encoding="utf-8")
    # Insert terminal REJECT-style rules first, then allows above them.
    for rule in reversed(rules):
        install_iptables_rule(rule, log_path)


def install_iptables_rule(rule: list[str], log_path: Path) -> None:
    with log_path.open("a", encoding="utf-8") as log:
        check_cmd = ["iptables", "-C", "DOCKER-USER", *rule]
        log.write("$ " + " ".join(check_cmd) + "\n")
        log.flush()
        check = subprocess.run(check_cmd, stdout=log, stderr=subprocess.STDOUT, text=True)
        if check.returncode == 0:
            log.write("# already present\n")
            return
        insert_cmd = ["iptables", "-I", "DOCKER-USER", "1", *rule]
        log.write("$ " + " ".join(insert_cmd) + "\n")
        log.flush()
        subprocess.run(insert_cmd, stdout=log, stderr=subprocess.STDOUT, check=True, text=True)


def iptables_rule_present(rule: list[str]) -> bool:
    return (
        subprocess.run(
            ["iptables", "-C", "DOCKER-USER", *rule],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        ).returncode
        == 0
    )


def remove_iptables_rules(rules: list[list[str]], paths: RunPaths, *, append_log: bool = False) -> None:
    log_path = paths.attempt / "egress-iptables-cleanup.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append_log else "w"
    with log_path.open(mode, encoding="utf-8") as log:
        for rule in rules:
            check_cmd = ["iptables", "-C", "DOCKER-USER", *rule]
            log.write("$ " + " ".join(check_cmd) + "\n")
            log.flush()
            check = subprocess.run(check_cmd, stdout=log, stderr=subprocess.STDOUT, text=True)
            if check.returncode != 0:
                log.write("# absent\n")
                continue
            delete_cmd = ["iptables", "-D", "DOCKER-USER", *rule]
            log.write("$ " + " ".join(delete_cmd) + "\n")
            log.flush()
            subprocess.run(delete_cmd, stdout=log, stderr=subprocess.STDOUT, text=True)


def acquire_egress_shared(config: EgressConfig, paths: RunPaths, *, holder: str, proxy_port: int) -> dict[str, Any]:
    state_path = egress_state_path(config.network_name)
    common_rules = egress_common_iptables_rules(config.subnet, config.gateway)
    proxy_rule = egress_proxy_iptables_rule(config.subnet, config.gateway, proxy_port)
    with locked_egress_state(config.network_name):
        network_created = ensure_docker_network(config, paths)
        state = read_egress_state(state_path)
        holders = dict(state.get("holders") or {})
        if holders and not all(iptables_rule_present(rule) for rule in common_rules):
            holders = {}
        first_holder = not holders
        if first_holder:
            install_iptables_rules(common_rules, paths)
        else:
            (paths.attempt / "egress-iptables.log").write_text("", encoding="utf-8")
        install_iptables_rules([proxy_rule], paths, append_log=True)
        holders[holder] = {"proxy_port": proxy_port, "results_root": str(paths.root)}
        write_json(
            state_path,
            {
                "network_name": config.network_name,
                "subnet": config.subnet,
                "gateway": config.gateway,
                "holders": holders,
            },
        )
        return {
            "state_path": str(state_path),
            "network_created": network_created,
            "common_rules_installed": first_holder,
            "holder_count": len(holders),
        }


def release_egress_shared(config: EgressConfig, paths: RunPaths, *, holder: str, proxy_port: int) -> None:
    state_path = egress_state_path(config.network_name)
    common_rules = egress_common_iptables_rules(config.subnet, config.gateway)
    proxy_rule = egress_proxy_iptables_rule(config.subnet, config.gateway, proxy_port)
    with locked_egress_state(config.network_name):
        remove_iptables_rules([proxy_rule], paths)
        state = read_egress_state(state_path)
        holders = dict(state.get("holders") or {})
        holders.pop(holder, None)
        if holders:
            write_json(
                state_path,
                {
                    "network_name": config.network_name,
                    "subnet": config.subnet,
                    "gateway": config.gateway,
                    "holders": holders,
                },
            )
            return
        remove_iptables_rules(common_rules, paths, append_log=True)
        with contextlib.suppress(FileNotFoundError):
            state_path.unlink()
        subprocess.run(["docker", "network", "rm", config.network_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def read_egress_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def egress_state_path(network_name: str) -> Path:
    return EGRESS_STATE_ROOT / f"{safe_tag(network_name)}.json"


@contextlib.contextmanager
def locked_egress_state(network_name: str):
    EGRESS_STATE_ROOT.mkdir(parents=True, exist_ok=True)
    lock_path = EGRESS_STATE_ROOT / f"{safe_tag(network_name)}.lock"
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def git_history_cleanup_script(base_commit: str, *, artifacts_dir: str = "/attempt-out/artifacts") -> str:
    base = sh_single(base_commit)
    artifacts = sh_single(artifacts_dir)
    return textwrap.dedent(
        f"""
        mkdir -p {artifacts}
        {{
          echo "base_commit={base_commit}"
          echo "$ test HEAD == base"
          test "$(git rev-parse HEAD)" = {base}
          tracked_files="$(mktemp /tmp/sentinel-base-tracked.XXXXXX)"
          echo "$ git ls-files -z > $tracked_files"
          git ls-files -z > "$tracked_files"
          echo "$ snapshot old git config"
          old_user_email="$(git config --get user.email || true)"
          old_user_name="$(git config --get user.name || true)"
          echo "$ rm -rf .git"
          rm -rf .git
          echo "$ git init -q"
          git init -q
          if [ -n "$old_user_email" ]; then git config user.email "$old_user_email"; else git config user.email "sentinel@example.invalid"; fi
          if [ -n "$old_user_name" ]; then git config user.name "$old_user_name"; else git config user.name "Sentinel Base Snapshot"; fi
          echo "$ GIT_LITERAL_PATHSPECS=1 git add -f --pathspec-from-file=$tracked_files --pathspec-file-nul"
          GIT_LITERAL_PATHSPECS=1 git add -f --pathspec-from-file="$tracked_files" --pathspec-file-nul
          rm -f "$tracked_files"
          echo "$ git commit -qm 'sentinel base snapshot'"
          GIT_AUTHOR_DATE="2000-01-01T00:00:00Z" GIT_COMMITTER_DATE="2000-01-01T00:00:00Z" git commit -qm "sentinel base snapshot"
          echo "$ git branch -M sentinel-base"
          git branch -M sentinel-base
          echo "$ git reflog expire --expire=now --all"
          git reflog expire --expire=now --all
          echo "$ git gc --prune=now"
          git gc --prune=now
        }} > {artifacts}/git-history-cleanup.log 2>&1
        {{
          echo "original_base_commit={base_commit}"
          printf "head="
          git rev-parse HEAD
          printf "reachable_commit_count="
          git rev-list --all --count
          if [ "$(git rev-list --all --count)" != "1" ]; then
            echo "ERROR: expected exactly one reachable snapshot commit" >&2
            exit 1
          fi
          if git cat-file -e {base}^{{commit}} 2>/dev/null; then
            echo "ERROR: original base commit is still reachable in rewritten repository" >&2
            exit 1
          fi
          echo "original_base_commit_unreachable=yes"
          echo "tags:"
          git tag -l
          echo "remote_refs:"
          git for-each-ref --format='%(refname) %(objectname)' refs/remotes
          echo "heads:"
          git for-each-ref --format='%(refname:short) %(objectname)' refs/heads
          echo "log_all:"
          git log --all --oneline -20
          echo "status:"
          git status --short
        }} > {artifacts}/git-history-cleanup-verify.txt 2>&1
        """
    ).strip()


def run_attempt_container(
    *,
    image: str,
    container_name: str,
    paths: RunPaths,
    instance: dict[str, Any],
    auth_dir: Path,
    runtime_config: Path,
    model: str | None,
    platform: str,
    extra_supervisor_args: list[str],
    egress: EgressRuntime | None,
    agent_mode: str = "supervisor",
) -> int:
    base_commit = str(instance["base_commit"])
    agent_command = agent_invocation_script(agent_mode=agent_mode, model=model, extra_supervisor_args=extra_supervisor_args)
    command = textwrap.dedent(
        f"""
        set -euo pipefail
        cd /app
        git reset --hard {sh_single(base_commit)}
        git clean -fd
        {git_history_cleanup_script(base_commit)}
        sentinel_diff_base_ref="$(git rev-parse HEAD)"
        echo "$sentinel_diff_base_ref" > /attempt-out/artifacts/sentinel-diff-base-ref.txt
        cp /attempt-input/TASK.md /app/TASK.md
        export SENTINEL_CODER_SANDBOX=danger-full-access
        start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        echo "$start_utc" > /attempt-out/sentinel-start-utc.txt
        echo {sh_single(agent_mode)} > /attempt-out/agent-mode.txt
        set +e
        {agent_command}
        rc=$?
        set -e
        date -u +%Y-%m-%dT%H:%M:%SZ > /attempt-out/sentinel-end-utc.txt
        echo "$rc" > /attempt-out/sentinel-exit-code.txt
        mkdir -p /attempt-out/artifacts
        cp /app/TASK.md /attempt-out/artifacts/TASK.md
        if [ -d /app/.supervisor ]; then cp -a /app/.supervisor /attempt-out/artifacts/.supervisor; fi
        git status --short > /attempt-out/artifacts/final_git_status.txt
        git add -A -- \\
          ':(exclude).supervisor' ':(exclude).supervisor/**' \\
          ':(exclude)TASK.md' \\
          ':(exclude)pyproject.toml' ':(exclude)setup.cfg' ':(exclude)setup.py' \\
          ':(exclude)tox.ini' ':(exclude)*.cfg' ':(exclude)*.toml'
        git diff --cached --binary "$sentinel_diff_base_ref" > /attempt-out/artifacts/agent_diff_vs_base.diff
        git diff --cached --stat "$sentinel_diff_base_ref" > /attempt-out/artifacts/agent_diff_vs_base.stat || true
        git reset --quiet
        tar --exclude=.git --exclude=node_modules --exclude=.supervisor -czf /attempt-out/artifacts/final-worktree-no-git-no-node_modules.tar.gz -C /app .
        exit "$rc"
        """
    ).strip()
    log_path = paths.attempt / "sentinel-live.log"
    cmd = [
        "docker",
        "run",
        "--rm",
        "--platform",
        platform,
        # Codex read-only/workspace-write sandboxes use bubblewrap namespaces.
        # The attempt container is disposable, and privileged mode keeps those
        # sandboxes usable inside Docker instead of weakening supervisor policy.
        "--privileged",
        "--name",
        container_name,
    ]
    if egress:
        cmd.extend(
            [
                "--network",
                egress.network_name,
                "-e",
                f"HTTPS_PROXY={egress.proxy_url}",
                "-e",
                f"HTTP_PROXY={egress.proxy_url}",
                "-e",
                f"https_proxy={egress.proxy_url}",
                "-e",
                f"http_proxy={egress.proxy_url}",
                "-e",
                "ALL_PROXY=",
                "-e",
                "all_proxy=",
                "-e",
                "NO_PROXY=localhost,127.0.0.1,::1",
                "-e",
                "no_proxy=localhost,127.0.0.1,::1",
            ]
        )
    cmd.extend(
        [
            "-v",
            f"{paths.attempt_input}:/attempt-input:ro",
            "-v",
            f"{paths.attempt_output}:/attempt-out",
            "-v",
            f"{paths.rollouts / 'codex-home'}:/root/.codex",
            "-v",
            f"{auth_dir / 'auth.json'}:/root/.codex/auth.json:ro",
            "-v",
            f"{runtime_config}:/root/.codex/config.toml:ro",
            "--entrypoint",
            "/bin/bash",
            image,
            "-c",
            command,
        ]
    )
    (paths.attempt / "docker-run-command.json").write_text(json.dumps(cmd, indent=2) + "\n", encoding="utf-8")
    return run_streaming(cmd, log_path=log_path)


def agent_invocation_script(*, agent_mode: str, model: str | None, extra_supervisor_args: list[str]) -> str:
    if agent_mode == "supervisor":
        return (
            "/opt/sentinel-venv/bin/sentinel --task TASK.md --start-over "
            f"{('--model ' + sh_single(model)) if model else ''} "
            f"{' '.join(sh_single(arg) for arg in extra_supervisor_args)}"
        ).strip()
    if agent_mode == "raw-codex":
        model_args = f"--model {sh_single(model)} " if model else ""
        return (
            "codex exec --json "
            "--cd /app "
            "--dangerously-bypass-approvals-and-sandbox "
            f"-c {sh_single(CODEX_WEB_SEARCH_DISABLED_CONFIG)} "
            f"{model_args}"
            "--output-last-message /attempt-out/raw-codex-final-message.txt "
            "- < /attempt-input/RAW_CODEX_PROMPT.md"
        )
    raise ValueError(f"unknown agent_mode: {agent_mode}")


def collect_rollouts(paths: RunPaths, *, container_cwd: str, start_utc: datetime, end_utc: datetime) -> dict[str, Any]:
    artifacts_supervisor = paths.artifacts / ".supervisor"
    coder_thread_id = None
    config_path = artifacts_supervisor / "config.json"
    if config_path.exists():
        try:
            coder_thread_id = json.loads(config_path.read_text(encoding="utf-8")).get("coder_thread_id")
        except json.JSONDecodeError:
            coder_thread_id = None

    supervisor_thread_ids = set()
    wakes_path = artifacts_supervisor / "supervisor_wakes.jsonl"
    if wakes_path.exists():
        for line in wakes_path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            thread_id = item.get("thread_id")
            if thread_id:
                supervisor_thread_ids.add(thread_id)

    for bucket in ["coder", "supervisor", "other"]:
        (paths.rollouts / bucket).mkdir(parents=True, exist_ok=True)

    matched: list[dict[str, Any]] = []
    rollout_roots = [
        paths.rollouts / "codex-home" / "sessions",
        paths.rollouts / "codex-home" / "archived_sessions",
        paths.rollouts / "sessions",
        paths.rollouts / "archived_sessions",
    ]
    for rollout_root in rollout_roots:
        if not rollout_root.exists():
            continue
        for path in rollout_root.rglob("*.jsonl"):
            meta = read_rollout_meta(path)
            if not meta:
                continue
            if meta.get("cwd") != container_cwd:
                continue
            ts = parse_utc(meta.get("timestamp"))
            if ts and (ts < start_utc.replace(tzinfo=timezone.utc) or ts > end_utc.replace(tzinfo=timezone.utc)):
                continue
            rollout_id = meta.get("id")
            bucket = rollout_bucket(
                rollout_id=rollout_id,
                role_hint=meta.get("role_hint"),
                coder_thread_id=coder_thread_id,
                supervisor_thread_ids=supervisor_thread_ids,
            )
            dest = paths.rollouts / bucket / path.name
            if path.resolve() != dest.resolve():
                shutil.copy2(path, dest)
            matched.append(
                {
                    "id": rollout_id,
                    "cwd": meta.get("cwd"),
                    "source": str(path),
                    "bucket": bucket,
                    "role_hint": meta.get("role_hint"),
                }
            )

    return {
        "container_cwd": container_cwd,
        "start_utc": start_utc.isoformat(),
        "end_utc": end_utc.isoformat(),
        "coder_thread_id": coder_thread_id,
        "supervisor_thread_ids": sorted(supervisor_thread_ids),
        "matched_count": len(matched),
        "coder_count": sum(1 for item in matched if item["bucket"] == "coder"),
        "supervisor_count": sum(1 for item in matched if item["bucket"] == "supervisor"),
        "other_count": sum(1 for item in matched if item["bucket"] == "other"),
        "matched": matched,
    }


def read_rollout_meta(path: Path) -> dict[str, Any] | None:
    try:
        with path.open(encoding="utf-8") as handle:
            meta: dict[str, Any] | None = None
            role_hint: str | None = None
            for index, line in enumerate(handle):
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if item.get("type") == "session_meta":
                    payload = item.get("payload") or {}
                    meta = {
                        "id": payload.get("id"),
                        "cwd": payload.get("cwd"),
                        "timestamp": payload.get("timestamp") or item.get("timestamp"),
                    }
                if role_hint is None:
                    role_hint = rollout_role_hint_from_item(item)
                if meta is not None and role_hint is not None:
                    break
                if index >= 120 and meta is not None:
                    break
    except OSError:
        return None
    if meta is None:
        return None
    if role_hint is not None:
        meta["role_hint"] = role_hint
    return meta


def rollout_bucket(
    *,
    rollout_id: Any,
    role_hint: Any,
    coder_thread_id: str | None,
    supervisor_thread_ids: set[str],
) -> str:
    if isinstance(rollout_id, str) and rollout_id in supervisor_thread_ids:
        return "supervisor"
    if isinstance(rollout_id, str) and coder_thread_id and rollout_id == coder_thread_id:
        return "coder"
    if role_hint == "supervisor":
        return "supervisor"
    if role_hint == "coder":
        return "coder"
    return "other"


def rollout_role_hint_from_item(item: dict[str, Any]) -> str | None:
    text = rollout_prompt_text(item)
    if not text:
        return None
    lowered = text.lower()
    if (
        "you are the coding agent for this task" in lowered
        or "an automated supervisor observes your work" in lowered
        or "read the task file first:" in lowered
        or ("# benchmark task" in lowered and "/app/task.md" in lowered)
    ):
        return "coder"
    if (
        "runtime oversight controller" in lowered
        or "structured output self-test" in lowered
        or ("current_summary" in lowered and "wake_sequence" in lowered)
    ):
        return "supervisor"
    return None


def rollout_prompt_text(item: dict[str, Any]) -> str:
    payload = item.get("payload")
    candidates: list[Any] = []
    if isinstance(payload, dict):
        if payload.get("type") == "user_message":
            candidates.append(payload.get("message"))
        if payload.get("type") == "message":
            candidates.append(payload.get("content"))
    if item.get("type") == "response_item" and isinstance(payload, dict):
        candidates.append(payload.get("content"))
    parts: list[str] = []
    for candidate in candidates:
        collect_rollout_text(candidate, parts)
    return "\n".join(parts)


def collect_rollout_text(value: Any, parts: list[str]) -> None:
    if isinstance(value, str):
        if value:
            parts.append(value)
        return
    if isinstance(value, list):
        for item in value:
            collect_rollout_text(item, parts)
        return
    if isinstance(value, dict):
        for key in ("text", "content", "message"):
            collect_rollout_text(value.get(key), parts)


def scan_test_evidence(paths: RunPaths) -> dict[str, Any]:
    patterns = [
        "npm test",
        "npm run",
        "npx mocha",
        "pytest",
        "go test",
        "cargo test",
        "yarn test",
        "pnpm test",
    ]
    hits: list[str] = []
    search_files = [paths.attempt / "sentinel-live.log"]
    search_files.extend((paths.rollouts / "coder").glob("*.jsonl"))
    search_files.extend((paths.rollouts / "other").glob("*.jsonl"))
    for path in search_files:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            lower = line.lower()
            if any(pattern in lower for pattern in patterns):
                hits.append(f"{path}: {line[:500]}")
    out = paths.attempt / "test-command-evidence.txt"
    out.write_text("\n".join(hits) + ("\n" if hits else ""), encoding="utf-8")
    return {"count": len(hits), "path": str(out), "examples": hits[:10]}


def run_scoring(
    *,
    paths: RunPaths,
    instance: dict[str, Any],
    swe_bench_pro_dir: Path | None,
    dockerhub_username: str,
    platform: str,
) -> int:
    assert swe_bench_pro_dir is not None
    raw_sample = paths.scoring / "raw_sample.jsonl"
    patch_json = paths.scoring / "patches.json"
    harness_output = paths.scoring / "harness-output"
    harness_output.mkdir(parents=True, exist_ok=True)
    raw_sample.write_text(json.dumps(scoring_sample_for_scorer(instance)) + "\n", encoding="utf-8")
    patch = (paths.artifacts / "agent_diff_vs_base.diff").read_text(encoding="utf-8") if (paths.artifacts / "agent_diff_vs_base.diff").exists() else ""
    patch_json.write_text(
        json.dumps([{"instance_id": instance["instance_id"], "patch": patch, "prefix": "container_attempt"}], indent=2)
        + "\n",
        encoding="utf-8",
    )
    venv = paths.scoring / "eval-venv"
    if not venv.exists():
        run([sys.executable, "-m", "venv", str(venv)], log_path=paths.scoring / "eval-venv-create.log")
        pip = venv / "bin" / "pip"
        requirements = swe_bench_pro_dir / "requirements.txt"
        install_cmd = [str(pip), "install", "--upgrade", "pip", "setuptools", "wheel"]
        run(install_cmd, log_path=paths.scoring / "eval-venv-install.log")
        if requirements.exists():
            run([str(pip), "install", "-r", str(requirements)], log_path=paths.scoring / "eval-venv-install.log", append=True)
        run([str(pip), "install", "docker", "pandas", "tqdm"], log_path=paths.scoring / "eval-venv-install.log", append=True)

    cmd = [
        str(venv / "bin" / "python"),
        str(swe_bench_pro_dir / "swe_bench_pro_eval.py"),
        "--raw_sample_path",
        str(raw_sample),
        "--patch_path",
        str(patch_json),
        "--output_dir",
        str(harness_output),
        "--dockerhub_username",
        dockerhub_username,
        "--scripts_dir",
        str(swe_bench_pro_dir / "run_scripts"),
        "--use_local_docker",
        "--num_workers",
        "1",
        "--redo",
        "--docker_platform",
        platform,
    ]
    (paths.scoring / "eval_command.json").write_text(json.dumps(cmd, indent=2) + "\n", encoding="utf-8")
    return run_streaming(cmd, log_path=paths.scoring / "eval-run.log", cwd=swe_bench_pro_dir)


def score_attempt_if_sentinel_succeeded(
    *,
    args: argparse.Namespace,
    paths: RunPaths,
    instance: dict[str, Any],
    sentinel_rc: int,
) -> int:
    if sentinel_rc != 0:
        write_json(
            paths.scoring / "score-skipped.json",
            {
                "reason": "sentinel exited nonzero; run is infra-invalid/not-scored",
                "sentinel_exit_code": sentinel_rc,
            },
        )
        return 0
    if args.skip_score:
        return 0
    return run_scoring(
        paths=paths,
        instance=instance,
        swe_bench_pro_dir=args.swe_bench_pro_dir.resolve() if args.swe_bench_pro_dir else None,
        dockerhub_username=args.dockerhub_username,
        platform=args.platform,
    )


def summarize_scoring(paths: RunPaths, instance: dict[str, Any]) -> None:
    instance_id = instance["instance_id"]
    output_path = paths.scoring / "harness-output" / instance_id / "container_attempt_output.json"
    eval_results_path = paths.scoring / "harness-output" / "eval_results.json"
    summary: dict[str, Any] = {"instance_id": instance_id, "output_path": str(output_path), "eval_results_path": str(eval_results_path)}
    if eval_results_path.exists():
        summary["eval_results"] = json.loads(eval_results_path.read_text(encoding="utf-8"))
    if output_path.exists():
        output = json.loads(output_path.read_text(encoding="utf-8"))
        passed = {item["name"] for item in output.get("tests", []) if item.get("status") == "PASSED"}
        scorer_sample = scoring_sample_for_scorer(instance)
        fail_to_pass = parse_list_field(scorer_sample.get("fail_to_pass", "[]"))
        pass_to_pass = parse_list_field(scorer_sample.get("pass_to_pass", "[]"))
        summary["fail_to_pass_total"] = len(fail_to_pass)
        summary["fail_to_pass_failed"] = sorted(set(fail_to_pass) - passed)
        summary["pass_to_pass_total"] = len(pass_to_pass)
        summary["pass_to_pass_regressed"] = sorted(set(pass_to_pass) - passed)
    write_json(paths.scoring / "scoring_summary.json", summary)


def write_run_report(
    paths: RunPaths,
    instance: dict[str, Any],
    base_image: str,
    attempt_image: str,
    codex_version: str,
    sentinel_rc: int,
    scoring_rc: int,
    rollouts: dict[str, Any],
    test_evidence: dict[str, Any],
) -> None:
    scoring_summary_path = paths.scoring / "scoring_summary.json"
    scoring_summary = json.loads(scoring_summary_path.read_text(encoding="utf-8")) if scoring_summary_path.exists() else {}
    identity_path = paths.attempt / "runner-identity.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8")) if identity_path.exists() else {}
    egress_isolation_path = paths.attempt / "egress-isolation.json"
    egress_enabled = egress_isolation_path.exists()
    report = f"""# Sentinel Container Attempt Report

## Instance

- instance_id: `{instance.get('instance_id')}`
- repo: `{instance.get('repo')}`
- base_commit: `{instance.get('base_commit')}`
- dockerhub_tag: `{instance.get('dockerhub_tag')}`
- base_image: `{base_image}`
- attempt_image: `{attempt_image}`
- container_name: `{identity.get('container_name')}`

## Feasibility

- Base image provided `/app`, Python, Node/npm, git/curl, and outbound network during preflight.
- Codex CLI is installed into the attempt image as `@openai/codex@{codex_version}`.
- Codex auth is provided at runtime by a read-only mount from host `~/.codex/auth.json`; config is generated from host `~/.codex/config.toml` with `zsh_path = "/usr/bin/zsh"` for Linux unified exec.
- Codex rollouts are mounted out through one host-backed `/root/.codex` directory, so `sessions` and `archived_sessions` stay on the same filesystem for Codex archive renames.
- The attempt container sets `SENTINEL_CODER_SANDBOX=danger-full-access` because Codex's Linux read-only sandbox requires user namespace support that was unavailable in the nested Docker attempt container during feasibility probes.
- Codex web search is disabled in the generated runtime config and Codex process flags with `{CODEX_WEB_SEARCH_DISABLED_CONFIG}`.

## Attempt

- Agent mode: `{identity.get('agent_mode')}`
- Sentinel cwd inside container: `{CONTAINER_CWD}`
- TASK.md path inside container: `{CONTAINER_CWD}/TASK.md`
- Coder sandbox inside attempt container: `danger-full-access`
- Agent exit code: `{sentinel_rc}`
- Live log: `{paths.attempt / 'sentinel-live.log'}`
- Raw Codex final message: `{paths.attempt_output / 'raw-codex-final-message.txt'}`
- Agent diff: `{paths.artifacts / 'agent_diff_vs_base.diff'}`
- Supervisor state: `{paths.artifacts / '.supervisor'}`
- Test command evidence count: `{test_evidence.get('count')}`
- Test command evidence file: `{test_evidence.get('path')}`

## Egress Isolation

- Enabled during agent run: `{egress_enabled}`
- Isolation config: `{egress_isolation_path if egress_enabled else None}`
- Proxy CONNECT log: `{paths.attempt / 'egress-proxy.log'}`
- iptables install log: `{paths.attempt / 'egress-iptables.log'}`
- iptables cleanup log: `{paths.attempt / 'egress-iptables-cleanup.log'}`

## Rollouts

- Mounted Codex home: `{paths.rollouts / 'codex-home'}`
- Mounted sessions dir: `{paths.rollouts / 'codex-home' / 'sessions'}`
- Mounted archived sessions dir: `{paths.rollouts / 'codex-home' / 'archived_sessions'}`
- Matched rollouts: `{rollouts.get('matched_count')}`
- Coder rollouts: `{rollouts.get('coder_count')}`
- Supervisor rollouts: `{rollouts.get('supervisor_count')}`
- Other `/app` rollouts: `{rollouts.get('other_count')}`
- Summary: `{paths.rollouts / 'rollout_collection_summary.json'}`

## Scoring

- Scoring exit code: `{scoring_rc}`
- Eval command: `{paths.scoring / 'eval_command.json'}`
- Eval log: `{paths.scoring / 'eval-run.log'}`
- Scoring summary: `{scoring_summary_path}`
- Eval results: `{scoring_summary.get('eval_results')}`
- fail_to_pass failed: `{scoring_summary.get('fail_to_pass_failed')}`
- pass_to_pass regressed: `{scoring_summary.get('pass_to_pass_regressed')}`
"""
    (paths.root / "run_report.md").write_text(report, encoding="utf-8")


def dockerhub_image(instance: dict[str, Any], dockerhub_username: str) -> str:
    return f"{dockerhub_username}/sweap-images:{instance['dockerhub_tag']}"


def detect_codex_version() -> str:
    try:
        output = subprocess.check_output(["codex", "--version"], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "0.134.0"
    match = re.search(r"(\d+\.\d+\.\d+)", output)
    return match.group(1) if match else "0.134.0"


def compose_task_text(instance: dict[str, Any]) -> str:
    """Compose the canonical SWE-bench Pro task text shown to the agent."""
    problem_statement = decode_text_field(instance["problem_statement"])
    requirements = decode_text_field(instance.get("requirements", ""))
    interface = decode_text_field(instance.get("interface", ""))
    return (
        f"{problem_statement}\n\n"
        f"Requirements:\n{requirements}\n\n"
        f"New interfaces introduced:\n{interface}"
    )


def compose_raw_codex_prompt(prompt_text: str) -> str:
    return (
        prompt_text.rstrip()
        + "\n\n"
        + "# Benchmark task\n\n"
        + "Read `/app/TASK.md` first. It contains the benchmark problem statement, "
        + "requirements, and new interfaces. Implement that task in the `/app` "
        + "repository. Leave the final code changes in the worktree for scoring.\n"
    )


def decode_text_field(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        return str(value)
    return decode_problem_statement(value)


def decode_problem_statement(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith('"') and stripped.endswith('"'):
        try:
            decoded = json.loads(stripped)
            if isinstance(decoded, str):
                return decoded
        except json.JSONDecodeError:
            pass
    return value


def parse_list_field(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if not isinstance(value, str):
        return []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    except json.JSONDecodeError:
        pass
    try:
        import ast

        parsed = ast.literal_eval(value)
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    except (SyntaxError, ValueError):
        pass
    return []


def scoring_sample_for_scorer(instance: dict[str, Any]) -> dict[str, Any]:
    sample = dict(instance)
    if "fail_to_pass" not in sample and "FAIL_TO_PASS" in sample:
        sample["fail_to_pass"] = sample["FAIL_TO_PASS"]
    if "pass_to_pass" not in sample and "PASS_TO_PASS" in sample:
        sample["pass_to_pass"] = sample["PASS_TO_PASS"]
    return sample


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def safe_tag(value: str) -> str:
    tag = re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip(".-")
    return tag[:96] or "attempt"


def make_run_token(task_id: str, results_root: Path, timestamp: str) -> str:
    root_part = safe_tag(results_root.name)[:32]
    task_part = safe_tag(task_id)[:48]
    unique = f"{timestamp}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    token = safe_tag(f"{task_part}-{root_part}-{unique}")
    return token[:120] or f"run-{uuid.uuid4().hex[:12]}"


def sh_single(value: str | None) -> str:
    if value is None:
        return "''"
    return "'" + value.replace("'", "'\"'\"'") + "'"


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(cmd: list[str], *, cwd: Path | None = None, log_path: Path, append: bool = False) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with log_path.open(mode, encoding="utf-8") as log:
        log.write("$ " + " ".join(cmd) + "\n")
        log.flush()
        subprocess.run(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, check=True, text=True)


def run_streaming(cmd: list[str], *, log_path: Path, cwd: Path | None = None) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        log.write("$ " + " ".join(cmd) + "\n")
        log.flush()
        process = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        assert process.stdout is not None
        for line in process.stdout:
            sys.stdout.write(line)
            log.write(line)
        return process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
