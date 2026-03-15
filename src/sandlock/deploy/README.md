# sandlock[deploy] — SSH-Based Remote Sandbox Deployment

Deploy kernel-enforced sandboxes to any machine you can SSH into. No root, no
Docker, no agents, no central server.

```bash
pip install sandlock[deploy]
```

## Quick Start

```bash
# Deploy sandlock to a remote host
sandlock deploy user@host --profile restricted

# Run a sandboxed command remotely
sandlock run --host user@host -e "echo hello"

# Same Python API, local or remote
python3 -c "
from sandlock import Sandbox, Policy
policy = Policy(fs_readable=['/usr', '/tmp'], fs_writable=['/tmp'])
result = Sandbox(policy, host='user@host').run(['echo', 'hello'])
print(result.stdout.decode())
"
```

## Targets

Define deployment targets in `sandlock.toml` (project root or
`~/.config/sandlock/sandlock.toml`):

```toml
[target.ci]
host = "ci@runner-1"
profile = "restricted"
repo = "git@github.com:org/project.git"
workdir = "/opt/project"
setup = "pip install -r requirements.txt"

[target.staging]
host = "deploy@staging.example.com"
port = 2222
key = "~/.ssh/staging_key"
profile = "web"
```

Then deploy and run by name:

```bash
sandlock deploy ci          # install sandlock, push profile, clone repo, run setup
sandlock run --host ci -e "pytest"
```

Target fields:

| Field | Description |
|-------|-------------|
| `host` | Remote host (required, `user@host`) |
| `profile` | Sandbox profile name |
| `repo` | Git repo URL to clone |
| `branch` | Git branch to checkout |
| `workdir` | Working directory (auto-added to sandbox allow list) |
| `setup` | Shell commands to run after clone |
| `port` | SSH port (default: 22) |
| `key` | Path to SSH private key |
| `pubkey` | Public key for authorized_keys setup |
| `force_command` | Configure SSH ForceCommand (bool) |
| `remote_python` | Python interpreter on remote (default: `python3`) |

## SSH Integration

Sandlock can sandbox all SSH sessions for a key or user.

**Per-key sandbox** via `authorized_keys`:

```bash
sandlock deploy user@host --profile restricted \
    --pubkey ~/.ssh/id_rsa.pub --force-command
```

This configures the remote `authorized_keys` so every command through that
key runs inside a sandlock sandbox.

**Per-user sandbox** via `sshd_config`:

```
Match User deploy
    ForceCommand /usr/local/bin/sandlock run --profile restricted -e "${SSH_ORIGINAL_COMMAND:-/bin/bash}"
```

## Cluster Scheduling

Group targets into clusters for multi-node operations.

```toml
[cluster.prod]
nodes = ["web-1", "web-2", "web-3"]

[target.web-1]
host = "deploy@web-1.example.com"
profile = "web"
workdir = "/opt/app"

[target.web-2]
host = "deploy@web-2.example.com"
profile = "web"
workdir = "/opt/app"

[target.web-3]
host = "deploy@web-3.example.com"
profile = "web"
workdir = "/opt/app"
```

### Status

Check all nodes in a cluster:

```bash
sandlock status prod
```

```
NODE            HOST                            CPU      MEM   LOAD STATUS
---------------------------------------------------------------------------
web-1           deploy@web-1.example.com          4    8192M   0.30 ok
web-2           deploy@web-2.example.com          4    8192M   2.10 busy
web-3           deploy@web-3.example.com          4    8192M   0.50 ok
```

### Schedule

Run a command on the best available node. The scheduler probes all nodes in
parallel via SSH, picks the one with the lowest load-per-CPU, and runs there:

```bash
sandlock schedule prod -e "pytest"
```

```
Selected: web-3 (deploy@web-3.example.com)
... test output ...
```

### Deploy to a cluster

Deploy to every node in a cluster:

```bash
for node in web-1 web-2 web-3; do
    sandlock deploy $node
done
```

## Python API

```python
from sandlock import Sandbox, Policy

policy = Policy(
    fs_readable=["/usr", "/lib", "/lib64", "/bin", "/etc", "/tmp"],
    fs_writable=["/tmp"],
    max_memory="512M",
    max_processes=50,
)

# Local
result = Sandbox(policy).run(["python3", "task.py"])

# Remote — same API
result = Sandbox(policy, host="user@server").run(["python3", "task.py"])

# Using a profile name (must exist on remote)
result = Sandbox("restricted", host="user@server").run(["python3", "task.py"])
```

For cluster scheduling:

```python
from sandlock.deploy import schedule, probe_cluster

# Probe and pick best node
target = schedule("prod")
print(f"Best node: {target.name} ({target.host})")

# Check cluster health
for status in probe_cluster("prod"):
    print(f"{status.name}: load={status.load_1m}, mem={status.mem_available_mb}M")
```

## Architecture

```
Your machine                         Remote hosts
+--------------+       SSH          +------------+
| sandlock     |--------------------| sandlock   |
| deploy/run/  |--------------------| (Landlock  |
| schedule     |--------------------| + seccomp) |
+--------------+                    +------------+

No daemon. No agent. No container runtime.
SSH is the transport. The kernel is the sandbox.
```

## How It Compares

| | Docker | Kubernetes | E2B/Daytona | sandlock |
|---|---|---|---|---|
| Needs root | Yes | Yes | N/A (their cloud) | No |
| Agent/daemon | dockerd | kubelet + etcd + ... | N/A | None |
| Setup | Install Docker | Install K8s cluster | API key | `pip install` |
| Deploy | Build image, push, pull | kubectl apply | API call | `sandlock deploy` |
| Isolation | Namespaces + cgroups | Same + pod security | VM | Landlock + seccomp |
| Data stays on your infra | Yes | Yes | No | Yes |
| Works air-gapped | Yes | Yes | No | Yes |
| Per-SSH-key policies | No | No | No | Yes |
