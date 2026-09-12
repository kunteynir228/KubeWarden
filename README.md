# KubeWarden

A container runtime security agent for Kubernetes, built with eBPF.
It detects container escape attempts, correlates individual syscalls
into a readable **Attack Story**, and kills the offending pod while
leaving a human-readable reason in a Kubernetes Event.

```
[CRITICAL] cgroup=108000 KILL — proc=chroot threat_score=90
           chain=[execve(/bin/cat) -> openat(/etc/shadow)
                  -> execve(/bin/chroot) -> chroot(/)]
[INFO]     cgroup.kill: all processes in cgroup=108000 killed
[CRITICAL] KILLED default/attacker [cgroup.kill (instant), API-delete queued]
```

---

## ⚠️ Read this first

**This is a learning project. Do not run it in production.**

I built it to understand how runtime security works at the kernel
level, and it does work — it is deployed on my homelab cluster and
has caught every attack vector I threw at it. But please understand
what you are looking at:

- **It kills pods.** A bug in a detection rule means a legitimate
  workload dies. This happened to me twice during development: once
  a path-matching bug killed Trivy on both nodes, and once an
  unconditional kernel-level kill took down `runc` and no new pod
  could be created on the node at all. Both are documented in
  [DEBUGGING-HISTORY.md](DEBUGGING-HISTORY.md).
- **It runs privileged with `hostPID`** and can load eBPF programs
  into your kernel. Compromising this agent means compromising the
  node.
- **I have never run it on control-plane nodes.** The manifest ships
  with control-plane tolerations commented out. Static pods
  (`etcd`, `kube-apiserver`) live in `kube-system`, which is
  `warn_only` by default, but I have not tested that path.
- **It is not a replacement for Falco or Tetragon.** Those are
  mature, audited, CNCF-backed projects with teams behind them.
  This is one person's homelab experiment.

If you want to learn how this class of tooling works, or you want a
starting point to build something of your own — you are in the right
place. If you want runtime security for a real cluster, use Falco
or Tetragon.

---

## What makes it different

Most tutorials stop at "print the syscall". The interesting parts
are what comes after:

**Attack Story instead of single events.** `openat(/etc/shadow)`
alone is suspicious but not conclusive — `passwd` and PAM modules
read that file too. The sequence `execve(/bin/cat) → openat(/etc/shadow)
→ execve(/bin/chroot) → chroot(/)` within one container over five
seconds shows intent. Weights accumulate in a sliding 30-second
window; two thresholds produce the decision.

**Three response tiers, by how certain the signal is.**
Escape syscalls with no legitimate use inside a container (`setns`,
`pivot_root`, `init_module`) are killed in the kernel unconditionally
— ~40 microseconds, before user space even sees the event. Weaker
signals require a chain. Slow cleanup (Event, API delete) happens
asynchronously so it never blocks event processing.

**Killing where the process actually lives.** `delete_namespaced_pod`
is asynchronous: the API server writes to etcd and returns, but the
actual SIGKILL arrives 5–30 seconds later when kubelet processes the
watch event. During development I could keep running commands inside
a pod that was already "deleted". The fix is cgroup v2's
`cgroup.kill` — one byte written to a file, all processes in the
cgroup die synchronously, microseconds.

**Filtering in the kernel.** Measured on a live node: 868 events/sec
reaching user space, of which only 11% passed the noise filters.
The other 89% were doing a full round trip through the perf buffer
and a ctypes callback just to be discarded — which also caused event
loss. Moving the filter into the eBPF program cut throughput to
68 events/sec with zero drops.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                     KERNEL (eBPF, C)                           │
│                                                                │
│  15 tracepoints on syscalls:sys_enter_*                        │
│  execve openat openat2 chroot mount move_mount open_tree       │
│  fsmount pivot_root setns ptrace connect init_module           │
│  finit_module delete_module                                    │
│                            │                                   │
│                            ▼                                   │
│            should_skip(cgroup_id)  ◄── BPF_HASH cgroup_class   │
│            HOST or EXCLUDED → drop (≈92% of events)            │
│                            │                                   │
│                            ▼                                   │
│            fill_common(): ktime, pid, ppid, comm, filename     │
│                            │                                   │
│         ┌──────────────────┴──────────────────┐                │
│         ▼                                     ▼                │
│  red_line_kill()                      maybe_kill()             │
│  setns, pivot_root, *_module          chroot, mount*, ptrace   │
│  unconditional                        only if armed            │
│                                       ◄── BPF_HASH armed_cgroups│
│         │                                     │                │
│         └──────────────┬──────────────────────┘                │
│                        ▼                                       │
│         both check is_container_runtime() first —              │
│         otherwise runc and kubelet get killed                  │
│                        │                                       │
│              bpf_send_signal(SIGKILL)  ← ~40 µs                │
│                        │                                       │
│                  perf_submit()                                 │
└────────────────────────┼───────────────────────────────────────┘
                         │  ~0.35 ms
┌────────────────────────┼───────────────────────────────────────┐
│                    USER SPACE (Python)                         │
│                        ▼                                       │
│  SyscallTracer      — latency measurement, comm denylist       │
│  PodResolver        — is this a pod or a host process?         │
│  AttackCorrelator   — group by cgroup, score, build the chain  │
│  PolicyEngine       — ALLOW / WARN / KILL                      │
│         │                              │                       │
│         ▼ WARN                         ▼ KILL                  │
│  tracer.arm()                   K8sKiller.handle_kill          │
│  (write to BPF map)              1. resolve cgroup → pod       │
│                                  2. namespace policy check     │
│                                  3. cgroup.kill    ← instant   │
│                                  4. queue Event + API delete   │
│                                                                │
│  CgroupSync    — background cgroupfs scan → BPF map            │
│  RepeatTracker — count repeated detections per pod owner       │
│  Metrics       — Prometheus endpoint on :9102                  │
└────────────────────────────────────────────────────────────────┘
```

The split is deliberate:

| Layer | Responsibility | Why there |
|---|---|---|
| Kernel | filtering, instant SIGKILL | speed (40 µs); 92% of events never leave the kernel |
| User space | correlation, scoring, rules | needs strings, data structures, flexible logic |
| Background threads | K8s API, cgroupfs scanning | slow (~70 ms); must never block event reading |

Full walkthrough of every component:
[ARCHITECTURE.md](ARCHITECTURE.md).

---

## How policies work

### Scoring

Each signal has a weight. Weights accumulate per container in a
sliding 30-second window. Two thresholds decide the outcome:

```yaml
thresholds:
  warn: 40   # log it; with --kernel-enforce, also arm the cgroup
  kill: 90   # kill the pod, create an Event
```

Signals fall into two categories:

**Suspicion** (below threshold — needs a chain):
`/etc/shadow` (60), another pod's SA token (50), `chroot` (50),
`ptrace` (40).

**Escape already happened** (100 — conclusive on its own):
`setns`, `pivot_root`, kernel module loading, container runtime
socket access, reads through `/proc/1/root` or `/host`, the cluster
CA key.

The score also **decreases** as events age out of the window.
Without that, any pod that periodically reads something on the list
would eventually cross the kill threshold with no actual violation.

### Path matching

Three separate mechanisms, and the distinction matters more than it
looks:

```python
SUSPICIOUS_PATH_PREFIXES   # directory and everything under it
SUSPICIOUS_PATH_SUFFIXES   # sensitive file, wherever it lives
SUSPICIOUS_FILENAMES       # basename (runtime sockets move around)
```

Prefix matching respects path component boundaries:

```python
def _path_matches(filename, prefix):
    return filename == prefix or filename.startswith(prefix + "/")
```

The naive `if prefix in filename` version caused the worst bug in
this project. The rule `/host` matched `/etc/hosts` — a file that
**every networked application reads**. Two such reads scored 120 and
killed the pod. It was a landmine under every workload in the
cluster; Trivy just happened to trip it first.

Suffix matching exists because an attacker reads sensitive files
through a host mount, not by their canonical path:
`/host/etc/shadow` scores 30 (prefix) + 60 (suffix) = 90 → kill,
while `/host/usr/src/` — which Falco reads for kernel headers —
scores 30 and stays silent.

### Namespace tiers

```yaml
# Events dropped in the kernel. Deliberate blind spot.
exclude_namespaces:
  - kubewarden-system      # the agent itself

# Detection and Events, but no automatic kill.
warn_only_namespaces:
  - kube-system            # killing coredns/cilium takes down the cluster
  - trivy-system           # scanners look exactly like attackers
  - falco
  - monitoring
```

`kube-system` is `warn_only` by default on purpose: a false positive
on `coredns` or `cilium` is worse than a delayed response. Verified
in practice — `calico-node` scored 160 reading
`/proc/1/root/etc/shadow` and survived, with the Event tagged
`[WARN-ONLY, pod not killed]`.

Worth noting: `calico-node` is *legitimately* privileged with
`hostPID`, so `/proc/1/root` inside it really does lead to the host
root. The most dangerous pod in a cluster is often not a
misconfigured one — it is the CNI installed per the docs.

### Repeat escalation

Production namespaces end up in `warn_only` because nobody wants a
revenue-generating service killed on a single detection. But then a
signal is lost: one alert is probably noise, three in ten minutes is
not. Legitimate applications either do something always or never.

```yaml
repeat_escalation:
  enabled: true
  window_minutes: 10
  threshold: 3
  action: alert        # alert | kill
```

Counting is per **pod owner** (Deployment/DaemonSet/StatefulSet),
not per pod — after a kill the controller creates a new pod with a
new cgroup id, so a per-cgroup counter would always read 1 and
repeated attacks from a compromised image would be invisible.

Result:

```
10:44:14  WARNING   (first)
10:45:01  WARNING   [REPEAT: 2nd detection ... within 1 min]
10:48:00  CRITICAL  [REPEAT: 3rd detection ... within 4 min]
```

---

## Verified attack vectors

All tested on a live cluster, not in unit tests.

| Vector | Command | Result | Latency |
|---|---|---|---|
| Password read + root change | `cat /etc/shadow; chroot /` | KILL (90) | ~1 ms |
| Host root via PID 1 | `cat /proc/1/root/etc/shadow` | KILL (140) | ~1 ms |
| Bind mount (new mount API) | `mount --bind /proc/1/root /tmp/h` | KILL (90) | ~1 ms |
| Entering host namespace | `nsenter --target 1 --mount bash` | killed in kernel | 1.9 ms |
| **Runtime socket** | `nc -U /run/containerd/containerd.sock` | KILL (100) | ~1 ms |
| **Kernel module** | `touch /tmp/e.ko; insmod /tmp/e.ko` | killed in kernel | **0.04 ms** |

Two of these are worth a closer look.

**The runtime socket** is the most dangerous and least obvious. The
test pod had **no** `privileged` and **no** `hostPID` — the escape
required no suspicious syscall at all. A mounted socket is enough to
ask the runtime to start a privileged container with `hostPath: /`,
and in a manifest that single `hostPath` line looks harmless.

**The kernel module** test pod had no `privileged` either, just one
added capability: `SYS_MODULE`. It would pass Pod Security Standard
`baseline` while being able to take over the kernel and unload
KubeWarden itself. (Common misconception: `CAP_SYS_ADMIN` does *not*
grant module loading — you need `CAP_SYS_MODULE` specifically.)

Also worth documenting: before `move_mount` was added as a sensor,
`mount --bind` escaped **while the agent was running**. Modern
`util-linux` barely uses `mount(2)` — `strace` showed
`open_tree()` + `move_mount()` instead, both kernel 5.2+ syscalls
the agent was not watching.

### Not covered, by design

**RBAC escalation and token theft.** Reading your own SA token is
not an anomaly — every application does it. The anomaly happens
afterwards, as network requests to the API server. At the kernel
level you only see `connect()` to a cluster IP, which cannot
distinguish a legitimate request from privilege enumeration. That
detection belongs in the API server audit log.

**How the attacker got into the pod.** `kubectl exec` is how you
*test* this, not how anyone attacks: if you have exec rights you are
already a legitimate user. Real entry points are application RCE, a
compromised image or dependency, or CI/CD access. That is the domain
of WAF, SAST and image scanning.

---

## Requirements

- Kernel 5.3+ for `bpf_send_signal`, 5.14+ for `cgroup.kill`,
  5.2+ to see `move_mount`
- cgroup v2
- BTF helps but is not used — bcc compiles against kernel headers,
  so `linux-headers-$(uname -r)` must be installed **on every node**
  and match the running kernel

That last point bites after a kernel upgrade: the agent will
`CrashLoopBackOff` until the matching headers are installed. Moving
to libbpf CO-RE would remove the dependency entirely (and shrink the
image from 444 MB to tens of MB) — see
[Known limitations](#known-limitations).

## Quick start

```bash
# Build and distribute (no registry needed)
sudo buildah bud -t kubewarden:0.9 .
sudo buildah push kubewarden:0.9 docker-archive:/tmp/kw.tar:kubewarden:0.9
sudo ctr --namespace k8s.io images import /tmp/kw.tar   # k8s.io namespace matters

kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/daemonset.yaml
```

Start in the safest mode and work up:

```bash
--no-k8s                       # detection only, no API calls
(default)                      # dry-run: resolves pods, logs "would kill"
--enforce                      # actually kill pods
--enforce --kernel-enforce     # also kill in-kernel on red lines
```

Full deployment guide, including the control-plane discussion:
[deploy/DEPLOY.md](deploy/DEPLOY.md).

**Test it:**

```bash
kubectl apply -f deploy/attacker-pod.yaml
kubectl exec -it attacker -- bash
cat /etc/shadow && chroot /

kubectl get events -A --field-selector reason=KubeWardenThreatDetected
```

Three test manifests are included — `attacker-pod.yaml` (privileged),
`attacker-socket.yaml` (runtime socket only, no privileges) and
`attacker-module.yaml` (one capability, no privileges).

## Metrics

Prometheus endpoint on `:9102/metrics`, plus `/healthz` for the
liveness probe. Queries, alert rules and what to put on a dashboard:
[deploy/METRICS.md](deploy/METRICS.md).

The metrics earned their place immediately — they revealed ~270
events lost on every startup, invisible in the logs because bcc
printed the warning straight to stderr from C. Root cause: the first
`CgroupSync` scan was synchronous and hit the API server, so the
perf buffer filled up before `poll_loop()` started reading. Now
zero drops.

## Known limitations

Honest list, in rough order of how much they would bother a real user:

- **Kernel header dependency** — bcc compiles at startup, so headers
  must match the running kernel on every node. libbpf CO-RE would
  fix this properly.
- **`privileged: true`** rather than targeted capabilities.
  `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_RESOURCE` should be enough on
  5.8+, but `cgroup.kill` needs write access to `/sys/fs/cgroup`,
  which wants host user namespace privileges.
- **Rules are hardcoded** in `core/correlator.py` even though
  `PolicyEngine` already reads YAML. Moving them would allow changes
  without rebuilding the image.
- **`PodResolver` caches never invalidate.** On a busy node this
  leaks slowly. `kubewarden_cache_entries` exists to watch for it.
- **`CgroupSync` calls `list_pod_for_all_namespaces` every 5s.** On
  a large node this should be a watch instead.
- **`bpf_send_signal` does not block the syscall** — it kills the
  process immediately after. Real blocking (`-EPERM`) needs
  `bpf_lsm`, which means `CONFIG_BPF_LSM=y` and `lsm=bpf` at boot.
  The honest description is sub-millisecond *response*, not
  prevention.
- **`comm` is 16 bytes** (`TASK_COMM_LEN`), so longer process names
  get truncated and can slip past the denylist.
- **Untested:** `pivot_root`, `ptrace`, `fsmount` via
  `fsopen`/`fsconfig`, and anything on control-plane nodes.

## Contributing

Genuinely welcome. Fork it, change it, take it in whatever direction
makes sense to you — that is more interesting to me than PRs back
here.

If you do want to contribute directly, the things I would find most
useful:

- **libbpf CO-RE port.** Biggest single improvement available.
- **Rules in YAML** instead of Python constants.
- **More detection rules** — but please read the note below first.
- **Anything you find that produces false positives.** Every one of
  those I found came from running it on a real cluster, never from
  reasoning about the code.

A word on new rules: the useful criterion is *has this appeared in
real incidents*. If not, it adds complexity and false-positive risk
for no benefit. By that measure `release_agent` (cgroup v1) is not
worth adding, while `connect` to the cloud metadata endpoint
`169.254.169.254` clearly is.

Also worth internalising if you touch the kernel-side code: any
unconditional kill needs an allowlist of infrastructure processes,
and you must test it against **normal cluster operation**, not just
against your attack. The correct order is enable enforcement →
immediately create an ordinary pod → confirm it starts → *then* test
detection. I learned that by making every new pod on the node fail
to start.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — every component explained,
  with the reasoning behind each decision
- [DEBUGGING-HISTORY.md](DEBUGGING-HISTORY.md) — 18 problems hit
  during development, each with symptom, root cause and fix.
  Probably the most useful file in the repository: the code can be
  rewritten, but understanding *where* eBPF and Kubernetes break is
  harder to come by.
- [deploy/DEPLOY.md](deploy/DEPLOY.md) — deployment
- [deploy/METRICS.md](deploy/METRICS.md) — metrics and alerting

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Acknowledgements

[Falco](https://falco.org/) and
[Tetragon](https://tetragon.io/) are the projects this one learns
from. Reading how they solve these problems taught me more than any
tutorial. If you need runtime security rather than an education,
use one of those.
