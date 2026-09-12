# KubeWarden — debugging history

Every problem hit during development, with an explanation of **why** it
happened. This is the most valuable part of the project: code can be
rewritten, but understanding *where* eBPF and Kubernetes break only
comes from cases like these.

Chronological order. Three **outages** — cases where the agent broke a
working cluster — are marked separately.

**Index by type:**

- eBPF and the kernel: #1, #7, #13, #14
- False positives: #5, #6, #15 (outage), #17
- Cluster outages: #15 (Trivy), #16 (runc)
- Kubernetes asynchrony: #8, #9
- Missed detections: #13, #14
- Small but instructive: #12, #18

---

## 1. Empty `filename` in events

### Symptom

The tracer worked, events arrived, but the path was always empty:

```
[openat ] pid=563 ppid=1 comm=containerd-shim file= cgroup=2923
```

### First version of the code

```c
int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename) {
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), filename);
}
```

Looks reasonable: the syscall signature is
`openat(int dfd, const char *filename, ...)`, so we declare the function
parameters the same way and bcc should supply them from the registers.

### Why it did not work

Modern x86_64 kernels build with `CONFIG_ARCH_HAS_SYSCALL_WRAPPER`. That
means the real syscall handler is called `__x64_sys_openat` and takes
**one** argument — a pointer to `struct pt_regs`, inside which all the
actual arguments live.

So the kprobe receives not `(dfd, filename, ...)` but `(pt_regs*)`,
where `pt_regs->di` is the syscall's first argument, `pt_regs->si` the
second. bcc was trying to read `filename` out of a register that
actually held a pointer to a struct.

### Second attempt — and a verifier rejection

```c
struct pt_regs *real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
const char __user *filename = (const char __user *)PT_REGS_PARM2(real_regs);
```

The kernel rejected the program:

```
63: (79) r3 = *(u64 *)(r1 +112)
R1 invalid mem access 'scalar'
Failed to load BPF program 'trace_execve': Permission denied
```

### Why the verifier objects

`real_regs` was obtained by reading memory (`r1 = *(u64*)(r6+112)`), so
to the verifier it is an ordinary number (`scalar`), not a validated
pointer. In eBPF you may only dereference `PTR_TO_CTX` or
`PTR_TO_BTF_ID` — pointers whose provenance the verifier has traced and
accepted.

An arbitrary number cannot be dereferenced: otherwise an eBPF program
could read any kernel memory, which is precisely the hole the verifier
exists to close.

### The fix, via bpf_probe_read_kernel

```c
bpf_probe_read_kernel(&val, sizeof(val), &real_regs->di);
```

`bpf_probe_read_kernel()` makes a safe copy with a runtime check: if the
address is invalid the helper returns an error rather than crashing the
kernel. That is exactly why the verifier permits it.

### The real fix — moving to tracepoints

None of the above is necessary if you use a **tracepoint** instead of a
kprobe:

```c
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), args->filename);
}
```

bcc generates the `args` struct from the tracepoint format (see
`/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format`),
and `args->filename` is already a usable pointer to the right argument.

Bonus: bcc attaches such probes automatically when the BPF object is
created, so `attach_kprobe()` never has to be called.

### Takeaway

**kprobe** gives access to any kernel function but requires ABI
knowledge and is version-dependent. **Tracepoint** is a stable contract
with annotated arguments, but only exists where kernel developers placed
one. For syscalls a tracepoint always exists, so for this task the
choice is obvious.

---

## 2. An Attack Story drowning in noise

### Symptom

The chain was technically correct but unreadable — 50 steps, 45 of them
about the dynamic linker:

```
chain=[execve(/bin/ls) -> openat(/etc/ld.so.cache)
-> openat(/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v4/libm.so.6)
-> openat(/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libm.so.6)
... (40 more like these) ...
-> openat(/etc/shadow)]
```

### Why

When any program starts, `ld.so` searches for libraries by walking the
`glibc-hwcaps` list (optimisations for different instruction sets:
`x86-64-v2`, `v3`, `v4`), then `tls/`, `haswell/` and so on. Each probe
is a separate `openat`, which may return `ENOENT` — but the syscall
still happened and the tracepoint still fired.

### The fix

Only significant steps make it into the chain: events that scored, plus
`execve` of non-libraries. Result:

```
chain=[execve(/bin/cat) -> openat(/etc/shadow) -> execve(/bin/chroot) -> chroot(/)]
```

Why the harmless `execve(/bin/ls)` stays: it shows a human's behaviour
(they were looking around), whereas `openat(libc.so)` is linker work
nobody chose.

---

## 3. An endless list of noisy processes

### Symptom

First `containerd-shim` was noisy (it reads its cgroup metrics). Added
to the denylist. Then `calico-node` with `ip` and `sv`. Added. Then
`runc:[1:CHILD]`, `runc:[2:INIT]`, `check-status`. Then a mysterious
`comm=6`.

### Why `comm=6`

During `execve` the process name has not yet been updated to the new
binary, so `bpf_get_current_comm()` returns the old one — and runc
launches processes through `/proc/self/fd/6`, hence the name `6`.

### Why this approach is a dead end

Control-plane health probes run `runc exec` every few seconds, spawning
a cascade of short-lived processes with different names. Enumerating
them all is pointless — the list would grow forever.

### The fix — filter by the nature of the process, not its name

The right property: is the process **in a pod** or **on the host**? A
host process has nowhere to escape to; it is already on the host.

```python
if not resolver.is_pod_cgroup(event["cgroup_id"]):
    return
```

This later moved into the kernel via the `cgroup_class` map — see #10.

---

## 4. A monotonically growing threat_score

### Symptom

Never manifested directly — this was a time bomb. Found by reading the
code, before it fired on a live cluster.

### The buggy code

```python
def _evict_old(self):
    cutoff = time.time() - CORRELATION_WINDOW_SEC
    while self.events and self.events[0]["ts"] < cutoff:
        self.events.popleft()      # event removed, score not returned
```

### What would have happened

`metrics-server`, `kube-controller-manager` and any other pod that
periodically reads something in `SUSPICIOUS_PATHS` would accumulate
score without bound. Within minutes or hours — depending on frequency —
it would cross `kill_threshold` and be killed. Without a single real
violation.

The worst part: it would look like pods dying at random for no visible
reason.

### The fix

Store the score alongside the event and subtract it on eviction:

```python
self.events.append((event, score_delta))
...
while self.events and self.events[0][0]["ts"] < cutoff:
    _, old_score = self.events.popleft()
    self.threat_score -= old_score
```

---

## 5. False positive on ServiceAccount tokens

### Symptom

```
[CRITICAL] cgroup=60974 KILL — threat_score=100
          chain=[openat(...serviceaccount/token) -> openat(...serviceaccount/token)]
```

`cgroup=60974` was `metrics-server`. It read **its own** token twice and
got a death sentence.

### Why the rule was wrong

`/var/run/secrets/kubernetes.io/serviceaccount/token` is the standard
location where kubelet mounts the projected token volume. **Every** pod
in the cluster reads that file to authenticate to the API server.

### What is actually suspicious

Reading **another** pod's token. On the node, every pod's token lives in
`/var/lib/kubelet/pods/<UID>/volumes/kubernetes.io~projected/`. Reaching
there from inside a container means either an escape or an
over-permissive hostPath.

### Takeaway

The difference between "reads a secret" and "reads **someone else's**
secret" is the difference between a false positive and a real detection.

---

## 6. Kubernetes reacting to the agent's own actions

### Symptom

```
19:08:07,702 [CRITICAL] KILLED default/attacker
19:08:08,136 [CRITICAL] cgroup=29610 KILL — proc=umount threat_score=100
             chain=[mount(tmpfs) -> openat(/var/lib/kubelet/pods/.../token)]
```

400 ms after our kill, the agent decided to kill something else.

### What was happening

Our kill removed the pod -> kubelet started cleaning up its volumes ->
`umount` plus reads of `/var/lib/kubelet/pods/...` -> exactly the
pattern we had just flagged as suspicious (#5) -> `threat_score=100` ->
KILL.

The agent reacted to **the consequences of its own actions**.

The only thing that saved us was that `kubelet` lives in `system.slice`,
so the resolver found no pod. Had that cgroup resolved, there would have
been a cascade.

### Takeaway

Automated response creates a feedback loop. A tool that changes the
state of a system will inevitably observe its own changes through its
own sensors.

---

## 7. Event loss and "Python is slow"

### The hypothesis that turned out to be wrong

"Python is slow, we should rewrite this in Go."

### What the measurement showed

We added `bpf_ktime_get_ns()` in the kernel and compared against
`CLOCK_MONOTONIC`:

```
[stats] events=142134 (708/s), passed filter=2769 (1.9%),
        latency avg=0.32ms max=85.70ms
```

**Latency of 0.32 ms** — Python was not the bottleneck. Rewriting in Go
would have saved ~0.1 ms.

The **1.9% passing the filter**, on the other hand, was the real
problem: 98% of events travelled through the perf buffer and a ctypes
callback only to be discarded.

### Where the "feeling of lag" came from

```
18:52:49  WARN  (cat /etc/shadow)
18:52:55  KILL  (chroot /)         <- 6 seconds
```

Those 6 seconds were a human typing the second command. The agent's
reaction to the `chroot` itself took 71 ms.

### The fix

In-kernel filtering: 868 events/s -> 68, losses gone.

### Takeaway

Profile before optimising. The intuition pointed at the right problem
(performance) but the wrong cause (language rather than volume of work).

---

## 8. The pod died 5–30 seconds after the decision

The single most important observation of the project.

### Symptom

The log showed an instant response (71 ms), yet in practice you could
keep running commands inside the pod for several more seconds.

### Why

`delete_namespaced_pod()` is an **asynchronous** operation:

```
agent -> API server:  "delete the pod"      (71 ms, the log ends here)
API server -> etcd:   record removed
   ... watch event travels to kubelet ...
kubelet -> containerd: StopContainer
containerd -> processes: SIGKILL            <- actual death happens here
```

Worse: with `grace_period=0` the API server removes the object from etcd
**without waiting** for kubelet. The pod disappears from
`kubectl get pods` while the container keeps running. The attacker
operates inside a pod that formally no longer exists.

The key point: **this is not a Kubernetes problem and not a Python
problem.** It follows from asking Kubernetes to kill a process instead
of killing it ourselves.

### The fix — cgroup.kill

```python
with open(f"{cgroup_path}/cgroup.kill", "w") as f:
    f.write("1")
```

The kernel synchronously sends SIGKILL to every process in the cgroup.
Microseconds.

Result — three lines within the same millisecond:
```
19:35:54,511 [CRITICAL] KILL — proc=chroot threat_score=90
19:35:54,511 [INFO] cgroup.kill: all processes killed
19:35:54,511 [CRITICAL] KILLED default/attacker [cgroup.kill (instant), ...]
19:35:54,538 [INFO] API-delete done                <- in the background
```

### From the attacker's side

```
/ # command terminated with exit code 137
```

`137 = 128 + 9` -> SIGKILL. (Worth remembering: `137` = SIGKILL,
`143 = 128 + 15` = SIGTERM.)

---

## 9. Slow calls blocking the hot path

### The problem (found by reasoning, not in practice)

A single `handle_kill` performed the Event creation and API delete
synchronously — about 140 ms during which `perf_buffer_poll()` is never
called.

With ten simultaneous detections that is over a second of blindness. At
800 events/s, hundreds of events from other pods are lost — and an
attack on the eleventh pod goes unnoticed precisely because the agent is
busy killing the first ten.

### The fix

Split by time criticality: `cgroup.kill` synchronously (microseconds),
Event and API delete into a queue with two worker threads.

---

## 10. Kubernetes Event: error 422

### Symptom

A self-inflicted regression. An attempt to fix `<unknown>` in the
`LAST SEEN` column produced:

```
{"message":"Event ... is invalid: action: Required value","code":422}
```

### Why

Kubernetes has two Event formats: legacy (`core/v1`) and the newer
`events.k8s.io/v1`. Filling in `event_time` switches validation to the
new format, where `action` and `reportingController` are mandatory.

### The fix

Drop `event_time`, keep only `first_timestamp`, `last_timestamp` and
`count`.

### What saved us

`_emit_event` was wrapped in `try/except`, so failing to create the
Event did not prevent killing the pod. The response happened; only the
alert was lost — the right priority.

---

## 11. The agent reacting to an already dead pod

27 seconds after a kill — a WARN about the same cgroup. The
`AttackStory` was still in `correlator.stories`, and residual events
kept landing in its window.

Fixed with `correlator.forget(cgroup_id)` after a successful kill.

---

## 12. Small but instructive (first batch)

### The pod was on the wrong node

The tracer ran on the control plane while `attacker` was scheduled onto
a worker. eBPF only sees **its own** node — each node has its own
kernel.

Fix for testing: `nodeName: worker1`. Fix for production: a DaemonSet.

### Pods are immutable

```
The Pod "attacker" is invalid: spec: Forbidden: pod updates may not
change fields other than spec.containers[*].image, ...
```

`nodeName` and `command` cannot be changed — only recreated.

### sudo and venv

`sudo python3` uses the **system** interpreter, ignoring an active venv.
`bcc` is installed as a system package and is invisible inside a venv
without `--system-site-packages`.

### kubeconfig under sudo

`sudo` looks for the config in `/root/.kube/config`. Fix:
`sudo KUBECONFIG=/home/admin/.kube/config python3 main.py`.

On worker nodes kubeadm does not create a kubeconfig at all — it has to
be copied from the control plane, and `/etc/kubernetes/admin.conf` is
readable only by root.

### An Event lives in its object's namespace

`kubectl get events` without `-A` only shows the current namespace. An
Event about a pod in `kube-system` lives in `kube-system`.

### Circular dependency in main.py

`on_event` needs to call `tracer.arm()`, but the tracer is constructed
with `on_event`. Broken with a container:

```python
tracer_ref = {"t": None}
tracer = SyscallTracer(on_event=on_event, ...)
tracer_ref["t"] = tracer
```

### Importing from the wrong module

```
ImportError: cannot import name 'Decision' from 'core.correlator'
```

`Decision` was declared in `policy_engine.py`. The bug had been in the
code since the first version and only surfaced on the first real run.

---

## 13. An escape succeeded while the agent was running: the new mount API

### Symptom

Agent running, `--enforce` enabled. Inside the pod:

```
attacker:~# mkdir -p /tmp/h
attacker:~# mount --bind /proc/1/root /tmp/h
attacker:~# lsblk
attacker:~# mount /dev/vda1 /tmp/h
attacker:~# nsenter --target 1 --mount --pid bash
root@attacker:/#          <- HOST ROOT
```

A full escape. **Not a single line** in the agent's log.

### Diagnosis

First we checked whether events were arriving at all:

```bash
sudo python3 bpf/syscall_tracer.py | grep -E "mount|setns"
```

The output contained only `execve(/bin/mount)` — the utility starting,
but not its action. So the `mount` tracepoint was never firing.

`strace` gave the precise answer:

```
$ strace -e trace=mount,move_mount,fsopen,open_tree mount --bind /proc/1/root /tmp/h2
open_tree(AT_FDCWD, "/", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC) = 3
move_mount(3, "", AT_FDCWD, "/tmp/h2", MOVE_MOUNT_F_EMPTY_PATH)
```

No classic `mount(2)` **at all**.

### Why

Since kernel 5.2 there is a new mount API: `fsopen()`, `fsconfig()`,
`fsmount()`, `open_tree()`, `move_mount()`. Modern `util-linux` uses
exactly that. Our `sys_enter_mount` tracepoint does not see those calls
— they are different syscalls with different numbers.

### The fix

Probes added for `move_mount`, `open_tree`, `fsmount`, with weights.

### Takeaway

Knowing a syscall from a textbook does not guarantee it is used in
practice. Before considering a vector covered, check with `strace` what
the target utility actually calls.

---

## 14. setns was detected but not scored

### Symptom

In the same run as #13:

```
[WARNING] cgroup=110390 proc=nsenter threat_score=70
          chain=[execve(/usr/bin/nsenter) -> setns()]
```

The event arrived and the chain was built — but `threat_score=70`
against a threshold of 90 produced only a WARN. The operator got root on
the node.

### Two separate causes

**First — a forgotten weight.** The `setns` tracepoint had been added,
but the syscall itself was never entered into `SUSPICIOUS_SYSCALLS`.
Events arrived with score 0 and were not even logged. Then we added a
weight of 70, which turned out to be too low.

**Second — structural.** Even with a weight of 100 user space is too
late: by the time the event reaches Python (0.3 ms), `setns` has already
executed. And `--kernel-enforce` did not help either — it arms a cgroup
**after** a WARN, and the WARN comes after `setns`.

### The fix — unconditional red lines

A separate mechanism, `red_line_kill()`, for syscalls that are
themselves a completed escape:

```c
static __always_inline int red_line_kill(u64 cgroup_id, struct event_t *e) {
    if (is_container_runtime())  return 0;
    if (!kill_allowed(cgroup_id)) return 0;
#ifdef KERNEL_ENFORCE
    bpf_send_signal(9);
    e->killed_in_kernel = 1;
#endif
}
```

No arming, no score accumulation — SIGKILL straight from the probe.
Applied to `setns`, `pivot_root`, `init_module`, `finit_module`,
`delete_module`.

### Result

```
attacker:~# nsenter --target 1 --mount --pid bash
Killed                     nsenter --target 1 --mount --pid bash
attacker:~# command terminated with exit code 137
```

Response latency 1.9 ms; for `finit_module`, 0.04 ms.

### A separate observation

The chain was missing `openat(/proc/1/ns/mnt)`, even though `nsenter`
must open that file. The likely cause is `openat2()`, the newer
file-opening variant (kernel 5.6+), for which a probe was also added.
The same story as `mount` -> `move_mount`.

---

## 15. OUTAGE: the "/host" rule killed Trivy

**The worst bug in the project.** A landmine under every workload in the
cluster, not a rare edge case.

### Symptom

Seconds after deploying the DaemonSet to two nodes:

```
[CRITICAL] cgroup=157497 KILL — proc=trivy threat_score=120
  chain=[openat(/opt/hostedtoolcache/go/1.26.6/x64/lib/time/zoneinfo.zip)
         -> openat(/etc/hosts)]
[CRITICAL] KILLED trivy-system/scan-vulnerabilityreport-86f7cdc77-lxzq4
```

Trivy killed on **both** nodes, independently.

### Cause

Path matching was naive:

```python
for path, weight in SUSPICIOUS_PATHS.items():
    if path in event["filename"]:      # <- substring!
        score += weight
```

The rule `"/host": 60` matched:

| Actual path | Why it matched |
|---|---|
| `/etc/hosts` | contains `/host` |
| `/etc/hostname` | contains `/host` |
| `/opt/hostedtoolcache/...` | contains `/host` |

Two such reads = 120 points = KILL.

### Why this was a catastrophe rather than a bug

**`/etc/hosts` is read by every networked application.** Practically
every pod in the cluster eventually reads it twice within 30 seconds.
The rule would have wiped out the cluster — Trivy just happened to be
first, because it was not in `NOISE_COMMS`.

### The fix

Matching on a path component boundary:

```python
def _path_matches(filename: str, prefix: str) -> bool:
    return filename == prefix or filename.startswith(prefix + "/")
```

`/host` now matches `/host` and `/host/etc/shadow`, but not
`/etc/hosts`.

### Side effect of the fix

Previously `/host/etc/shadow` scored 100 because the substring match
**accidentally** counted both `/host` (60) and `/etc/shadow` (40). After
correct matching that bonus disappeared — the path does not start with
`/etc/shadow`.

A separate suffix dictionary (`SUSPICIOUS_PATH_SUFFIXES`) and a review
of the host path weights were needed.

### A related bug found at the same time

Nested keys stacked their weights:

```
"/run/docker.sock": 100
"/var/run/docker.sock": 100
-> the path /var/run/docker.sock matched BOTH -> 200
```

Fixed by matching the basename (`docker.sock`) rather than the full
path. Plus a nesting check when adding new rules:

```python
for a in keys:
    for b in keys:
        if a != b and a in b:
            print(f'NESTED: "{a}" inside "{b}"')
```

### Takeaway

Substring matching in security rules is a source of quiet catastrophes.
A rule looks sensible, gets tested against the target scenario, works —
and simultaneously matches a dozen harmless paths nobody thought about.

---

## 16. OUTAGE: the agent broke pod creation

### Symptom

After enabling the unconditional red lines (#14), no new pods could be
created on the node:

```
Warning  FailedCreatePodSandBox  kubelet
  Failed to create pod sandbox: rpc error: ... OCI runtime create failed:
  runc create failed: unable to start container process:
  can't get final child's PID from pipe: EOF;
  runc init error(s): nsexec-0[2810545]: failed to sync with stage-1:
  next state (got 0 of 4 bytes)
```

An endless retry loop; nothing came up.

### Cause

`runc` uses **`setns`** when creating every container — its `nsexec`
enters the namespaces. The unconditional `red_line_kill` was killing
`runc init` in the kernel.

`nsexec-0` in the error message is precisely the part of runc receiving
our SIGKILL.

### Why the protections did not work

Two lines of defence existed, and both were in the wrong place:

**`NOISE_COMM_PREFIXES = ("runc",)`** works in Python, while
`red_line_kill` fires **in the kernel**, before the event leaves for
user space. The filter physically could not reach it.

**`should_skip()`** checks the cgroup class, but `runc init` already
executes inside the cgroup of the pod being created, so its class is
`CLASS_POD`. It passed through as an ordinary pod.

### The fix — an allowlist in the kernel

```c
static __always_inline int is_container_runtime(void) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0]=='r' && comm[1]=='u' && comm[2]=='n' && comm[3]=='c') return 1;
    // + containerd, crun, kubelet
    return 0;
}
```

The check was added **both** to `red_line_kill` **and** to `maybe_kill`
— `runc` also performs `mount` and `pivot_root` while creating a
container.

### Takeaway

Any unconditional kill in the kernel needs an allowlist of
infrastructure processes, and it must be tested against **normal cluster
operation**, not just against your attack. The correct order is: enable
enforcement -> immediately create an ordinary pod -> confirm it starts
-> *then* test detection.

---

## 17. Trivy: detection stayed, the response changed

### What happened after fixing #15

We rebuilt the image, redeployed — and Trivy appeared again, but
differently:

```
[CRITICAL] cgroup=141125 KILL — proc=trivy threat_score=120
[WARNING] trivy-system/scan-vulnerabilityreport-...: WARN-ONLY namespace —
          pod NOT killed, creating an Event for human triage
```

The pod survived.

### Why the score was still 120

Because the pods were running the **old image**. With
`imagePullPolicy: IfNotPresent` kubelet uses the cached image even if
you rebuild under the same tag. A new tag is required.

### What did work

`trivy-system` had been added to `warn_only_namespaces`, and the
protection behaved exactly as designed — detection happened, an Event
was created, the workload survived. Even with a live bug in the rules,
the second layer of defence prevented the workload from being taken
down.

### After updating the image

Silence: with correct matching Trivy scores 0.

### Takeaway

Layered protection pays off. The rule bug was real and dangerous, but
`warn_only` turned an outage into an informational message.

---

## 18. Small but instructive (second batch)

### Kernel headers are needed on every node

The DaemonSet came up on `worker1` and crashed on `worker2`:

```
chdir(/lib/modules/6.1.0-52-cloud-amd64/build): No such file or directory
Unable to find kernel headers.
Exception: Failed to compile BPF module <text>
```

bcc compiles eBPF **against the host kernel**, at every startup. On
`worker1` the headers were installed during manual debugging; on
`worker2` they were not.

Separately: BTF (`/sys/kernel/btf/vmlinux`) exists on the node, but bcc
does not use it — that is the path for libbpf CO-RE, a different
approach.

### insmod fails before the syscall

```
attacker:~# insmod /tmp/nonexistent.ko
insmod: can't insert '/tmp/nonexistent.ko': No such file or directory
```

No detection, because `insmod` failed opening the file, before
`finit_module()`. The test needs an existing file — an empty one is
enough, `finit_module` will return `ENOEXEC` but the call itself
happens.

### CAP_SYS_ADMIN does not grant module loading

A common misconception. `init_module` specifically requires
`CAP_SYS_MODULE`. `privileged: true`, however, grants every capability
at once.

A test pod with a single `SYS_MODULE` capability and no `privileged`
would pass Pod Security Standard `baseline` — while being able to take
over the kernel.

### nerdctl cannot build without buildkit

```
ERRO `buildctl` needs to be installed and `buildkitd` needs to be running
```

The answer is `buildah`, which is self-contained:

```bash
sudo buildah bud -t kubewarden:0.1 .
sudo buildah push kubewarden:0.1 docker-archive:/tmp/kw.tar:kubewarden:0.1
sudo ctr --namespace k8s.io images import /tmp/kw.tar
```

`--namespace k8s.io` is mandatory: without it kubelet will not see the
image.

### print() is invisible inside a container

Cost about an hour of debugging. The `[prefill] ...` line never appeared
in the logs even though the code ran.

Cause: `print` writes to stdout, which inside a container is a pipe
rather than a TTY. Python buffers output in 8 KB blocks and the messages
get stuck. `logging` writes to stderr, which is not buffered.

Fixed by switching to `logging` plus `PYTHONUNBUFFERED=1` in the image.

**Takeaway:** do not use `print` for diagnostics in containers. It
silently swallows messages and turns debugging into guesswork.

### ConfigMap is not re-read at runtime

`PolicyEngine` reads the YAML once at startup. After changing the
ConfigMap a `rollout restart` is required.

Note also that the ConfigMap is mounted **over**
`/opt/kubewarden/policies`, so the version of the file baked into the
image is irrelevant.

### /tmp is wiped on reboot

An image tarball left in `/tmp` disappeared after a node reboot.
systemd clears `/tmp` on boot (see `/usr/lib/tmpfiles.d/tmp.conf`), and
if `/tmp` is a tmpfs it lives in RAM anyway. Build artefacts belong in a
home directory.

---

## General conclusions

**1. The verifier is a specification, not an obstacle.** Every rejection
explains which assumption is wrong. `invalid mem access 'scalar'`
literally means "you are dereferencing an unvalidated pointer".

**2. False positives are more dangerous than misses.** More than half
the work went not into detection but into stopping the agent from
killing legitimate pods. A tool that occasionally takes down `coredns`
or Trivy will be switched off — and then it catches nothing at all.

**3. Automation creates feedback loops.** An agent that changes system
state will observe its own changes through its own sensors (#6), and can
kill the infrastructure it runs on (#16).

**4. Profile before optimising.** "Python is slow" sounded convincing;
measurement showed 0.35 ms of latency and 98% wasted work. The problem
was elsewhere.

**5. API asynchrony is not an implementation detail.**
`delete_namespaced_pod` returns in 71 ms while the process dies 5–30
seconds later. For a security tool that is the difference between
working and not working.

**6. Knowing a syscall is not knowing practice.** `mount(2)` is in every
textbook, but modern `util-linux` calls `move_mount`. Check with
`strace` rather than relying on theory.

**7. Protection has to live where the action happens.** A Python
denylist does not stop a kill in the kernel. Every response tier
requires its own tier of protection.

**8. Layered protection pays off.** The rule bug was real and dangerous,
but `warn_only_namespaces` turned an outage into an informational
message (#17).

**9. Only a live cluster finds these things.** None of cases 5, 6, 8, 15
or 16 would have surfaced in unit tests — they need a real kubelet with
its reconcile loop, a real runc and real system pods.
