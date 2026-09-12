# KubeWarden — architecture

Component-level detail. The README covers the overall design, the
policy model and the verified attack vectors; this document explains
what each module does and why it is written the way it is.

## Contents

1. [One incident, start to finish](#1-one-incident-start-to-finish)
2. [Sensors: which syscalls and why](#2-sensors-which-syscalls-and-why)
3. [Response tiers](#3-response-tiers)
4. [In-kernel filtering](#4-in-kernel-filtering)
5. [Protection against false positives](#5-protection-against-false-positives)
6. [Component walkthrough](#6-component-walkthrough)
7. [Reading the logs](#7-reading-the-logs)
8. [Measured figures](#8-measured-figures)

---

## 1. One incident, start to finish

A real incident from a test run, traced through every layer.

### Moment 0: agent startup

1. `PolicyEngine` reads `policies.yaml` (from a ConfigMap in the
   DaemonSet): thresholds 40/90, `exclude_namespaces`,
   `warn_only_namespaces`.
2. `K8sKiller` connects to the API server (through the pod's
   ServiceAccount in-cluster, or a kubeconfig when debugging) and starts
   two worker threads.
3. `SyscallTracer` compiles the eBPF program through LLVM — bcc does
   this on the fly, at startup, against the specific node's kernel — and
   attaches 15 tracepoints.
4. `_prefill_host_classes()` marks host cgroups immediately, before
   anything can accumulate.
5. `CgroupSync` starts a background scan of `/sys/fs/cgroup`, resolving
   each pod's namespace:
   ```
   cgroup-sync (first scan): pod=46 host=34 warn_only=12 excluded=3 in 58ms
   ```
6. `poll_loop()` begins reading the perf buffer.

### Moment 1: the attacker reads /etc/shadow

Inside pod `default/attacker` someone runs `cat /etc/shadow`.

**In the kernel**, two events occur.

`execve("/bin/cat")`:
- the `sys_enter_execve` tracepoint fires
- `bpf_get_current_cgroup_id()` -> `108000`
- `should_skip(108000)` -> class `POD` in the map, so not dropped
- `fill_common()` fills ktime, pid, ppid, comm
- `bpf_probe_read_user_str` copies `/bin/cat` from user space
- `maybe_kill` is not called (it is absent from `execve` — see §3)
- `perf_submit()` sends it to the buffer

`openat("/etc/shadow")` — the same, with `syscall_type=1`.

**In user space**, ~0.35 ms later:

```python
# _handle_event
latency_ms = (CLOCK_MONOTONIC_now - event.ktime) / 1e6   # 0.35
parsed = {...}                    # ctypes -> dict
if parsed["comm"] in NOISE_COMMS: # "cat" is not on the noise list
    return
self.on_event(parsed)
```

```python
# on_event in main.py
resolver.is_pod_cgroup(108000)    # True, this is a pod
story = correlator.process(event)
```

`_score_event`: `/etc/shadow` matches a prefix on a component boundary
-> +60. `threat_score = 60`.

`PolicyEngine.evaluate`: 60 >= warn(40), < kill(90) -> `WARN`.

```
[WARNING] cgroup=108000 proc=cat threat_score=60
          chain=[execve(/bin/ls) -> execve(/bin/cat) -> openat(/etc/shadow)]
```

Only `execve` calls and the scoring event made it into the chain — the
~30 `openat` calls on `libc.so`, `libm.so` and `ld.so.cache` were
filtered out by `summary()`. Without that the line would be 50 steps
long.

### Moment 2: the escape attempt

`chroot /` runs.

**In the kernel**: `sys_enter_chroot` -> `should_skip` passes it ->
`maybe_kill` checks `armed_cgroups`. Without `--kernel-enforce` the map
is empty, nothing happens, and the event goes to the buffer.

**In user space**: `chroot` is in `SUSPICIOUS_SYSCALLS` -> +50.
`threat_score = 110` -> `KILL`.

### Moment 3: the response

`K8sKiller.handle_kill` runs in order:

**Step 1 — resolve the pod.** `cgroup_id=108000` ->
`namespace/pod-name`:

```
108000 (inode)
  -> os.walk over /sys/fs/cgroup/kubepods*, comparing st_ino
  -> /sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/
      kubepods-burstable-pod<UID>.slice/cri-containerd-<id>.scope
  -> a regex extracts the pod UID (underscores -> dashes)
  -> list_pod_for_all_namespaces(field_selector=spec.nodeName=worker1)
  -> UID matched -> default/attacker
```

Both steps are cached. The cache was warmed during the WARN, so this
takes microseconds.

**Step 2 — namespace check.** `default` is in neither
`exclude_namespaces` nor `warn_only_namespaces`, so full enforcement is
allowed.

**Step 3 — instant stop.** Write `1` to
`/sys/fs/cgroup/.../cgroup.kill`:

```python
with open(kill_file, "w") as f:
    f.write("1")
```

The kernel synchronously sends SIGKILL to **every** process in the
cgroup, including children and background ones. Microseconds. This is
where the attack actually stops.

**Step 4 — enqueue.** `(namespace, pod_name, reason)` goes into a
`queue.Queue`, from which a worker thread picks up the slow part:
creating the Event and calling API delete.

```
[CRITICAL] cgroup=108000 KILL — proc=chroot threat_score=110 chain=[...]
[INFO]     cgroup.kill: all processes in cgroup=108000 killed
[CRITICAL] KILLED default/attacker [cgroup.kill (instant),
           API-delete queued] — proc=chroot threat_score=110 chain=[...]
[INFO]     API-delete done: default/attacker
```

The first three lines share the same millisecond. The API delete
completed 27 ms later, in the background, without delaying event
processing.

**From the attacker's side:**

```
/ # command terminated with exit code 137
```

`137 = 128 + 9` -> SIGKILL.

### Moment 4: cleanup

```python
correlator.forget(story.cgroup_id)     # forget a dead pod's history
last_decision.pop(story.cgroup_id)     # reset the alert state
tracer.disarm(story.cgroup_id)         # remove it from armed_cgroups
```

Without `forget()`, residual events from the killed pod would linger in
the correlation window and generate WARNs about a corpse.

### Moment 5: human triage

```bash
kubectl get events -A --field-selector reason=KubeWardenThreatDetected -o wide
```

```
NAMESPACE  OBJECT          SOURCE      MESSAGE
default    pod/attacker    kubewarden  proc=chroot threat_score=110
  chain=[execve(/bin/cat) -> openat(/etc/shadow) -> execve(/bin/chroot) -> chroot(/)]
```

The Event is self-contained: who (`proc=chroot`), how serious
(`threat_score=110`), and exactly what was attempted (the full chain).

### The kernel-enforce variant: response before user space knows

With `--kernel-enforce` the `nsenter` scenario looks different:

```
[CRITICAL] cgroup=137833 KILLED IN KERNEL: setns() proc=nsenter pid=2841255
           (latency 1.90ms)
[CRITICAL] cgroup=137833 KILL — proc=nsenter threat_score=100
           chain=[execve(/usr/bin/nsenter) -> setns()]
[INFO]     cgroup.kill: all processes in cgroup=137833 killed
[CRITICAL] KILLED default/attacker [...]
```

The first line means the kernel had **already** killed the process by
the time user space received the event. From the attacker's side:

```
attacker:~# nsenter --target 1 --mount --pid bash
Killed                     nsenter --target 1 --mount --pid bash
attacker:~# command terminated with exit code 137
```

`Killed` is `bpf_send_signal` taking out `nsenter` — the operator never
reached the host namespace. The next line is `cgroup.kill` removing the
whole pod. Two mechanisms, each doing its part: the kernel stopped the
**action**, user space removed the **source**.

---

## 2. Sensors: which syscalls and why

15 tracepoints, grouped by purpose.

### Observation (no in-kernel response)

| Syscall | Purpose |
|---|---|
| `execve` | which programs were started — the plot of the attack |
| `openat`, `openat2` | file access; the rules decide which files matter |
| `open_tree` | preparation for `move_mount`, harmless alone (+20) |
| `connect` | unix socket access (the runtime socket) |

`maybe_kill` is deliberately **not** called in these: every process
opens dozens of libraries at startup. A response there would mean
killing everything.

### Mounting (response after arming)

| Syscall | Weight | Note |
|---|---|---|
| `mount` | 70 | the classic mount(2) |
| `move_mount` | 70 | **the new mount API** (kernel 5.2+) |
| `fsmount` | 70 | new API via `fs_context` |

On `move_mount` specifically. Modern `util-linux` barely uses
`mount(2)`. Verified with `strace` on a live cluster:

```
$ strace -e trace=mount,move_mount,fsopen,open_tree mount --bind /proc/1/root /tmp/h
open_tree(AT_FDCWD, "/", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC) = 3
move_mount(3, "", AT_FDCWD, "/tmp/h", MOVE_MOUNT_F_EMPTY_PATH)
```

The classic `mount(2)` was never called. While only that sensor existed,
`mount --bind /proc/1/root` went completely unnoticed — the escape
succeeded with the agent running.

### Unconditional red lines

| Syscall | Weight | Why no chain is needed |
|---|---|---|
| `setns` | 100 | entering another namespace = escape completed |
| `pivot_root` | 100 | replaces the root of the whole mount namespace |
| `init_module` | 100 | whoever loads a module owns the kernel |
| `finit_module` | 100 | the fd variant, used by `insmod` |
| `delete_module` | 100 | a security module could be unloaded |

The "WARN -> arm -> kill on the next step" scheme does not work for
these: by the time user space learns about the event (0.35 ms), `setns`
has already executed. Verified in practice — `nsenter --target 1` with a
weight of 70 produced only a WARN, and the operator got root on the
node.

### Other

`ptrace` (40) — injection into another process; with `hostPID`, into
host processes. Response after arming.

---

## 3. Response tiers

| Tier | When | What it does | Latency |
|---|---|---|---|
| `red_line_kill` | `setns`, `pivot_root`, `*_module` | SIGKILL to the process, unconditionally | ~40 µs |
| `maybe_kill` | `chroot`, `mount*`, `ptrace` — only if the cgroup is armed | SIGKILL to the process | ~40 µs |
| `cgroup.kill` | score >= kill_threshold | SIGKILL to every process in the pod | microseconds |
| API delete | after cgroup.kill, in the background | remove the pod object from the cluster | ~20–70 ms |

### How arming works

The core idea of the hybrid scheme — the decision is made early, at the
suspicion stage, and executed instantly at the first real escape step:

```
1. Attacker reads /etc/shadow          -> score 60 -> WARN
2. User space writes cgroup_id into the armed_cgroups BPF map
3. Attacker runs chroot /
4. The KERNEL sees: cgroup armed + this is chroot -> bpf_send_signal(SIGKILL)
5. The process is dead in ~40 µs, before user space learns of the event
```

Enabled with `--kernel-enforce`.

### Honestly about bpf_send_signal

This is **not** syscall blocking. The signal is delivered at the next
signal check point — usually on return to user space — so the syscall
may still complete and the process dies immediately afterwards.

In practice: `nsenter` technically executed `setns`, but died before it
could use the namespace it obtained — the `bash` inside never started.

Real blocking (returning `-EPERM`, the syscall never executing) requires
LSM hooks via `bpf_lsm`, meaning `CONFIG_BPF_LSM=y` and `lsm=bpf` at
boot.

The honest description is sub-millisecond **response**, not prevention.

### Why cgroup.kill is needed alongside bpf_send_signal

`bpf_send_signal` only kills the process that made the syscall. The
attacker may have others — a background reverse shell, for instance.
`cgroup.kill`, one byte written to a file, takes out the **entire**
cgroup and leaves nothing behind.

### Why API delete is not good enough as the primary response

```
KubeWarden -> API server: "delete the pod"  (71 ms, the log ends here)
API server -> etcd:       record removed
   ... watch event travels to kubelet ...
kubelet -> containerd:    StopContainer
containerd -> processes:  SIGKILL           <- the attacker actually dies here
```

Those steps take **5–30 seconds**. Worse: with `grace_period=0` the API
server removes the object from etcd without waiting for kubelet — the
pod disappears from `kubectl get pods` while the container keeps running
"orphaned".

This was observed in testing: after a KILL fired, it was still possible
to run commands comfortably inside a pod that formally no longer
existed.

---

## 4. In-kernel filtering

### Why it is needed

Measured on a real node without filtering: **868 events/sec** reaching
user space, of which only **11%** passed the noise filters. The other
89% of the work (perf buffer, ctypes callback, parsing) was wasted —
which also caused event loss (`Possibly lost 103 samples`) and latency
spikes up to 85 ms.

With in-kernel filtering: **68 events/sec**, zero losses.

### Four classes

```python
CLASS_POD = 1        # ordinary pod -> full enforcement
CLASS_HOST = 2       # host process -> drop in the kernel
CLASS_EXCLUDED = 3   # exclude_namespaces -> drop in the kernel
CLASS_WARN_ONLY = 4  # warn_only_namespaces -> detect, never kill
```

### Fail-open by design

```c
static __always_inline int should_skip(u64 cgroup_id) {
    u8 *cls = cgroup_class.lookup(&cgroup_id);
    if (!cls)
        return 0;  // UNKNOWN -> submit
    if (*cls == CLASS_HOST || *cls == CLASS_EXCLUDED)
        return 1;
    return 0;
}
```

We drop **only** what is explicitly marked as unwanted. An unknown
cgroup is submitted.

Why this matters: if we only passed explicit `CLASS_POD`, a pod created
between `CgroupSync` scans would be invisible for up to 5 seconds. For a
security agent that window is unacceptable. One extra event is cheaper
than a missed attack.

### Who ends up as HOST

`system.slice`, `init.scope`, `user.slice` — where `kubelet`,
`containerd`, `etcd`, `kube-apiserver` and `systemd` live. They are the
noisiest processes on the node, and scoring them is pointless: a host
process has nowhere to "escape the container" to, it is already on the
host.

More importantly, this was the source of a dangerous false positive:
kubelet routinely calls `mount(tmpfs)` and reads
`/var/lib/kubelet/pods/.../token` while mounting volumes. Together those
scored `threat_score=100` -> KILL. The only thing that saved us was the
resolver failing to find a pod.

Separately unpleasant: our own kill triggers volume cleanup (`umount`),
which without this filter looked like an attack again — the agent
reacting to the consequences of its own actions.

### Order inside a probe

```c
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;                       // <- bail out BEFORE expensive work

    struct event_t e = {};
    fill_common(&e);                    // reads task_struct, comm
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), args->filename);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
```

The check comes **first**, before `fill_common()` and before copying 256
bytes of string. For a dropped event none of that work happens.

### Synchronising through cgroupfs rather than the API

`CgroupSync` scans `/sys/fs/cgroup` rather than asking the API server:
cgroupfs is the source of truth on the node, works without an API
server, and never lags behind reality during fast pod create/delete.

Measured: 84 cgroups in 3–4 ms; 46+34+12+3 on a live node in 58 ms. The
5-second interval can be lowered to 1–2 if you want to narrow the window
for new pods.

Namespace resolution happens in that same background thread, so it does
not make event handling on the hot path any more expensive.

### Two startup problems, both about ordering

`BPF(text=...)` attaches the probes **immediately** — events start
flowing at once, while the map is still empty and `poll_loop()` is not
reading. That produced a consistent ~270 lost events per startup
(invisible in the logs, because bcc printed the warning straight to
stderr from C).

Two fixes were needed:

1. `_prefill_host_classes()` right after loading the program: a fast
   `system.slice` walk with no API calls, ~10 ms.
2. `CgroupSync.start(blocking_first_scan=False)` — the first scan calls
   `list_pod_for_all_namespaces` and takes hundreds of milliseconds, so
   it must not run before polling begins.

Result: zero drops.

---

## 5. Protection against false positives

This was half of all the work on the project. A tool that occasionally
takes down `coredns` will be switched off — and then it catches nothing
at all.

### Five layers

**1. Runtime allowlist in the kernel** (`is_container_runtime()`)

```c
static __always_inline int is_container_runtime(void) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0]=='r' && comm[1]=='u' && comm[2]=='n' && comm[3]=='c') return 1;
    // + containerd, crun, kubelet
    return 0;
}
```

Checked **before** `bpf_send_signal`, in both `red_line_kill` and
`maybe_kill`.

Why it has to be in the kernel: `runc` uses `setns` when creating
**every** container — its `nsexec` enters the namespaces. The Python
`NOISE_COMMS` denylist does not help, because the response fires before
the event is submitted to user space.

Without this check the agent killed `runc init`, and no new pod on the
node could be created:

```
FailedCreatePodSandBox ... runc init error(s): nsexec-0[2810545]:
failed to sync with stage-1: next state (got 0 of 4 bytes)
```

`should_skip()` does not help here: `runc init` already executes inside
the cgroup of the pod being created, so its class is `CLASS_POD`.

**2. Host process filter** (`is_pod_cgroup()`) — host processes are
never scored, see §4.

**3. Noisy process denylist** (`NOISE_COMMS`)

```python
NOISE_COMMS = {
    "containerd-shim", "containerd", "kubelet", "kube-proxy",
    "calico-node", "felix", "bird", "birdcl", "sv", "ip", "ipset",
    "falco", "check-status", "coredns", "kube-apiserver", "systemd",
    "etcd", "kubectl", "iptables", "ip6tables",
    "kube-controller", "kube-scheduler",
    "trivy", "trivy-operator", "grype", "syft",
}
NOISE_COMM_PREFIXES = ("runc",)
```

Plus discarding `comm.isdigit()` — during `execve` the process name has
not been updated yet and comes from a file descriptor number (`comm="6"`
from `/proc/self/fd/6`).

`runc` is matched by prefix: it spawns processes named `runc:[1:CHILD]`,
`runc:[2:INIT]`, and enumerating them all is futile.

**4. Two namespace tiers** — see the README section on policies.

**5. Rule precision** — component-boundary path matching, plus
explicitly excluding a pod's own SA token from the rules.

### The observation about calico-node

`calico-node` is **legitimately** privileged with `hostPID`, so
`/proc/1/root` inside it really does lead to the host root. The most
dangerous pod in a cluster is often not one someone misconfigured — it
is the CNI installed per the documentation.

### The pattern nobody expected

Three times in a row the agent attacked a security tool:
`metrics-server` (its SA token), `trivy` (`/etc/hosts`), `falco`
(`/host/usr/src`). That is not a coincidence — we share a behaviour
profile with them: mounting the host filesystem, reading system paths,
running privileged.

The practical consequence: "a pod touches host paths" is useless as a
signal, because both defenders and attackers do it. Only **which** path,
in **which** combination, distinguishes them.

---

## 6. Component walkthrough

### `bpf/syscall_tracer.py` — the sensor

The most complex file. Contains the eBPF program in C inside a Python
string (bcc compiles it through LLVM at startup) plus the Python
wrapper.

#### The event struct

```c
struct event_t {
    u64 ktime;            // bpf_ktime_get_ns() — taken IN THE KERNEL
    u32 pid;
    u32 ppid;
    u64 cgroup_id;        // = the cgroup directory's inode
    char comm[16];        // TASK_COMM_LEN, longer names are truncated
    char filename[256];
    u8  syscall_type;
    u8  killed_in_kernel; // 1 = the kernel already sent SIGKILL
};
```

About `ktime`: the timestamp is taken in the kernel, not when Python
handles the event. That makes it possible to measure delivery latency
and to maintain the correlation window correctly. Previously `ts` was
set in user space, so the window was based on processing time.

Important: `bpf_ktime_get_ns()` and
`time.clock_gettime(CLOCK_MONOTONIC)` are the **same clock**, so they
can be subtracted. Consequently the correlator also uses
`time.monotonic()` rather than `time.time()` — mixing them is not
allowed.

#### Two BPF maps

```c
BPF_HASH(armed_cgroups, u64, u8);   // armed: user space -> kernel
BPF_HASH(cgroup_class,  u64, u8);   // cgroup classification
```

This is a communication channel in the reverse direction: normally user
space reads from the kernel, here it also **writes decisions** that the
kernel applies on its own.

#### Conditional compilation

```c
#ifdef KERNEL_ENFORCE
    bpf_send_signal(9);
    e->killed_in_kernel = 1;
#endif
```

`bpf_send_signal()` appeared in kernel 5.3. On older kernels a program
containing it fails verification **entirely** — better to build without
enforcement than to lose all detection.

#### The connect sensor

```c
struct sockaddr *addr = (struct sockaddr *)args->uservaddr;
u16 family = 0;
bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
if (family != AF_UNIX)
    return 0;

struct sockaddr_un *uaddr = (struct sockaddr_un *)addr;
bpf_probe_read_user_str(&e.filename, sizeof(e.filename), uaddr->sun_path);
```

The `AF_UNIX` filter in the kernel is mandatory: without it all pod TCP
traffic would bury the buffer.

---

### `core/correlator.py` — the brain

#### AttackStory

```python
self.events = deque()      # items: (event, score_delta)
```

Each event is stored **together with its contribution to the score**, so
that eviction subtracts exactly what was added:

```python
def _evict_old(self):
    cutoff = time.monotonic() - CORRELATION_WINDOW_SEC
    while self.events and self.events[0][0]["ts"] < cutoff:
        _, old_score = self.events.popleft()
        self.threat_score -= old_score      # <- this is the important part
```

#### The readability filter

```python
def summary(self):
    steps = []
    for e, score in self.events:
        is_scored = score > 0
        is_exec = e["syscall"] == "execve" and not _is_library(e["filename"])
        if is_scored or is_exec:
            steps.append(f"{e['syscall']}({e['filename']})")
    return " -> ".join(steps)
```

Only scoring events and `execve` of non-libraries make it into the
chain.

Why the harmless `execve(/bin/ls)` stays: it shows a human's behaviour
(they were looking around), whereas `openat(libc.so)` is linker work
nobody chose.

---

### `core/pod_resolver.py` — the translator

Turns a `cgroup_id` into `namespace/pod-name`. Three steps, all cached.

**Step 1: cgroup_id -> path.** `bpf_get_current_cgroup_id()` returns the
**inode number** of the cgroup directory. So the path is found by
walking `/sys/fs/cgroup/kubepods*` and comparing
`os.stat(dirpath).st_ino`.

**Step 2: path -> pod UID.** A regex over the slice name. Works for
every QoS class: `kubepods-burstable-pod<UID>.slice`,
`kubepods-besteffort-pod<UID>.slice`, `kubepods-pod<UID>.slice`.

**Step 3: pod UID -> pod.** A list of pods for **our node only**
(`field_selector=spec.nodeName=<node>`) with the UID matched in Python.
More reliable than a field selector on `metadata.uid`, whose support
depends on the version.

**The negative cache** (`_not_in_kubepods`) exists so host processes do
not trigger a full `os.walk` on every event — and those events are the
majority.

**Owner resolution** (`owner_of`) is used by the repeat tracker. It goes
through `ownerReferences`; for a Deployment the ReplicaSet hash is
additionally stripped, otherwise a rollout would reset the counter:

```
payment-api-7d9f8c4b5-x7k2p  ->  prod/ReplicaSet/payment-api
payment-api-9aa11bb22-zz99x  ->  prod/ReplicaSet/payment-api   (after rollout)
```

---

### `core/k8s_killer.py` — the response

#### The queue and deduplication

```python
self._api_queue = queue.Queue(maxsize=1000)
self._in_flight = set()          # (namespace, pod_name) already in flight
self._lock = threading.Lock()
```

A single `handle_kill` without the queue would take ~140 ms (Event plus
delete). While it runs, `perf_buffer_poll()` is not called and the
buffer is not drained. With ten simultaneous detections that is over a
second of blindness, during which at 800 events/s hundreds of events
from other pods are lost — and an attack on the eleventh pod goes
unnoticed.

#### The Event

The `event_time` field is **deliberately left unset**: it switches
validation to the `events.k8s.io/v1` format, where `action` and
`reportingController` are mandatory, and the API returns
`422 action: Required value`. The two legacy timestamps
(`first_timestamp`, `last_timestamp`) are enough for `kubectl` to show a
time.

The Event is created via `generate_name`, so each detection is a
separate object with `count=1`. For security alerts that is correct:
every incident keeps its own chain and nothing gets merged.

`_emit_event` is wrapped in `try/except` — failing to create the Event
does not prevent killing the pod. Priority: stopping the attack matters
more than recording the alert.

---

### The remaining modules

**`core/policy_engine.py`** — reads the YAML, compares the score against
the thresholds, formats the human-readable reason. `last_comm()` returns
the process name from the last **scoring** event rather than the last
library load, because that is the one that matters during triage.

**`core/cgroup_sync.py`** — background classification, see §4.

**`core/repeat_tracker.py`** — counts KILL decisions per pod owner in a
sliding window. Entries appear only on a detection, so in a healthy
cluster this holds a handful of records.

**`core/metrics.py`** — the Prometheus endpoint, no external
dependencies. Counters are updated on the hot path; gauges are refreshed
once a minute by a background thread so that rendering `/metrics` never
depends on scrape frequency.

---

## 7. Reading the logs

### Normal operation

```
[INFO] prefill: marked 28 host cgroups before polling starts
[INFO] cgroup-sync: first scan in background, rescan every 5s
[INFO] KubeWarden started, watching syscalls...
[INFO] cgroup-sync (first scan): pod=46 host=34 warn_only=12 excluded=3 in 58ms
```

```
[WARNING] cgroup=108000 proc=cat threat_score=60
          chain=[execve(/bin/ls) -> execve(/bin/cat) -> openat(/etc/shadow)]
```
A suspicion. `proc` is the process from the last scoring event.

```
[CRITICAL] cgroup=108000 KILL — proc=chroot threat_score=110 chain=[...]
[INFO]     cgroup.kill: all processes in cgroup=108000 killed
[CRITICAL] KILLED default/attacker [cgroup.kill (instant), API-delete queued]
[INFO]     API-delete done: default/attacker
```
A full response. The first three lines share one millisecond.

### Special cases

```
[CRITICAL] cgroup=555 KILLED IN KERNEL: setns() proc=nsenter pid=1235 (latency 1.90ms)
```
`--kernel-enforce` fired. The process was killed before user space could
decide anything. The `latency` here is the time until **logging**, not
until the response — the response happened at syscall time.

```
[WARNING] kube-system/calico-node-gzrqh: WARN-ONLY namespace — pod NOT killed,
          creating an Event for human triage. Reason: ...
```
The kube-system protection worked.

```
[WARNING] cgroup=29610: could not match to a pod — kill skipped
```
The resolver found no pod. After `is_pod_cgroup` was added this should
not appear.

### Stats on exit (Ctrl+C, standalone run)

```
[stats] events=1873 (68/s), passed filter=511 (27.3%), latency avg=0.83ms max=49.41ms
[cgroup-sync] scans=6 pod=50 host=34 warn_only=2 excluded=2 last=4ms
```

---

## 8. Measured figures

Measured on `worker1` (kubeadm, Calico, Falco, metrics-server, Trivy).

### In-kernel filtering

| Metric | Without filter | With filter | Change |
|---|---|---|---|
| Events reaching user space | 868/s | 68/s | **−92%** |
| Losses | `lost 103 samples` | none | eliminated |
| Share of useful events | 11.1% | 27.3% | x2.5 |
| Average latency | 1.01 ms | 0.83 ms | −18% |
| cgroupfs scan | — | 3–4 ms | negligible |

### Response speed

| Stage | Time |
|---|---|
| Syscall in the kernel -> handled in Python | 0.35 ms (avg over 246k events) |
| `bpf_send_signal` on `finit_module` | **0.04 ms** |
| `bpf_send_signal` on `setns` | 1.9 ms |
| KILL decision -> `cgroup.kill` complete | <1 ms (cache warm) |
| KILL decision -> API delete complete | ~27 ms (background) |
| **API delete -> actual SIGKILL from kubelet** | **5–30 s** |

That last row is why `cgroup.kill` exists: without it the attacker would
have seconds to keep working.

### Steady state

Measured over 7842 seconds of uptime on a live node:

```
kubewarden_events_total          246410      (31 events/s average)
kubewarden_events_dropped_total  0
kubewarden_event_latency_sum     86.69 s     (0.35 ms per event)
kubewarden_cache_entries{path}   3           (stable, no leak)
```

A note on reading these: computing latency as `sum/count` over a short
window is misleading, because the startup spike dominates. An early
measurement over 70 seconds showed 7 ms where the true steady-state
value was 0.35 ms. Use `rate()` in PromQL.
