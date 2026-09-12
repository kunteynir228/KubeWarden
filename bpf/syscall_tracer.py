"""
KubeWarden — Syscall Tracer

Uses BCC (BPF Compiler Collection): the eBPF C code is embedded right
here and compiled on the fly through LLVM at startup.

Approach: TRACEPOINT_PROBE (syscalls:sys_enter_*) rather than kprobe.
Syntax reference — bcc/tools/execsnoop.py; opensnoop uses a similar
pattern over syscalls tracepoints.

Requirements (on the node):
    apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)

Run: sudo python3 syscall_tracer.py
"""

from bcc import BPF
import ctypes as ct
import time
import logging

# IMPORTANT: we use logging, NOT print.
# print writes to stdout, which inside a container is a pipe rather than
# a TTY, so Python buffers output in 8 KB blocks. Messages get stuck in
# the buffer and never show up in `kubectl logs` at all. That is exactly
# why the [prefill] line was invisible even though the code worked.
# logging writes to stderr, which is not buffered.
log = logging.getLogger("kubewarden.tracer")

# ---------------------------------------------------------------------------
# The eBPF program in C. Compiled by bcc at load time.
# ---------------------------------------------------------------------------
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/un.h>
#include <linux/in.h>

// Event structure sent to user space through the perf buffer
struct event_t {
    u64 ktime;           // syscall time in the kernel (ns since boot, CLOCK_MONOTONIC)
    u32 pid;
    u32 ppid;
    u64 cgroup_id;      // used later to match the event to a pod/container
    char comm[16];       // process name (TASK_COMM_LEN)
    char filename[256];  // file or binary path
    u8  syscall_type;    // 0=execve, 1=openat, 2=chroot, 3=mount, 4=setns
    u8  killed_in_kernel; // 1 = the kernel already sent SIGKILL to this process
};

BPF_PERF_OUTPUT(events);

// ---------------------------------------------------------------------------
// ARMED CGROUPS — feedback channel from user space into the kernel.
//
// The idea behind the hybrid architecture: complex logic (chains,
// threat_score, YAML) lives in Python, where strings and data structures
// exist. But once a chain reaches WARN, user space WRITES the cgroup_id
// into this map. After that the kernel kills the next suspicious syscall
// from that cgroup on its own, without asking user space — in
// microseconds instead of seconds.
//
// Value = response level:
//   1 = ARMED_KILL — send SIGKILL on red lines (chroot/mount/setns)
//
// IMPORTANT about bpf_send_signal: this is NOT syscall blocking. The
// signal is delivered at the next signal check point (usually on return
// to user space), so the syscall may still complete and the process dies
// immediately afterwards. Real blocking (-EPERM, syscall never executes)
// requires bpf_lsm hooks, CONFIG_BPF_LSM=y and lsm=bpf in the kernel
// parameters — that is the next level up. What we get here is
// sub-millisecond response, not prevention.
// ---------------------------------------------------------------------------
BPF_HASH(armed_cgroups, u64, u8);

#define ARMED_KILL 1

// ---------------------------------------------------------------------------
// CGROUP CLASSIFICATION — in-kernel filter, applied before submitting
// to the perf buffer.
//
// User space (CgroupSync) proactively scans cgroupfs and fills this map:
// 1 = pod cgroup, 2 = host cgroup.
//
// Without this filter 98% of events (measured: 34995 events, 1687
// passed) travelled all the way to Python only to be discarded — hence
// "Possibly lost N samples" and latency spikes up to 85 ms under burst.
//
// FAIL-OPEN: we drop ONLY what is known to be host-owned. An unknown
// cgroup is submitted — otherwise a new pod that has not yet made it
// into the map would be invisible until the next rescan, and that is a
// window for an undetected attack.
// ---------------------------------------------------------------------------
BPF_HASH(cgroup_class, u64, u8);

#define CLASS_POD       1
#define CLASS_HOST      2
#define CLASS_EXCLUDED  3
#define CLASS_WARN_ONLY 4

// Returns 1 if the event should be dropped right here, in the kernel.
static __always_inline int should_skip(u64 cgroup_id) {
    u8 *cls = cgroup_class.lookup(&cgroup_id);
    if (!cls)
        return 0;  // unknown -> submit (fail-open)
    // HOST — host processes; they have nowhere to escape to.
    // EXCLUDED — a namespace the operator deliberately excluded.
    if (*cls == CLASS_HOST || *cls == CLASS_EXCLUDED)
        return 1;
    return 0;
}

// Whether processes in this cgroup may be killed automatically.
// For a warn_only namespace (kube-system by default) the answer is no:
// a false kill of coredns or cilium takes the cluster down, so the
// decision is left to a human.
static __always_inline int kill_allowed(u64 cgroup_id) {
    u8 *cls = cgroup_class.lookup(&cgroup_id);
    if (cls && *cls == CLASS_WARN_ONLY)
        return 0;
    return 1;
}

// ---------------------------------------------------------------------------
// UNCONDITIONAL RED LINE — kill immediately, with no arming and no
// threat_score accumulation.
//
// Why this is separate from maybe_kill: the "WARN -> arm -> kill on the
// next step" scheme does not work for syscalls that ARE THEMSELVES a
// completed escape. During testing `nsenter --target 1` produced the
// chain [execve(nsenter) -> setns()] with score 70 — short of the 90
// threshold — and by the time user space even learned about the event
// (0.3 ms) setns had already executed and the operator had root on the
// node.
//
// !!! CRITICALLY IMPORTANT !!!
// The container-runtime filter MUST live here, in the kernel. The
// NOISE_COMMS denylist in Python does not help: red_line_kill fires
// BEFORE the event leaves for user space.
//
// A real outage: runc uses setns when creating EVERY container (its
// nsexec enters the namespaces). Without this check the agent killed
// `runc init` in the kernel, and no new pod on the node could start:
//   FailedCreatePodSandBox ... runc init error(s): nsexec-0[...]:
//   failed to sync with stage-1: next state (got 0 of 4 bytes)
//
// should_skip() does not help here: runc init already executes inside
// the cgroup of the pod being created, so its class is CLASS_POD.
// ---------------------------------------------------------------------------
static __always_inline int is_container_runtime(void) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // runc, runc:[1:CHILD], runc:[2:INIT] — every container startup stage
    if (comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n' && comm[3] == 'c')
        return 1;
    // containerd, containerd-shim
    if (comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'n' && comm[3] == 't' &&
        comm[4] == 'a' && comm[5] == 'i' && comm[6] == 'n' && comm[7] == 'e' &&
        comm[8] == 'r' && comm[9] == 'd')
        return 1;
    // crun — alternative OCI runtime
    if (comm[0] == 'c' && comm[1] == 'r' && comm[2] == 'u' && comm[3] == 'n' &&
        comm[4] == '\0')
        return 1;
    // kubelet — mounts volumes, also works with namespaces
    if (comm[0] == 'k' && comm[1] == 'u' && comm[2] == 'b' && comm[3] == 'e' &&
        comm[4] == 'l' && comm[5] == 'e' && comm[6] == 't')
        return 1;
    return 0;
}

static __always_inline int red_line_kill(u64 cgroup_id, struct event_t *e) {
    if (is_container_runtime())
        return 0;   // routine runtime work — leave it alone
    if (!kill_allowed(cgroup_id))
        return 0;   // warn_only namespace — detection only
#ifdef KERNEL_ENFORCE
    bpf_send_signal(9);
    e->killed_in_kernel = 1;
    return 1;
#else
    return 0;
#endif
}

// Check whether the cgroup is armed and kill the process if so.
// Returns 1 if a signal was sent.
static __always_inline int maybe_kill(u64 cgroup_id, struct event_t *e) {
    u8 *level = armed_cgroups.lookup(&cgroup_id);
    if (!level || *level != ARMED_KILL)
        return 0;

    // Same protection as in red_line_kill: runc performs mount and
    // pivot_root while creating a container. If a cgroup was armed and
    // then a container restarts inside it, we would kill the runtime.
    if (is_container_runtime())
        return 0;

    // warn_only namespace: detect, but never kill even when armed
    if (!kill_allowed(cgroup_id))
        return 0;

#ifdef KERNEL_ENFORCE
    // SIGKILL = 9. Cannot be sent from NMI context, but a syscall
    // tracepoint is ordinary task context, so the helper is allowed.
    // Guarded by #ifdef because on kernels < 5.3 the helper does not
    // exist and the program would fail verification entirely — better
    // to build without it than to lose detection completely.
    bpf_send_signal(9);
    e->killed_in_kernel = 1;
#endif
    return 1;
}

// Helper: fill the common event fields (shared by every probe)
static __always_inline void fill_common(struct event_t *e) {
    // The timestamp is taken IN THE KERNEL, at syscall time. It used
    // to be set in Python during handling — which made it impossible
    // both to measure delivery latency and to maintain the correlation
    // window correctly (it was based on processing time, not event
    // time).
    e->ktime = bpf_ktime_get_ns();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &parent->tgid);
}

// ---------------------------------------------------------------------------
// TRACEPOINT_PROBE instead of kprobe — bcc generates the args struct
// from the tracepoint format itself (see
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format),
// so args->filename is already a usable pointer to the argument we
// want. No manual pt_regs/di/si handling — the thing that had us
// fighting the verifier in the kprobe version is simply unnecessary
// here. bcc also attaches such probes automatically when the BPF
// object is created, so attach_tracepoint() need not be called by
// hand.
// ---------------------------------------------------------------------------

// The order inside each probe matters: first take the cgroup_id (a
// single helper call) and check the filter, and only then do the
// expensive work — bpf_probe_read_user_str over 256 bytes, reading
// task_struct for ppid, bpf_get_current_comm. For a dropped event none
// of that work happens at all.

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;                       // bail out BEFORE expensive work

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 0;
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), args->filename);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 1;
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), args->filename);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_chroot) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 2;
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), args->filename);

    // RED LINE: a chroot from an armed cgroup is killed in the kernel.
    // This must NOT be done on execve/openat — every process opens libc
    // at startup, and we would be killing everything. A chroot inside a
    // container, on the other hand, almost always means an escape
    // attempt.
    maybe_kill(e.cgroup_id, &e);

    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

// mount — the classic mount(2). IMPORTANT: modern util-linux barely
// uses it! Verified with strace: on kernel 5.2+ `mount --bind` calls
// open_tree() + move_mount() — the new mount API. This tracepoint alone
// is therefore NOT ENOUGH, see the probes below.
TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 3;
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), args->dev_name);
    maybe_kill(e.cgroup_id, &e);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

// move_mount — the second half of the new mount API (kernel 5.2+).
// This is what actually attaches the mounted tree to the target point.
// During testing `mount --bind /proc/1/root /tmp/h` produced:
//   open_tree(AT_FDCWD, "/", OPEN_TREE_CLONE) = 3
//   move_mount(3, "", AT_FDCWD, "/tmp/h", MOVE_MOUNT_F_EMPTY_PATH)
// and the classic mount(2) was never called — the escape went entirely
// unnoticed.
TRACEPOINT_PROBE(syscalls, sys_enter_move_mount) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 5;
    // to_pathname — where it is attached; more useful for triage than
    // from_pathname (which is often empty with MOVE_MOUNT_F_EMPTY_PATH)
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), args->to_pathname);
    maybe_kill(e.cgroup_id, &e);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

// open_tree — the first half of the new mount API: opens an fd on a
// filesystem subtree. It does not mount anything by itself, but with
// OPEN_TREE_CLONE it is preparation for move_mount.
TRACEPOINT_PROBE(syscalls, sys_enter_open_tree) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 6;
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), args->filename);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

// fsmount — creates a mount object from an fs_context
// (fsopen/fsconfig). The third route to mounting in the new API.
TRACEPOINT_PROBE(syscalls, sys_enter_fsmount) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 7;
    maybe_kill(e.cgroup_id, &e);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

// pivot_root — replaces the root of the entire mount namespace. This
// is what the runtime itself uses when starting a container; called
// from inside a container it almost certainly means an escape.
// An UNCONDITIONAL RED LINE for the same reason as setns.
TRACEPOINT_PROBE(syscalls, sys_enter_pivot_root) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 8;
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), args->new_root);
    red_line_kill(cgroup_id, &e);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

// ptrace — injection into another process. With hostPID it reaches
// host processes. Very rarely legitimate inside a container.
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 9;
    maybe_kill(e.cgroup_id, &e);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
// openat2 — the new file-opening variant (kernel 5.6+) with extended
// flags via struct open_how. The same story as mount -> move_mount:
// during testing nsenter opened /proc/1/ns/mnt, yet that openat never
// appeared in the chain — meaning the tool uses openat2, and without
// this probe access to namespace files stays invisible.
TRACEPOINT_PROBE(syscalls, sys_enter_openat2) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 1;   // indistinguishable from openat in user space, and that is fine
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), args->filename);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

// connect — access to a unix socket. The main target: container
// runtime sockets (containerd.sock, docker.sock, crio.sock).
//
// Why this matters more than any escape syscall: access to the runtime
// socket grants full root on the node WITHOUT a single suspicious
// syscall. The attacker performs neither chroot nor setns — they simply
// ask the runtime to start a privileged container with hostPath:/ .
// The pod needs neither privileged nor hostPID for this — a mounted
// socket is enough, and in a manifest that looks harmless.
//
// We filter on AF_UNIX: ordinary TCP connections never get here, which
// would otherwise bury us in noise from all pod network traffic.
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct sockaddr *addr = (struct sockaddr *)args->uservaddr;
    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    if (family != AF_UNIX)
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 10;

    // sun_path comes right after sa_family (2 bytes) in struct sockaddr_un
    struct sockaddr_un *uaddr = (struct sockaddr_un *)addr;
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), uaddr->sun_path);

    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

// init_module / finit_module — loading a kernel module.
// An UNCONDITIONAL RED LINE and the most destructive vector of all:
// whoever loads a module controls the kernel and can disable KubeWarden
// itself (unload our eBPF programs, hide processes, intercept
// anything).
//
// Requires CAP_SYS_MODULE. Note: CAP_SYS_ADMIN alone does NOT grant
// module loading — a common misconception. privileged:true, however,
// grants every capability including SYS_MODULE.
//
// There is no legitimate reason to load a module from inside a
// container: modules are loaded by the host at boot, never by the
// runtime.
TRACEPOINT_PROBE(syscalls, sys_enter_init_module) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 11;
    red_line_kill(cgroup_id, &e);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

// finit_module — the modern variant: the module is passed as a file
// descriptor rather than a buffer. This is what insmod/modprobe use.
TRACEPOINT_PROBE(syscalls, sys_enter_finit_module) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 12;
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), args->uargs);
    red_line_kill(cgroup_id, &e);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

// delete_module — unloading a module. A separate vector: one could
// unload a security module, or the one monitoring depends on.
TRACEPOINT_PROBE(syscalls, sys_enter_delete_module) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 13;
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), args->name_user);
    red_line_kill(cgroup_id, &e);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

// setns — entering another process's namespace (the host's PID 1, for
// example). An UNCONDITIONAL RED LINE: there is no legitimate scenario
// from inside a container, and waiting for the score to accumulate is
// pointless — by the time user space decides, the escape has already
// happened.
TRACEPOINT_PROBE(syscalls, sys_enter_setns) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_skip(cgroup_id))
        return 0;

    struct event_t e = {};
    fill_common(&e);
    e.syscall_type = 4;
    red_line_kill(cgroup_id, &e);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""

SYSCALL_NAMES = {
    0: "execve", 1: "openat", 2: "chroot", 3: "mount", 4: "setns",
    5: "move_mount", 6: "open_tree", 7: "fsmount", 8: "pivot_root",
    9: "ptrace", 10: "connect", 11: "init_module", 12: "finit_module",
    13: "delete_module",
}

# Control-plane/runtime/CNI service processes — their syscalls are not an
# attack but routine polling/reconcile/readiness probing (containerd-shim
# reads cgroup metrics, calico-node/felix/bird invoke `ip`/`sv`,
# runc:[N:xxx] are short-lived process startup stages spawned by a health
# check, and so on)
NOISE_COMMS = {
    "containerd-shim", "containerd", "kubelet", "kube-proxy",
    "calico-node", "felix", "bird", "birdcl", "sv", "ip", "ipset",
    "falco", "check-status", "coredns", "kube-apiserver", "systemd",
    "etcd", "kubectl", "iptables", "ip6tables",
    "kube-controller", "kube-scheduler",  # truncated to 15 chars by TASK_COMM_LEN
    # Image scanners and security agents: by the nature of their work
    # they read a lot of files and talk to the runtime socket. trivy was
    # falsely killed on a live cluster before the path-matching fix.
    "trivy", "trivy-operator", "grype", "syft",
}
# runc spawns processes named "runc:[1:CHILD]", "runc:[2:INIT]" and so on —
# matched by prefix rather than an exact list, which would never end
NOISE_COMM_PREFIXES = ("runc",)


class Event(ct.Structure):
    _fields_ = [
        ("ktime", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("cgroup_id", ct.c_uint64),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 256),
        ("syscall_type", ct.c_uint8),
        ("killed_in_kernel", ct.c_uint8),
    ]


class SyscallTracer:
    """
    Wrapper around BCC: loads the program (tracepoint probes are
    attached automatically) and delivers events out through a callback.
    """

    def __init__(self, on_event, kernel_enforce=False, metrics=None):
        self.on_event = on_event
        self.kernel_enforce = kernel_enforce
        self.metrics = metrics

        # bpf_send_signal() appeared in kernel 5.3. On older kernels a
        # program containing that helper simply will not load — so we
        # strip the call with the preprocessor instead of failing
        # verification.
        cflags = []
        if kernel_enforce and BPF.support_raw_tracepoint():
            cflags.append("-DKERNEL_ENFORCE=1")
        elif kernel_enforce:
            log.warning("kernel lacks the required helpers — "
                        "kernel-enforce disabled, running detection only")
            self.kernel_enforce = False

        self.bpf = BPF(text=BPF_PROGRAM, cflags=cflags)
        self.cgroup_sync = None

        # IMPORTANT: BPF(text=...) attaches the tracepoint probes
        # IMMEDIATELY, so events start being generated right away. The
        # full cgroup_sync, however, starts later from main. In that
        # window the in-kernel filter is empty, everything passes, and
        # poll_loop is not reading the buffer yet — hence a consistent
        # ~90 lost events on every startup (measured via metrics: 94 out
        # of 246410 over two hours, all at startup).
        #
        # We fill the HOST classes right here: kubelet, containerd and
        # etcd account for 90% of the noise. This is an os.walk over
        # system.slice with no API calls, ~10 ms. Pod classification
        # with namespace resolution stays in the background cgroup_sync
        # — it needs an API server and is less urgent (pods are covered
        # by fail-open, see should_skip).
        self._prefill_host_classes()

        self.stats = {
            "total": 0, "passed": 0,
            "latency_sum": 0.0, "latency_max": 0.0,
            "started": time.monotonic(),
        }
        self.lost_total = 0
        # attach_kprobe() is no longer needed here: probes declared via
        # TRACEPOINT_PROBE in the C code are attached by bcc
        # automatically when the BPF object is created — one of the
        # conveniences of that macro.
        #
        # page_cnt=64 (not 256): inflating the buffer is not a cure for
        # losses, it merely postpones overflow while consuming memory on
        # every CPU. The real fix is filtering in the kernel, before
        # submission.
        # lost_cb: by default bcc prints "Possibly lost N samples" to
        # stdout, making it impossible to notice a trend. We intercept
        # that and account for it as a metric.
        self.bpf["events"].open_perf_buffer(
            self._handle_event, page_cnt=64, lost_cb=self._handle_lost)

    def _handle_lost(self, count):
        self.lost_total += count
        if self.metrics is not None:
            self.metrics.on_lost(count)

    def _prefill_host_classes(self):
        """
        Quickly mark host cgroups right when the program is loaded.
        No namespace resolution and no API calls — just a cgroupfs walk,
        so the in-kernel filter starts working before events pile up.
        """
        import os
        from core.cgroup_sync import CGROUP_ROOT, HOST_TOP_LEVEL, CLASS_HOST

        m = self.bpf["cgroup_class"]
        n = 0
        errors = []
        missing = []
        for top in HOST_TOP_LEVEL:
            root = os.path.join(CGROUP_ROOT, top)
            if not os.path.isdir(root):
                missing.append(top)
                continue
            for dirpath, _, _ in os.walk(root):
                try:
                    cid = os.stat(dirpath).st_ino
                    m[ct.c_uint64(cid)] = ct.c_uint8(CLASS_HOST)
                    n += 1
                except Exception as e:
                    # This used to be a silent continue, so when the
                    # marking failed nothing appeared in the log at all
                    # and the cause was impossible to find.
                    if len(errors) < 3:
                        errors.append(f"{dirpath}: {e}")

        if n:
            log.info(f"prefill: marked {n} host cgroups before polling starts")
        else:
            log.warning(f"prefill: NOTHING marked (root={CGROUP_ROOT}, "
                        f"missing dirs: {missing or '-'}, "
                        f"errors: {errors or '-'})")

    # --- Arming cgroups: feedback from user space into the kernel --------
    ARMED_KILL = 1

    def arm(self, cgroup_id: int) -> bool:
        """
        Arm a cgroup: the kernel will kill the next chroot/mount/setns
        from it on its own, in microseconds, without user space
        involvement.
        Called once a chain reaches WARN — that is, before the attacker
        gets to the escape step.
        """
        try:
            key = ct.c_uint64(cgroup_id)
            self.bpf["armed_cgroups"][key] = ct.c_uint8(self.ARMED_KILL)
            return True
        except Exception as e:
            log.error(f"failed to arm cgroup={cgroup_id}: {e}")
            return False

    def disarm(self, cgroup_id: int):
        """Disarm a cgroup (the pod died or the alert was cleared)."""
        try:
            del self.bpf["armed_cgroups"][ct.c_uint64(cgroup_id)]
        except (KeyError, Exception):
            pass  # already absent — that is fine

    def armed_list(self):
        """List of armed cgroups — for debugging and metrics."""
        return [k.value for k in self.bpf["armed_cgroups"].keys()]

    # --- In-kernel filtering ----------------------------------------------
    def start_cgroup_sync(self, interval_sec=5.0, resolver=None,
                          exclude_namespaces=None, warn_only_namespaces=None,
                          blocking_first_scan=False):
        """
        Start proactive cgroup classification. After this the kernel
        drops events from host processes and excluded namespaces itself,
        spending neither perf buffer nor a Python callback on them.
        """
        from core.cgroup_sync import CgroupSync
        self.cgroup_sync = CgroupSync(
            self.bpf["cgroup_class"], interval_sec,
            resolver=resolver,
            exclude_namespaces=exclude_namespaces,
            warn_only_namespaces=warn_only_namespaces,
        )
        # blocking_first_scan=False by default: the first scan calls
        # the API server and takes hundreds of milliseconds, during
        # which the buffer overflows because poll_loop has not started.
        # Host classes are already marked by _prefill_host_classes, and
        # pods are covered by fail-open — so deferring classification is
        # safe.
        self.cgroup_sync.start(blocking_first_scan=blocking_first_scan)
        return self.cgroup_sync

    def _handle_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(Event)).contents

        # bpf_ktime_get_ns() and CLOCK_MONOTONIC are the same clock
        # (ns since boot), so the difference is the pure delivery time
        # of the event from the kernel to this handler.
        now_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        latency_ms = (now_ns - event.ktime) / 1e6

        parsed = {
            "pid": event.pid,
            "ppid": event.ppid,
            "cgroup_id": event.cgroup_id,
            "comm": event.comm.decode("utf-8", "replace"),
            "filename": event.filename.decode("utf-8", "replace"),
            "syscall": SYSCALL_NAMES.get(event.syscall_type, "unknown"),
            # ts in SECONDS of monotonic clock — aligned with the
            # kernel; the correlator uses it for the correlation window
            "ts": event.ktime / 1e9,
            "latency_ms": latency_ms,
            "killed_in_kernel": bool(event.killed_in_kernel),
        }

        self.stats["total"] += 1
        self.stats["latency_sum"] += latency_ms
        if latency_ms > self.stats["latency_max"]:
            self.stats["latency_max"] = latency_ms

        comm = parsed["comm"]
        passed = not (
            comm in NOISE_COMMS
            or comm.startswith(NOISE_COMM_PREFIXES)
            # artefact: during execve comm has not been updated yet and
            # comes from the old fd number (e.g. "6" from /proc/self/fd/6)
            or comm.isdigit()
        )

        if self.metrics is not None:
            self.metrics.on_event(latency_ms, passed)
            if parsed["killed_in_kernel"]:
                self.metrics.inc("killed_in_kernel")

        if not passed:
            return

        self.stats["passed"] += 1
        self.on_event(parsed)

    def stats_summary(self):
        """Stats for spotting bottlenecks: EPS, latency, noise ratio."""
        n = self.stats["total"]
        if n == 0:
            return "no events"
        elapsed = time.monotonic() - self.stats["started"]
        return (
            f"events={n} ({n / elapsed:.0f}/s), "
            f"passed filter={self.stats['passed']} "
            f"({100 * self.stats['passed'] / n:.1f}%), "
            f"latency avg={self.stats['latency_sum'] / n:.2f}ms "
            f"max={self.stats['latency_max']:.2f}ms"
        )

    def poll_loop(self):
        # timeout=100ms rather than a blocking call: gives Python a
        # chance to handle KeyboardInterrupt and lets the calling code
        # run periodic tasks between iterations.
        while True:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
        print(f"\n[stats] {self.stats_summary()}")
        if self.cgroup_sync is not None:
            print(f"[cgroup-sync] {self.cgroup_sync.summary()}")


if __name__ == "__main__":
    def _print_event(e):
        print(f"[{e['syscall']:7}] pid={e['pid']} ppid={e['ppid']} "
              f"comm={e['comm']} file={e['filename']} "
              f"cgroup={e['cgroup_id']} lat={e['latency_ms']:.2f}ms")

    tracer = SyscallTracer(on_event=_print_event)
    print("KubeWarden syscall tracer started. Ctrl+C to exit.")
    tracer.poll_loop()
