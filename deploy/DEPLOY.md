# Deploying KubeWarden as a DaemonSet

## 0. What changes compared to running from the node

| | Running from the node (debug) | DaemonSet |
|---|---|---|
| Cluster permissions | `admin.conf` = `system:masters` | ServiceAccount: pods get/list/delete, events create |
| Coverage | one node, for as long as the SSH session lives | every node, restarted on failure |
| Policy config | file on disk | ConfigMap |
| Node name | `socket.gethostname()` | `NODE_NAME` from `fieldRef` |

## 1. Building the image

The image is large (~450 MB) because of LLVM, which bcc needs to
compile eBPF on the fly.

```bash
cd ~/kubewarden
sudo docker build -t kubewarden:0.9 .
```

If there is no Docker on the nodes (we use containerd), build with
`buildah` — it needs no daemon:

```bash
sudo buildah bud -t kubewarden:0.9 .
```

`nerdctl` can run containers but needs a separate buildkit daemon to
build them, which is its well-known inconvenience.

## 2. Getting the image onto the nodes

Without a registry — build once and import on every node:

```bash
# where you built it
mkdir -p ~/kubewarden/images
sudo buildah push kubewarden:0.9 \
  docker-archive:$HOME/kubewarden/images/kw09.tar:kubewarden:0.9

scp ~/kubewarden/images/kw09.tar admin@worker1:~/
scp ~/kubewarden/images/kw09.tar admin@worker2:~/

# on each node — the k8s.io namespace MATTERS, without it kubelet
# will not see the image:
sudo ctr --namespace k8s.io images import ~/kw09.tar
sudo crictl images | grep kubewarden    # verify
```

Two things worth knowing, both learned the hard way:

- **`/tmp` is wiped on reboot.** systemd clears it on boot (see
  `/usr/lib/tmpfiles.d/tmp.conf`), and if `/tmp` is a tmpfs it lives in
  RAM and disappears anyway. Keep build artefacts in your home
  directory.
- **Always use a new tag.** With `imagePullPolicy: IfNotPresent`,
  kubelet will use the cached image even if you rebuild under the same
  tag.

With a registry (your own or Docker Hub) it is a normal `push`/`pull`,
and you replace `image:` in the manifest with the full path.

## 3. RBAC

```bash
kubectl apply -f deploy/rbac.yaml
```

Verify the permissions are exactly what was intended:

```bash
kubectl auth can-i delete pods \
  --as=system:serviceaccount:kubewarden-system:kubewarden   # yes
kubectl auth can-i get secrets \
  --as=system:serviceaccount:kubewarden-system:kubewarden   # no
kubectl auth can-i create clusterrolebindings \
  --as=system:serviceaccount:kubewarden-system:kubewarden   # no
```

Those last two `no` answers matter: compromising the agent must not
grant escalation to cluster owner.

## 4. Deploying — workers only at first

Leave `tolerations` commented out in `daemonset.yaml` so the pod does
not land on the control plane (which carries the
`node-role.kubernetes.io/control-plane` taint).

```bash
kubectl apply -f deploy/daemonset.yaml
kubectl -n kubewarden-system get pods -o wide -w
```

Expect one pod on each worker, in `Running`.

**First checks:**

```bash
# did the eBPF compilation succeed? did cgroup-sync run?
kubectl -n kubewarden-system logs -l app=kubewarden --tail=20 --prefix

# did anything in the cluster break?
kubectl get pods -A | grep -v Running | grep -v Completed
```

The logs should contain:
```
[INFO] metrics available on :9102/metrics
[INFO] repeat escalation: 3 detections within 10 min -> alert
[INFO] K8s integration enabled, mode: ENFORCE (pods will be killed)
[INFO] prefill: marked 28 host cgroups before polling starts
[INFO] cgroup-sync: first scan in background, rescan every 5s
[INFO] KubeWarden started, watching syscalls...
[INFO] cgroup-sync (first scan): pod=36 host=28 warn_only=13 excluded=3 in 66ms
```

## 5. Verifying detection

```bash
kubectl apply -f deploy/attacker-pod.yaml
kubectl exec -it attacker -- bash
cat /etc/shadow && chroot /
```

```bash
kubectl -n kubewarden-system logs -l app=kubewarden --tail=10 --prefix
kubectl get events -A --field-selector reason=KubeWardenThreatDetected
```

Note the `-A`: an Event is namespaced and lives in the namespace of the
object it refers to, so without it you only see the current namespace.

## 6. Control plane — separately and carefully

Uncomment `tolerations` and re-apply. A pod will appear on the
control-plane node.

Things to understand about the control plane:

- `etcd`, `kube-apiserver`, `kube-controller-manager` and
  `kube-scheduler` are **static pods** in `kube-system`, so they fall
  under `warn_only`: detection happens, automatic killing does not.
  This is correct — a false kill of `etcd` means losing the cluster.
- The most valuable target on this node is
  `/etc/kubernetes/pki/ca.key`. With it you can issue a certificate for
  `system:masters` and gain full control of the cluster without
  exploiting a single vulnerability. There is a dedicated rule for it
  (weight 100).
- Ordinary pods are not scheduled onto the control plane (the taint),
  so the agent will mostly stay quiet there. Its purpose is to catch
  the case where someone did run a pod with a toleration.

**This path is untested.** Everything above was verified on workers
only.

## 7. Enabling kernel-enforce

Only after the normal mode has run without false positives for at least
a day.

Uncomment `--kernel-enforce` in `args`, apply, and **immediately**
check that new pods can still be created:

```bash
kubectl apply -f deploy/daemonset.yaml
kubectl -n kubewarden-system rollout status ds/kubewarden
kubectl run test --image=busybox --restart=Never -- sleep 60
kubectl get pod test -w    # must reach Running
```

Why that specific check: `runc` uses `setns` when creating every
container, and a mistake in the runtime allowlist
(`is_container_runtime()` in the eBPF code) means no pod on the node can
start any more. This has already happened during development.

Rollback if something goes wrong:
```bash
kubectl -n kubewarden-system delete ds kubewarden
```

## Known first-run problems

**`OOMKilled` at startup** — LLVM needs memory while compiling eBPF.
Raise `resources.limits.memory` to 1Gi.

**`failed to compile BPF module`** — the header version in
`/lib/modules` does not match the node's kernel. Check on the node:
```bash
uname -r
ls /usr/src/
sudo apt install -y linux-headers-$(uname -r)
```

This is the single most likely failure, and it also happens **after a
kernel upgrade and reboot**: the node comes up on a new kernel whose
headers are not installed, and the agent goes into
`CrashLoopBackOff`. A metapackage helps keep them in sync:

```bash
sudo apt install -y linux-headers-cloud-amd64   # adjust for your flavour
```

**`Operation not permitted` when loading the program** — insufficient
privileges. Make sure `privileged: true` is still there.

**`cgroup.kill unavailable`** in the logs — `/sys/fs/cgroup` is mounted
read-only, or this is cgroup v1. The agent will keep working, but the
response degrades to the slow API-delete.

**`ImagePullBackOff` with `pull access denied`** — the image is not on
that node. `ctr images import` does not survive an image garbage
collection, and a rebuilt image under the same tag is ignored because of
`IfNotPresent`. Re-import under a new tag.
