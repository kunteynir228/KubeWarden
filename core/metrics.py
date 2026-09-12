"""
KubeWarden — Prometheus metrics export

No external dependencies: the Prometheus text format is simple, and an
extra package in the image is extra supply-chain surface for an agent
that runs privileged.

What this gives you that logs do not
-------------------------------------
Logs answer "what happened". Metrics answer "is everything working"
and "did it get worse":

  - is the agent alive on every node?   kubewarden_up
  - are events being lost?              kubewarden_events_dropped_total
  - has latency grown?                  kubewarden_event_latency_seconds
  - where does detection fire?          kubewarden_detections_total
  - are the caches leaking?             kubewarden_cache_entries

Without these, problems are only visible by grepping logs after the
fact. Event loss, for instance, was printed by bcc itself
("Possibly lost N samples") and noticing a trend was impossible.

Endpoint: http://<pod>:9102/metrics
"""

import time
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("kubewarden.metrics")

VERSION = "0.5"


class Metrics:
    """
    Thread-safe metrics collector.

    Counters are updated from the hot path (the perf buffer read
    callback), so every operation is a simple increment under a lock.
    There must be no heavy computation here: event handling latency is
    measured in tenths of a millisecond, and accounting must not make
    it worse.
    """

    def __init__(self, node_name="unknown"):
        self.node = node_name
        self._lock = threading.Lock()
        self.started = time.monotonic()

        # Counters (monotonically increasing)
        self.events_total = 0
        self.events_dropped = 0        # perf buffer loss (lost_cb)
        self.events_filtered = 0       # dropped by NOISE_COMMS / not-a-pod
        self.events_passed = 0         # reached correlation
        self.killed_in_kernel = 0      # bpf_send_signal fired
        self.cgroup_kills = 0          # cgroup.kill executed
        self.api_deletes = 0
        self.api_errors = 0
        self.events_emitted = 0        # Kubernetes Event created
        self.resolve_failures = 0      # cgroup -> pod match failed

        # detections[(namespace, decision)] -> count
        self.detections = {}
        # escalations[namespace] -> count
        self.escalations = {}

        # Latency: sum and max (not a histogram — enough for our
        # volumes, and buckets would complicate the hot path)
        self.latency_sum = 0.0
        self.latency_count = 0
        self.latency_max = 0.0

        # Gauge values, refreshed periodically
        self.cgroup_classes = {}       # "pod"/"host"/... -> count
        self.armed_count = 0
        self.repeat_sources = 0
        self.cache_entries = {}        # "path"/"pod"/"owner" -> count
        self.last_sync_ms = 0.0

    # --- updates from the hot path --------------------------------------

    def on_event(self, latency_ms, passed):
        with self._lock:
            self.events_total += 1
            self.latency_sum += latency_ms
            self.latency_count += 1
            if latency_ms > self.latency_max:
                self.latency_max = latency_ms
            if passed:
                self.events_passed += 1
            else:
                self.events_filtered += 1

    def on_lost(self, count):
        with self._lock:
            self.events_dropped += count

    def on_detection(self, namespace, decision):
        key = (namespace or "unknown", decision)
        with self._lock:
            self.detections[key] = self.detections.get(key, 0) + 1

    def on_escalation(self, namespace):
        ns = namespace or "unknown"
        with self._lock:
            self.escalations[ns] = self.escalations.get(ns, 0) + 1

    def inc(self, field, n=1):
        """Increment a simple counter by attribute name."""
        with self._lock:
            setattr(self, field, getattr(self, field) + n)

    def set_gauges(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                setattr(self, k, v)

    # --- rendering ------------------------------------------------------

    def render(self) -> str:
        with self._lock:
            n = f'node="{self.node}"'
            out = []
            a = out.append

            a("# HELP kubewarden_up the agent is running")
            a("# TYPE kubewarden_up gauge")
            a(f"kubewarden_up{{{n}}} 1")

            a("# HELP kubewarden_info agent version")
            a("# TYPE kubewarden_info gauge")
            a(f'kubewarden_info{{{n},version="{VERSION}"}} 1')

            a("# HELP kubewarden_uptime_seconds seconds since start")
            a("# TYPE kubewarden_uptime_seconds gauge")
            a(f"kubewarden_uptime_seconds{{{n}}} "
              f"{time.monotonic() - self.started:.0f}")

            a("# HELP kubewarden_events_total events delivered from the kernel")
            a("# TYPE kubewarden_events_total counter")
            a(f"kubewarden_events_total{{{n}}} {self.events_total}")

            a("# HELP kubewarden_events_dropped_total perf buffer losses")
            a("# TYPE kubewarden_events_dropped_total counter")
            a(f"kubewarden_events_dropped_total{{{n}}} {self.events_dropped}")

            a("# HELP kubewarden_events_filtered_total dropped by user space filters")
            a("# TYPE kubewarden_events_filtered_total counter")
            a(f"kubewarden_events_filtered_total{{{n}}} {self.events_filtered}")

            a("# HELP kubewarden_events_passed_total reached correlation")
            a("# TYPE kubewarden_events_passed_total counter")
            a(f"kubewarden_events_passed_total{{{n}}} {self.events_passed}")

            a("# HELP kubewarden_detections_total detection hits")
            a("# TYPE kubewarden_detections_total counter")
            for (ns, dec), cnt in sorted(self.detections.items()):
                a(f'kubewarden_detections_total{{{n},namespace="{ns}",'
                  f'decision="{dec}"}} {cnt}')

            a("# HELP kubewarden_escalations_total repeat escalations")
            a("# TYPE kubewarden_escalations_total counter")
            for ns, cnt in sorted(self.escalations.items()):
                a(f'kubewarden_escalations_total{{{n},namespace="{ns}"}} {cnt}')

            a("# HELP kubewarden_kills_total response actions performed")
            a("# TYPE kubewarden_kills_total counter")
            a(f'kubewarden_kills_total{{{n},method="kernel_signal"}} '
              f"{self.killed_in_kernel}")
            a(f'kubewarden_kills_total{{{n},method="cgroup_kill"}} '
              f"{self.cgroup_kills}")
            a(f'kubewarden_kills_total{{{n},method="api_delete"}} '
              f"{self.api_deletes}")

            a("# HELP kubewarden_api_errors_total API server call errors")
            a("# TYPE kubewarden_api_errors_total counter")
            a(f"kubewarden_api_errors_total{{{n}}} {self.api_errors}")

            a("# HELP kubewarden_events_emitted_total Kubernetes Events created")
            a("# TYPE kubewarden_events_emitted_total counter")
            a(f"kubewarden_events_emitted_total{{{n}}} {self.events_emitted}")

            a("# HELP kubewarden_resolve_failures_total cgroup could not be matched to a pod")
            a("# TYPE kubewarden_resolve_failures_total counter")
            a(f"kubewarden_resolve_failures_total{{{n}}} {self.resolve_failures}")

            # Event delivery latency from the kernel. We export
            # sum/count so the average can be computed in PromQL with
            # rate():
            #   rate(...latency_seconds_sum[5m]) / rate(...latency_seconds_count[5m])
            a("# HELP kubewarden_event_latency_seconds delivery latency from the kernel")
            a("# TYPE kubewarden_event_latency_seconds summary")
            a(f"kubewarden_event_latency_seconds_sum{{{n}}} "
              f"{self.latency_sum / 1000:.6f}")
            a(f"kubewarden_event_latency_seconds_count{{{n}}} "
              f"{self.latency_count}")
            a("# HELP kubewarden_event_latency_max_seconds all-time maximum")
            a("# TYPE kubewarden_event_latency_max_seconds gauge")
            a(f"kubewarden_event_latency_max_seconds{{{n}}} "
              f"{self.latency_max / 1000:.6f}")

            a("# HELP kubewarden_cgroups cgroup classification in the BPF map")
            a("# TYPE kubewarden_cgroups gauge")
            for cls, cnt in sorted(self.cgroup_classes.items()):
                a(f'kubewarden_cgroups{{{n},class="{cls}"}} {cnt}')

            a("# HELP kubewarden_armed_cgroups armed cgroups")
            a("# TYPE kubewarden_armed_cgroups gauge")
            a(f"kubewarden_armed_cgroups{{{n}}} {self.armed_count}")

            a("# HELP kubewarden_repeat_sources sources tracked for repeats")
            a("# TYPE kubewarden_repeat_sources gauge")
            a(f"kubewarden_repeat_sources{{{n}}} {self.repeat_sources}")

            # Unbounded growth here means a memory leak in the caches
            a("# HELP kubewarden_cache_entries entries in the resolver caches")
            a("# TYPE kubewarden_cache_entries gauge")
            for kind, cnt in sorted(self.cache_entries.items()):
                a(f'kubewarden_cache_entries{{{n},cache="{kind}"}} {cnt}')

            a("# HELP kubewarden_cgroup_sync_duration_seconds cgroupfs scan duration")
            a("# TYPE kubewarden_cgroup_sync_duration_seconds gauge")
            a(f"kubewarden_cgroup_sync_duration_seconds{{{n}}} "
              f"{self.last_sync_ms / 1000:.4f}")

            return "\n".join(out) + "\n"


class _Handler(BaseHTTPRequestHandler):
    metrics = None   # set when the server starts

    def do_GET(self):
        if self.path in ("/metrics", "/"):
            body = self.metrics.render().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass   # do not clutter the agent log with Prometheus requests


def start_server(metrics, port=9102):
    """Start the metrics HTTP server in a background thread."""
    _Handler.metrics = metrics
    srv = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True,
                         name="kubewarden-metrics")
    t.start()
    log.info(f"metrics available on :{port}/metrics")
    return srv
