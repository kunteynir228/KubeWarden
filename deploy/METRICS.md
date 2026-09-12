# KubeWarden metrics and alerting

Endpoint: `http://<pod>:9102/metrics`, plus `/healthz` for the liveness
probe.

## Why metrics when there are logs

Logs answer "what happened". Metrics answer "is everything working" and
"did it get worse":

| Question | Metric |
|---|---|
| Is the agent alive on every node? | `kubewarden_up` |
| Are events being lost? | `kubewarden_events_dropped_total` |
| Has latency grown? | `kubewarden_event_latency_seconds` |
| Where does detection fire? | `kubewarden_detections_total` |
| Are the caches leaking? | `kubewarden_cache_entries` |

Before this, event loss was printed by bcc itself as
`Possibly lost N samples` straight to stderr from C — you could only
notice a trend by grepping logs after the fact. It is now a counter fed
by `lost_cb`.

## Useful queries

**Events per second:**
```promql
rate(kubewarden_events_total[5m])
```

**Fraction of lost events** — anything above zero means the buffer is
overflowing and some attacks may go unnoticed:
```promql
rate(kubewarden_events_dropped_total[5m])
  / rate(kubewarden_events_total[5m])
```

**Average delivery latency from the kernel:**
```promql
rate(kubewarden_event_latency_seconds_sum[5m])
  / rate(kubewarden_event_latency_seconds_count[5m])
```

Use `rate()` rather than the raw `sum/count` ratio. The cumulative
figure averages over the whole uptime, and on a short window the
startup spike dominates — that produced a false 7 ms reading once,
where the real steady-state value was 0.35 ms.

**Kernel filter efficiency** — what share of events actually reaches
correlation (27% on a live cluster):
```promql
rate(kubewarden_events_passed_total[5m])
  / rate(kubewarden_events_total[5m])
```

**Detections per namespace over a day:**
```promql
sum by (namespace, decision) (increase(kubewarden_detections_total[24h]))
```

**Where pods were actually killed:**
```promql
sum by (method) (increase(kubewarden_kills_total[24h]))
```

**Cache growth** — unbounded growth is a leak (a known limitation:
`PodResolver` has no invalidation):
```promql
kubewarden_cache_entries
```

## Alert rules

```yaml
groups:
  - name: kubewarden
    rules:
      # The agent is down on some node, which means that node is
      # unprotected
      - alert: KubeWardenDown
        expr: up{job=~".*kubewarden.*"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "KubeWarden not responding on {{ $labels.node }}"
          description: "Node has no runtime protection. A common cause
            after a reboot is missing linux-headers for the new kernel."

      # Event loss: some attacks may pass unnoticed
      - alert: KubeWardenDroppingEvents
        expr: rate(kubewarden_events_dropped_total[5m]) > 10
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "KubeWarden losing events on {{ $labels.node }}"
          description: "Perf buffer overflowing. Check in-kernel
            filtering (--sync-interval) and node load."

      # Latency has grown — the response is slower
      - alert: KubeWardenHighLatency
        expr: |
          rate(kubewarden_event_latency_seconds_sum[5m])
            / rate(kubewarden_event_latency_seconds_count[5m]) > 0.05
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Event handling latency > 50ms on {{ $labels.node }}"

      # The detection itself — the whole point of the exercise
      - alert: KubeWardenContainerEscape
        expr: increase(kubewarden_detections_total{decision="KILL"}[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Container escape attempt in {{ $labels.namespace }}"
          description: "Details in the Kubernetes Event:
            kubectl get events -A --field-selector
            reason=KubeWardenThreatDetected"

      # Repeated activity is not a coincidence
      - alert: KubeWardenRepeatedEscalation
        expr: increase(kubewarden_escalations_total[10m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Repeated detections in {{ $labels.namespace }}"
          description: "One source triggered several times within the
            window. Legitimate applications do not behave like that."

      # Memory leak in the resolver caches
      - alert: KubeWardenCacheGrowth
        expr: kubewarden_cache_entries{cache="path"} > 10000
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Path cache has grown on {{ $labels.node }}"
          description: "Known limitation: PodResolver does not
            invalidate its caches. A pod restart clears it."
```

## Dashboard: what to show

Four panels cover everything that matters:

1. **Health** — `kubewarden_up` per node, `kubewarden_uptime_seconds`
2. **Event flow** — `rate(events_total)`, `rate(events_dropped)`, the
   `passed` ratio
3. **Latency** — average and `kubewarden_event_latency_max_seconds`
4. **Detections** — `detections_total` by namespace and decision,
   `kills_total` by method

The detections panel is usually empty, and that is correct: detections
should be rare events rather than background noise.
