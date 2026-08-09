# Operations: HA posture for v1 production use

Cambium ships two subcommands out of one binary — `cambium sync` (the
reconciliation daemon, `src/sync.rs`) and `cambium ropc-proxy` (the
CLI-auth shim, `src/ropc.rs`). They sit on opposite sides of the
availability-sensitivity spectrum and this document treats them
separately rather than giving "Cambium" one HA answer, because a single
answer would be wrong for at least one of them.

## 1. `cambium sync` does not need HA — it needs a restart policy

**Claim: no, it does not need high availability in the request-serving
sense.** It is a periodic batch job, not something anything is blocked
waiting on synchronously.

### What actually happens if it's down

Per `src/main.rs::run_sync`, the process loop is: acquire the singleton
lock, load the manifest, then `tokio::time::interval(poll_interval_seconds)`
firing `sync::run_pass` forever. There is no client, human or machine,
making a live call into this process and waiting on a response — it reads
from Keycloak, writes to Nexus, and goes back to sleep
(`config.rs`, default `POLL_INTERVAL_SECONDS=60`).

If the single instance is down for N minutes:

- **Grants**: a user added to a Keycloak group during the outage doesn't
  get their Nexus role until the process comes back and runs a pass. They
  see `403`/no-access in Nexus in the meantime, not corrupted or wrong
  access — a delayed grant, not a security hole.
- **Revocations**: a user removed from a Keycloak group during the outage
  keeps their previously-synced Nexus role until the process comes back.
  This is the actual blast radius worth naming explicitly: **the outage
  window is also a stale-access window**, per the revocation policy in
  `docs/sync-semantics.md` ("Cambium does revoke... stale grants are
  themselves a security problem"). A 5-minute outage is a 5-minute
  extension of somebody's access past when it should have ended. That's
  the real cost of downtime here — not a service outage, an
  access-hygiene delay.
- **MTTR** is bounded by whatever restarts the process, not by any
  Cambium-internal recovery logic: on restart, `Manifest::load` reads the
  last-persisted state file (saved per-user, not per-batch — see
  `sync-semantics.md`'s durability section) and the very next poll tick
  runs a full pass exactly as if nothing happened. There's no warm-up,
  no replay log, no manual intervention needed. A crash mid-pass loses at
  most the one user being processed when it died (already covered by
  `sync::tests::crash_after_user_n_before_final_save_does_not_lose_track_of_granted_roles`),
  and the next scheduled pass reconciles that user like any other.

Given that, adding a second warm/hot replica buys nothing: it can't reduce
the size of the stale-access window below one poll interval (a hot standby
still has to wait for the primary to actually die and a failover to
happen, which is unlikely to beat "restart and wait for the next tick"),
and — per `lock.rs` and `docs/sync-semantics.md`'s "Single-instance-only"
section — a second *live* replica racing on the same manifest file is a
correctness bug, not a redundancy feature: two processes doing
read-modify-write on the same plain JSON file can lose an update, which
reintroduces the exact "Cambium can never prove it granted a role, can
never revoke it again" hole that `docs/sync-semantics.md` treats as a
security problem. HA-for-sync would have to mean *fast automatic restart
of one instance*, not *more instances*.

### Recommended posture: `replicas: 1`, restart-always, no PDB, no leader election

- **Kubernetes: `Deployment`, `replicas: 1`.** Standard `RollingUpdate`
  with `maxSurge: 1, maxUnavailable: 0` is fine for deploys (there's a
  brief window with 2 pods during rollout, both racing on the lock file —
  see below), but there's no reason to run more than one *steady-state*
  replica: this is a singleton-by-design batch job (per `lock.rs`), not a
  request-serving workload sized for throughput.
- **`restartPolicy: Always`** (the Deployment default) is sufficient — no
  custom liveness probe logic is needed beyond a basic
  process-is-running check, since there's no HTTP endpoint to probe
  (`cambium sync` opens no listener). A `livenessProbe` isn't wired up
  today; if one is added later it should be an `exec` probe checking the
  process is alive, not a synthetic "did the last pass succeed" check —
  a transient Keycloak/Nexus outage causing `run_pass` to return `Err`
  is explicitly designed to be retried next interval
  (`main.rs`: `"reconciliation pass failed, will retry next interval"`),
  not a reason to kill the pod.
- **No `PodDisruptionBudget`.** A PDB's job is to keep at least N replicas
  up during voluntary disruptions (node drain, cluster upgrade) — with
  `replicas: 1` there's nothing for a PDB to protect; it would only ever
  block the drain itself (`minAvailable: 1` on a single-replica workload
  means the eviction is refused until the pod is manually rescheduled),
  which is the opposite of useful for a stateless-restart batch job.
- **No leader election.** Leader election exists to let multiple
  *standing* replicas agree on which one is currently active, so a crash
  triggers fast failover to an already-running standby. That only pays
  for itself when (a) more than one replica is desired for other reasons
  (there isn't one here) and (b) the cost of the standby sitting idle is
  worth it for the MTTR improvement. Here, `replicas: 1` restarted by
  Kubernetes on crash *is* the failover mechanism, and it converges to
  the same state a leader-elected standby would (the manifest and lock
  file live in the same PV/hostPath regardless of which replica reads
  them). Leader election would add a Kubernetes lease/etcd dependency to
  solve a problem `flock` on a fast-restarting single pod already solves
  more simply. Revisit only if the manifest is ever migrated off a plain
  JSON file to something with real concurrency control (per
  `sync-semantics.md`'s closing note on what a real multi-instance v2
  would require) — that's a prerequisite for the *idea* of more than one
  concurrently-useful replica to even make sense, not something HA
  tooling can paper over first.
- **Rolling-update overlap window is a known, accepted gap**: for the
  few seconds a `maxSurge: 1` rollout has both the old and new pod alive,
  the new pod's `lock::acquire` will hit `LockError::AlreadyLocked` (it
  can't get the flock while the old pod holds it) and exit
  `std::process::exit(1)` — with `restartPolicy: Always` it crash-loops
  briefly until the old pod finishes terminating and releases the lock,
  then starts cleanly. This is `lock.rs` doing exactly its documented job
  (fail fast and loudly rather than corrupt the manifest) and is
  self-resolving within one `terminationGracePeriodSeconds` window; it is
  not a reason to add `maxUnavailable: 1` first (that would create an
  actual gap in polling) — a few CrashLoopBackOff restarts during deploy
  is the correct, cheaper trade.
- **Persistent state**: `state_file` and `lock_file` (defaults
  `/var/lib/cambium/state.json`, `/var/lib/cambium/cambium.lock`) must be
  on a volume that survives pod restart/reschedule (a PVC, not
  `emptyDir`) — losing the manifest doesn't corrupt anything
  (`sync-semantics.md`'s "first-run / manifest-loss" failure mode fails
  safe, treating every existing Nexus role as foreign and preserved), but
  it does silently disable revocation until every affected user is
  re-synced, which is the same access-hygiene cost as an extended outage
  and worth avoiding for something this cheap to persist.

## 2. `cambium ropc-proxy` has a genuinely different HA requirement

Unlike sync, this is on the **live request path** for every `docker
login`, `npm login`, and `pip`/`uv` credential exchange against Nexus.
Per `ARCHITECTURE.md` and `docs/oidc-proxy-pairing.md` section 3/4b, it's
the only viable path for those CLI tools (they can't follow a browser
OIDC redirect, and `oauth2-proxy` doesn't support ROPC). If it's down,
CLI-driven pulls/pushes/installs fail synchronously and visibly — this is
a real availability-sensitive service, not a background job.

### Confirming it's actually stateless (checked, not assumed)

Read `src/ropc.rs` end to end looking specifically for anything that
would make horizontal scaling unsafe:

- **No disk state at all.** `ropc.rs` never touches `std::fs` — no
  manifest, no lock file, nothing written anywhere. `mod lock;` (declared
  in `main.rs`) and `lock::acquire` are called exactly once, from
  `run_sync()` — `run_ropc_proxy()` (`main.rs:57-63`) never references
  `lock` at all. **Confirms the task's assumption directly: `lock.rs` is
  a sync-daemon-only concern.** There is no code path by which running
  N `ropc-proxy` replicas could race on a shared file the way N `sync`
  replicas would.
- **The one piece of in-process state is `TokenCache`**
  (`ropc.rs:290-321`): an in-memory `HashMap<String /* sha256(user+pass) */,
  CacheEntry>` behind a `Mutex`, TTL-bounded (`CACHE_TTL_SECONDS`, default
  60s per `config.rs`), constructed fresh per-process in
  `run()` (`ropc.rs:523`) and never persisted or shared across processes.
  This is a **local optimization cache, not a source of truth or a rate
  limiter** — nothing in `authenticate()` (`ropc.rs:327-342`) treats a
  cache miss as anything other than "go do the real Keycloak exchange."
  Consequence for scaling: with N replicas behind a load balancer and no
  session affinity, a client's repeated requests can land on different
  pods and each pod maintains its own cache — worst case, every request
  round-trips to Keycloak instead of hitting a cache within
  `CACHE_TTL_SECONDS`. That's a Keycloak-load/latency cost, **not a
  correctness or security bug**: a cache miss just re-runs the exact same
  `grant_type=password` exchange the design already treats as the
  authoritative path. No sticky sessions are required for correctness;
  they'd only be an optional throughput optimization.
- **No rate limiting exists in this code at all** (confirmed by reading
  the whole file — no counter gating requests, no token bucket, nothing
  keyed by IP or username that rejects on a threshold). So there is
  nothing to duplicate-or-fragment across replicas the way a per-instance
  rate limiter would fragment: if rate limiting is added later (worth
  doing, since ROPC directly exposes a password-guessing oracle against
  Keycloak — see `docs/oidc-proxy-pairing.md`'s security posture section),
  it would need to be either centralized (Keycloak's own brute-force
  detection, which already sits behind this proxy) or explicitly
  designed as per-replica-and-that's-fine, not bolted on assuming
  single-instance the way the manifest was.
- **Every other piece of state is per-request**: `TokenExchanger`,
  `NexusClient`-equivalent (`reqwest::Client`), and the identity/claim
  config are all `Arc`-shared read-only config wrapped in `RopcState`
  (`ropc.rs:372-382`), constructed once at startup and never mutated
  per-request except through the cache already covered above.
  `requests_handled: AtomicU64` (`ropc.rs:381`) is explicitly a
  per-process observability counter, not shared or reconciled across
  replicas — fine for a liveness/sanity check, not meant to be
  aggregated as a global count.

**Conclusion: yes, `ropc-proxy` can be horizontally scaled safely.**
Nothing in it requires the replicas to coordinate, share state, or avoid
racing each other. The only cost of doing so is the cache-hit-rate
dilution above, which is a minor efficiency loss, not a safety concern.

### Recommended posture: `replicas: 3`, rolling updates, PDB, no leader election

This is the standard shape for any stateless, horizontally-scaled,
request-serving Kubernetes workload (`replicas: N`, `RollingUpdate` with
`maxSurge: 1, maxUnavailable: 0`, paired with a `PodDisruptionBudget`
setting `minAvailable`) — nothing about `ropc-proxy` needs a deployer to
deviate from that:

- **Kubernetes: `Deployment`, `replicas: 3`** (or whatever N matches
  expected concurrent CLI-auth volume — this is a throughput/availability
  tuning knob, not a correctness one, precisely because the service is
  stateless). A `Service` in front load-balances across pods; no session
  affinity required per the cache analysis above.
- **`RollingUpdate` with `maxSurge: 1, maxUnavailable: 0`** — safe here in
  a way it explicitly is *not* for `sync`, because there's no shared lock
  file for two overlapping ropc-proxy pods to contend on. Old and new
  pods serving traffic simultaneously during a rollout is the normal,
  correct case, not a race condition.
- **`PodDisruptionBudget` with `minAvailable: 1` (or 2, for a
  3-replica set, if a full node drain is expected while keeping most
  capacity up)** — this is the piece that's explicitly the *opposite*
  recommendation from `sync`, and for the same underlying reason
  inverted: with N>1 stateless replicas, a PDB usefully prevents a
  cluster upgrade or node drain from ever taking every replica down at
  once, which would turn planned maintenance into a live CLI-auth outage.
- **No leader election** — nothing here needs a single active instance
  or elected coordinator; every replica independently authenticates and
  proxies. Leader election would be actively wrong here, not just
  unnecessary — it would artificially serialize a workload that has no
  reason to be serialized.
- **Failure mode: pod crash mid-request.** A pod dying while
  `forward_to_nexus` (`ropc.rs:429`) is mid-stream (e.g. mid-`docker
  push` of a large layer, which this code explicitly streams rather than
  buffers — see the comment at `ropc.rs:459-462`) drops that one
  in-flight connection; the client sees a connection reset and the CLI
  tool's own retry logic (Docker/npm/pip all retry failed
  pushes/installs) re-attempts against a different, healthy replica via
  the Service's load balancing. No cross-request state is lost because
  there was never any to begin with — this is the direct payoff of the
  statelessness confirmed above. Set a `livenessProbe`/`readinessProbe`
  against the listener (`config.listen_addr`, default `0.0.0.0:8090`) so
  a wedged pod (e.g. stuck on a hung upstream Keycloak/Nexus connection)
  is cycled out of the Service endpoints rather than continuing to
  receive traffic it can't serve.
- **No local persistent volume needed** — nothing is written to disk, so
  a plain `emptyDir`-free pod spec is correct; there's no equivalent of
  `sync`'s state-file durability concern here at all.
- **Fixed: graceful shutdown on routine deploys.** `run()` (`ropc.rs`) now
  calls `axum::serve(listener, app).with_graceful_shutdown(shutdown_signal())`.
  `shutdown_signal()` races `tokio::signal::unix::signal(SignalKind::terminate())`
  against `tokio::signal::ctrl_c()` (the latter only for local dev — Ctrl-C is
  `SIGINT`, not `SIGTERM`) and resolves on whichever fires first. On
  `SIGTERM`, axum stops accepting new connections but lets in-flight ones —
  including a `docker push` still streaming through `forward_to_nexus`
  (`ropc.rs`) — finish before the process exits, instead of the previous
  behavior of ignoring the signal outright until
  `terminationGracePeriodSeconds` forced a hard kill mid-stream. Two log
  lines mark the transition for an operator watching a rollout: `"received
  SIGTERM, draining in-flight requests"` when the signal lands, and
  `"graceful drain complete, exiting"` once `axum::serve` actually returns —
  so a stalled drain (e.g. a client holding a connection open) is
  distinguishable from a clean exit rather than both looking like silence.
  `RopcState`'s fields (`TokenCache` behind a `Mutex`, the `AtomicU64`
  request counter, the `reqwest::Client`) are all in-memory or
  self-contained — none hold an external resource (open file, DB
  connection) that needs explicit flushing beyond what axum's drain already
  provides. `terminationGracePeriodSeconds` should be set comfortably above
  the slowest realistic `docker push` for the layers this Nexus instance
  serves; this doc can't responsibly recommend a specific number without
  observed push-duration data from this environment — pull p99 push
  duration from Nexus/ingress metrics before setting it, don't guess.

## 3. Summary table

| | `cambium sync` | `cambium ropc-proxy` |
|---|---|---|
| On the live request path? | No — periodic batch (`POLL_INTERVAL_SECONDS`, default 60s) | Yes — every CLI login/push/install |
| Local state | Manifest + `flock` lock file, both on disk (`lock.rs`, only called from `run_sync`) | In-memory `TokenCache` only, no disk I/O anywhere in `ropc.rs` |
| Safe to run >1 replica? | No — enforced by `lock.rs`; a second live instance corrupts the manifest | Yes — confirmed stateless per-request, no coordination needed |
| v1 replica count | 1 | ≥3 (throughput/availability tuning, not a safety floor) |
| Restart policy | `Always`, crash-loop through lock contention during rollout is expected and self-resolving | `Always`, standard rolling update |
| PodDisruptionBudget | No — nothing for it to protect at `replicas: 1`, would only block draining | Yes — `minAvailable` to keep the auth path up during node drain/upgrade |
| Leader election | No — `flock` + fast pod restart already gives single-writer semantics without a Kubernetes lease dependency | No — nothing to elect, every replica is independently authoritative per request |
| Blast radius of downtime | Delayed grants, extended stale-access window bounded by outage length + one poll interval | Synchronous, visible CLI-auth failures for the outage duration |
