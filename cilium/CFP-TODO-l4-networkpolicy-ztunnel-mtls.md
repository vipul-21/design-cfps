# CFP-TODO: L4 NetworkPolicy with Cilium + ztunnel mTLS

**SIG: SIG-ServiceMesh, SIG-Datapath**

**Begin Design Discussion:** 2026-06-16

**Cilium Release:** TBD

**Authors:** Vipul Singh <singhvipul@microsoft.com>

**Status:** Draft

## Summary

Support Cilium L4 `CiliumNetworkPolicy` enforcement on traffic that is also
mTLS-encrypted by ztunnel. Today, when a pod is enrolled into Cilium's ztunnel
mesh, the original workload L4 port is lost before Cilium's per-endpoint BPF
programs can see it, so L4 policy can only match the HBONE inbound port
(`15008`). This proposal preserves the destination workload port at every BPF
enforcement point by combining a small upstream ztunnel change (source side)
with a destination-local demux mechanism (Cilium datapath), without regressing
the existing HBONE/mTLS encryption guarantees. It affects the `cilium` and
`cilium-ztunnel` repos.

## Motivation

When a pod is enrolled into Cilium's ztunnel mesh, iptables rules inside the
pod's network namespace rewrite the destination port of every TCP packet:

| Direction | Rule | Effect |
|---|---|---|
| Pod egress (`CILIUM_OUTPUT`) | `REDIRECT --to-ports 15001` | Original dport replaced with `15001` (ztunnel outbound) |
| Pod ingress (`CILIUM_PREROUTING`) | `REDIRECT --to-ports 15006` | Original dport replaced with `15006` (ztunnel inbound plaintext), unless dport is already `15008` (HBONE inbound) |

Because `REDIRECT` is a `DNAT` and runs in the pod's netns before the packet
ever reaches the host-side veth, **Cilium's per-endpoint BPF programs
(`cil_from_container`, `cil_to_container`) never see the original L4 5-tuple**.
Consequently the documented limitation holds:

> Ztunnel interferes with Cilium network policy as traffic is encrypted before
> it leaves the pod, meaning L4 policies won't work except for directly
> targeting the ztunnel HBONE port (15008).

The `15008` in that limitation is not arbitrary: for mesh (HBONE/mTLS) traffic
the original workload port is lost a second time, in ztunnel itself. After the
in-pod `REDIRECT` hands the app's packet to ztunnel, ztunnel **terminates** it
and opens a *new* TCP session between ztunnels carrying HTTP/2 CONNECT (HBONE).
That new session reuses the same IP-header addresses but has a kernel-selected
source port and a destination port of `15008`, the HBONE inbound port — built as
`(workload_ip, self.hbone_port)`. So even setting the iptables rewrite aside,
the 5-tuple Cilium sees on the wire carries dport `15008`, not the workload port
— which is why L4 policy can only match `15008` today.

The other documented limitations to keep in mind throughout this design:

1. Traffic flows only when **both** endpoints are enrolled (no enrolled ↔ non-enrolled).
2. Enrollment is **namespace-label only today**: no per-pod opt-in/opt-out yet.
3. TCP only.
4. iptables required in the pod's kernel.
5. L4 policy broken (the subject of this document).

## Goals

* Allow `CiliumNetworkPolicy` L4 rules (ports/protocols on identity) to be
  enforced on flows that traverse ztunnel.
* Preserve the L4 fields policy evaluates — in particular the destination
  **workload (target) port** — at every BPF enforcement point, instead of
  losing them to `15008`. For service-addressed traffic the preserved dport is
  the resolved backend target port (what the pod listens on and what ingress
  policy is keyed on), not the service frontend port.
* Do not regress the existing mTLS guarantees (HBONE encryption between meshed
  endpoints, SPIRE-issued identities).
* Surface, but not necessarily solve, the other four limitations. This document
  focuses on limitation #5 (L4 policy). The remaining four are acknowledged but
  not addressed by the design that follows.

## Non-Goals

* L7 policy on meshed (HBONE) flows. Cilium's Envoy is host-networked, so it
  only ever sees what crosses the veth — which for a meshed flow is HBONE
  ciphertext; the plaintext exists only inside the pod netns, where ztunnel
  hands it to the workload. Preserving the dport is a precondition for L7 but
  does not by itself make L7 work, for plain HTTP or for HTTPS. See Future
  Milestones for what each would additionally require.
* UDP / non-TCP support. (ztunnel itself is TCP-only today.)
* Removing iptables entirely. (May be a side benefit of some options, but not
  required.)

## Proposal

### Overview

What looks like a single task is really **two enforcement points**:
source-side egress (§Source-side egress) and destination-side ingress
(§Destination-side ingress).

* The **source-side** fix is small and lives in **ztunnel**, not Cilium: make
  ztunnel's outbound HBONE connection target the original
  `(workload_ip, workload_port)` instead of `(workload_ip, 15008)`, so the
  workload port survives on the wire.
* The **destination-side** fix lives in the **Cilium datapath**: since the
  outer dport now equals the workload port for both HBONE and plaintext flows,
  the destination needs a new way to demux "redirect to `ztunnel:15008` for
  HBONE decryption" from "deliver directly to the workload". This is done with
  destination-local DSCP stamping plus a new in-pod iptables match.

### Source-side egress

Today, two things together hide the original dport from `cil_from_container`:

1. **iptables DNAT in the pod netns**: `nat OUTPUT … REDIRECT --to-ports 15001`
   rewrites the dport to `15001` before the packet leaves the pod netns.
2. **Local socket termination by ztunnel**: ztunnel accepts the redirected TCP,
   reads the original `(dst_ip, dport)` via `getsockopt(SO_ORIGINAL_DST)`, then
   opens a **new** outbound HBONE TCP connection built as
   `(selected_workload_ip, self.hbone_port)` where `self.hbone_port` is `15008`.
   The packet that reaches `cil_from_container` is *ztunnel's outbound HBONE*,
   not the app's original socket — so the dport on the wire is `15008`.

**The fix is small and lives in ztunnel itself, not in Cilium.** Upstream
[istio/ztunnel#1665](https://github.com/istio/ztunnel/pull/1665) ("Add
transparent network policy support for HBONE connections") flips the outbound
HBONE socket to target the original `(workload_ip, workload_port)` instead of
`(workload_ip, 15008)`, gated on an env flag `TRANSPARENT_NETWORK_POLICIES`
(default `false` for backcompat). The patch is **one substantive line** — the
`InboundProtocol::HBONE` arm of the `actual_destination` match, swapping
`self.hbone_port` for the workload port (the inner H2 CONNECT authority,
`hbone_target_destination`, already carries the real `workload_socket_addr()`
and is unchanged). Cilium runs an upstream ztunnel binary (it carries no ztunnel
proxy code of its own), so adopting this is a matter of enabling the flag once
it is merged — or building from a fork that is always-on.

**5-tuple survival on the wire leaving pod A's lxc veth (with the flag on):**

| Field | App intent | At `cil_from_container` | L4 policy needs it? |
|---|---|---|---|
| src_ip | pod A | pod A (same netns) | ✓ used for identity lookup |
| src_port | app ephemeral | ztunnel ephemeral | not used by L4 policy |
| dst_ip | pod B | pod B | ✓ |
| **dst_port** | **8080** | **8080** | **✓ the field that matters** |
| proto | TCP | TCP | ✓ |

Cilium L4 NetworkPolicy is **(src identity, dst_port, protocol)** — every field
it evaluates survives.

**Service vs. workload port.** The `8080` above is the destination **workload
(target) port**. For service-addressed traffic ztunnel resolves the service port
to the backend target port, so that target port — not the service frontend port
— is what lands on the wire and what L4 policy sees. This is the port the
destination pod listens on and where Cilium already enforces destination ingress
policy, so it is the right field for enforcement; it just is not literally the
app's `connect()` port when that was a ClusterIP service port.

**Why pooling does not break this.** HBONE H2 pooling could in principle
collapse two different upstream ports onto one outer TCP. The ztunnel pool key
is:

```rust
struct WorkloadKey { src_id, dst_id, dst: SocketAddr, src: IpAddr }
```

`dst` is a `SocketAddr` (ip **+ port**), and with the flag on
`req.actual_destination` becomes `(workload_ip, workload_port)`. Different
upstream port → different pool key → different outer TCP. No pooling-induced
port collision for the source-side case.

### Destination-side ingress

With the source-side fix in place, the outer wire dport equals the inner
workload port (e.g. `8080`). The destination-side problem collapses to two
narrower questions:

1. **Demux**: how does the destination kernel know "redirect this packet to
   `ztunnel:15008` for HBONE decryption" vs "deliver directly to the workload"?
   Both flows look identical on the outer 5-tuple `(src-pod, dst-pod, 8080,
   TCP)`. The proposed mechanism is detailed below.
2. **Trust** (assumption): we assume source ztunnel is trusted — consistent with
   today's design, since it runs in-pod and already handles the workload's
   plaintext. Under that assumption, `cil_to_container` reading and enforcing on
   the outer dport (the same code path used for plaintext today) is sufficient.
   The assumption is load-bearing (see Impacts).

**Mixed (enrolled ↔ non-enrolled) traffic is untouched.** The selector fires
only when *both* peers are meshed, so mixed flows are never stamped and fall
through to the existing plaintext `:15006` redirect. Such traffic is plaintext
anyway (ztunnel passthrough, not HBONE), so its real dport is already visible to
`cil_from_container` / `cil_to_container` and L4 policy works without any of this
machinery. Enabling enrolled ↔ non-enrolled flow is limitation #1 (out of scope
here); if it lands, this L4 design needs no change.

#### Demux mechanism: destination-side DSCP stamping + in-pod iptables match

A two-step hand-off between host-side BPF and in-pod iptables. It mirrors the
pattern from [istio/istio#58285](https://github.com/istio/istio/pull/58285)
(which has Calico Felix stamp DSCP from an ipset), but uses Cilium-native
primitives.

**Prerequisite — a meshed-flow signal in the datapath.** The mechanism needs an
in-datapath test that answers, for each ingress packet (or flow): "is this an
HBONE flow between two meshed peers that needs to be demuxed to ztunnel?". The
*signal itself* — what bit is read, where it lives, how it is populated — is the
**selector** question (see Impacts / Key Questions). This mechanism only requires
that *some* O(1) datapath test exists.

**Step 1 — stamp DSCP locally on the destination node.** When the selector test
returns "yes" for an arriving packet (or for the flow it belongs to), the IP ToS
DSCP field is set to `0x17` before the packet enters the pod netns. The marker
is destination-local and never on the wire between nodes, so the value is **not**
chosen for cross-mesh interop — it is purely a node-local demux tag. `0x17`
simply reuses the value istio/istio#58285 reserves for the same
destination-demux pattern, keeping the two designs recognizably aligned. The
stamp happens **on the destination node only**, after any cross-network
traversal — so DSCP fragility under VXLAN/Geneve encap, cloud SDN, or NIC
offloads is irrelevant. The marker only needs to survive the veth crossing into
the pod netns (which it does; veth does not strip IP ToS).

**Step 2 — match DSCP in pod-netns iptables, redirect to `ztunnel:15008`.** A
new rule is prepended to `CILIUM_PREROUTING`:

```
-A CILIUM_PREROUTING ! -d 127.0.0.1/32 -p tcp \
   -m dscp --dscp 0x17 \
   -m mark ! --mark 0x539/0xfff \
   -j REDIRECT --to-ports 15008
```

The existing rule (`REDIRECT --to-ports 15006`) is preserved as a fallback for
plaintext traffic. The DSCP rule must run **first** — without the source-side
fix the existing rule's `! --dport 15008` carve-out caught HBONE traffic, but
with the source-side fix the outer dport is the workload port and that carve-out
never fires, so without the new rule HBONE traffic would be mis-redirected to
the plaintext listener.

**Cost.** Adds one iptables rule (worsens limitation #4 marginally, since the
long-term goal is to drop iptables entirely). Adds one selector check per
ingress packet (or per flow) plus one ToS-byte rewrite on the destination side.

### Data paths

#### Today's data path (pre-source-fix, for reference)

```
Source pod netns                              Destination pod netns

 app:5xxxx ──tcp──► svc:8080

       │  CILIUM_OUTPUT (iptables REDIRECT)
       │  DNAT dport 8080 → 15001
       ▼
 ztunnel:15001 (outbound listener)
       │  HBONE encrypt, set sport, dport=15008
       ▼
   pod-veth (egress)
       │
   cil_from_container ◄── HERE: dport already 15001 was rewritten;
       │                  then ztunnel re-emitted with dport=15008.
       │                  Cannot enforce L4 on app's original 8080.
       ▼
   (overlay/native routing across nodes)
                                              ▼ host-veth (ingress)
                                              cil_to_container
                                                 │  sees dport=15008
                                                 │  cannot see inner 8080
                                                 ▼
                                              pod netns
                                              CILIUM_PREROUTING:
                                              dport=15008 → bypass redirect
                                                 ▼
                                              ztunnel:15008 (HBONE listener)
                                                 │  decrypt, proxy over lo
                                                 ▼
                                              app listener on 0.0.0.0:8080
                                              (no Cilium BPF on this loopback hop)
```

Outer wire 5-tuple between the two `pod-veth`s: `(src=pod-A, dst=pod-B,
src_port=ztunnel-ephemeral, dst_port=15008, proto=TCP)`. The inner workload
port (`8080`) is buried inside the encrypted HBONE payload — that is what makes
destination-side L4 enforcement unworkable today.

#### Proposed data path (with the source-side fix in place)

```
Source pod netns                              Destination pod netns

 app:5xxxx ──tcp──► svc:8080

       │  CILIUM_OUTPUT (iptables REDIRECT)   ◄── unchanged from today
       │  DNAT dport 8080 → 15001
       ▼
 ztunnel:15001 (outbound listener)
       │  SO_ORIGINAL_DST → (pod-B, 8080)
       │  open new HBONE outbound to
       │  (pod-B, 8080) ◄── source-side change: was (pod-B, 15008)
       ▼
   pod-veth (egress)
       │
   cil_from_container ◄── HERE: dport on wire is now 8080.
       │                  L4 policy on (src_identity, 8080, TCP)
       │                  evaluates correctly.
       ▼
   (overlay/native routing across nodes)
                                              ▼ host-veth (ingress)
                                              cil_to_container
                                                 │  sees dport=8080
                                                 │  enforces ingress L4 policy
                                                 │  on (src_identity, 8080, TCP)
                                                 │
                                                 │  Demux: ipcache is_meshed(src,dst) →
                                                 │  BPF stamps IP ToS DSCP=0x17 here,
                                                 │  before the packet enters
                                                 │  the pod netns via veth.
                                                 ▼
                                              pod netns
                                              CILIUM_PREROUTING matches
                                              -m dscp --dscp 0x17 →
                                              REDIRECT --to-ports 15008
                                                 ▼
                                              ztunnel:15008 (HBONE listener)
                                                 │  decrypt, proxy over lo
                                                 ▼
                                              app listener on 0.0.0.0:8080
```

Outer wire 5-tuple between the two `pod-veth`s: `(src=pod-A, dst=pod-B,
src_port=ztunnel-ephemeral, dst_port=8080, proto=TCP)`. The destination HBONE
listener is still on `15008` — that is an internal port inside the destination
pod netns and is *not* on the wire between nodes. DSCP=`0x17` is stamped
*locally* on the destination node and only traverses the veth.

Key shifts from today:

* Outer wire `dst_port` = inner workload port (`8080`), not `15008`.
* `cil_from_container` evaluates L4 on the workload port directly.
* `cil_to_container` evaluates L4 on the workload port directly.
* The destination `CILIUM_PREROUTING` "bypass redirect if dport=15008" carve-out
  never fires for source-fixed flows; the new DSCP demux rule replaces it. This
  is the one new piece of in-pod plumbing the transition introduces.

## Impacts / Key Questions

### Key Question: Selector — which packets get the DSCP stamp

The demux needs an in-datapath answer to: "for this packet (or this flow),
should the DSCP marker be applied?". Two concrete options; both assume the
*stamp itself* is applied destination-locally.

#### Option I — Per-IP (per-endpoint) ipcache `is_meshed` flag (Recommended)

Add a new `FlagMeshed` to `RemoteEndpointInfoFlags` (a `uint8` enum declared as
`1 << iota`, with **4 of 8 bits already free** today; no new map / no new
struct). The bit is stored **per IP**, not per packet: ipcache is an LPM map
keyed by IP prefix, so the flag is a property of each endpoint IP that the
datapath merely *reads* once per packet — two lookups (`src`, `dst`) plus
`is_meshed(src) && is_meshed(dst)`. Populate it from whatever signal drives mesh
enrolment; today that is the `io.cilium/mtls-enabled` namespace label (the same
source of truth as ztunnel namespace enrolment).

##### Pros

* No new map; no new control plane. Reuses an already-shared, already-broadcast
  datapath structure — every BPF program already consults ipcache for L3 /
  identity enforcement, so the marginal cost of one extra flag-read is
  essentially zero.
* `Flags` is already a field of the synced `RemoteEndpointInfo` value, so
  `FlagMeshed` is one free bit — no new key, entry, or struct — and it adds **no
  sync churn**: ipcache propagation is change-driven, not flow-driven. The bit
  changes only when a namespace's enrolment label is toggled (a rare admin
  event); pod create/delete already upserts those entries regardless of the
  flag, so it piggybacks.

##### Cons

* **Transient demux mismatch (two independent signals).** Demux depends on two
  signals propagated by *different* pipelines that can disagree during
  transitions: the destination's ipcache `is_meshed` (gates stamping) and the
  source ztunnel's xDS view (decides whether the flow is actually HBONE or
  plaintext passthrough). Either skew can break the first packets of a flow
  until both converge (fresh enrolment / rollout, or a source ztunnel restart /
  xDS resync). Steady state is always correct (meshed↔meshed is always HBONE);
  it can only misfire in transient windows and only for a flow's first packets.
  It is a possibility, not a certainty — whether any packets land in the skew
  depends on the exact relative timing of the two pipelines. This is inherent to
  the transparent-dport approach the design adopts (istio/ztunnel#1665 +
  istio/istio#58285): Istio likewise demuxes from a per-endpoint "meshed-pod"
  membership signal (a Felix ipset) decoupled from ztunnel's own encryption
  decision, so it carries the same class of mismatch.
* **Verification owed.** Confirm `RemoteEndpointInfo` is stable enough to extend
  without rolling all BPF programs simultaneously; the struct's `align:` tags
  hint at on-wire format constraints that may require careful migration.
* **Optimization (deferred).** The per-packet flag-read can be amortized to one
  read per flow by caching the `is_meshed` result in a free `ct_entry` bit (the
  existing `proxy_redirect:1` flag is the in-tree precedent): do the ipcache
  lookup once on SYN, then read the CT bit on subsequent packets. Functionally
  identical — only the lookup-cost profile differs — so it is deferred until
  profiling shows the per-packet read is a hot path.

#### Option II — Per-flow 5-tuple BPF map, populated by cross-node signal

New BPF map keyed by the existing `struct ipv4_ct_tuple` (`daddr / saddr /
dport / sport / nexthdr`), value a single bit. Population: the **source-side**
Cilium agent observes outbound HBONE flows (instrumented in `cil_from_container`
via a perf event, or watched in userspace) and pushes the 5-tuple to the
destination node via the kvstore / clustermesh sync paths Cilium already uses
for ipcache broadcasting.

##### Pros

* Per-flow precision independent of namespace labels — eliminates the
  propagation race (the signal is the flow itself, not a label that must spread
  first). Allows per-pod or per-flow exclusions without touching namespace
  membership.
* Authoritative: only flows that source-side actually observed get stamped, so a
  compromised or buggy ipcache entry cannot accidentally enable demux on
  plaintext traffic.

##### Cons

* **Substantial new control plane** (new push path, new reconciliation, new map
  churn) at a granularity Cilium has **never synced** — everything Cilium
  broadcasts cross-node is endpoint / identity / node / service grained.
* **The scale is the killer:** the whole cluster's ipcache is capped at **512K
  entries**, whereas a *single node's* flow table already defaults to **~786K**
  (524K TCP + 262K non-TCP) and dynamically sizes into the **millions** — one
  node's flows can exceed the entire cluster's ipcache, × every node, churning
  at connection setup/teardown rates.
* **Latency-sensitive:** the first packets of a flow can reach the destination
  *before* the cross-node signal arrives — needs a fallback (most likely Option
  I as the conservative default), which effectively means implementing Option I
  anyway.
* **Verification owed.** Whether Cilium's existing kvstore / clustermesh push
  channel has the right shape for per-flow events (it was designed for long-lived
  identity / endpoint metadata, not per-connection bursts).

**Recommendation.** Option I is the smallest change and reuses Cilium's existing
consistency model. Option II sidesteps the transient-mismatch con but at a scale
and control-plane cost that is likely prohibitive.

### Key Question: DSCP stamping mechanism

How the IP ToS byte is actually written by the time the packet enters the pod
netns (the attach point, `cil_to_container` vs. earlier in the destination-host
pipeline, is a sub-question of the BPF mechanism).

#### Option 1 — BPF rewrite of the IPv4 ToS / IPv6 traffic-class byte (Recommended)

A new Cilium BPF helper does an ipcache lookup on `(src_ip, dst_ip)`, computes
`new_tos = (ip4->tos & 0x03) | (0x17 << 2)` (preserving the ECN bits in the low
2 bits, writing DSCP=`0x17` in the high 6), writes the byte, and updates the IP
header checksum via the existing `ipv4_csum_update_by_value` wrapper. The
pattern mirrors `ipv4_dec_ttl` — the only in-tree precedent for rewriting a
single IP-header byte.

##### Pros

* No new iptables / ipset; pure BPF, aligned with the long-term goal of dropping
  iptables.
* Cost is one ipcache lookup plus one checksum-incremental update per packet.

##### Cons

* The attach point must run on **every** ingress-to-pod datapath, not just
  `cil_to_container` — that program is attached to the lxc device **only when
  endpoint routes are enabled**. On the default (non-endpoint-routes) datapath,
  ingress policy runs via the `cil_lxc_policy` / `tail_ipv4_to_endpoint`
  to-endpoint tail call and `cil_to_container` never runs. The stamp must
  therefore live in the common local-delivery / to-endpoint path so the DSCP
  byte is set before the packet enters the pod netns on all of: same-node
  pod-to-pod, cross-node native routing, and VXLAN/Geneve. Pinning the exact
  program(s) per datapath mode is an implementation item.

#### Option 2 — iptables `-j DSCP --set-dscp 0x17` on the destination host, matched against an ipset

The agent (or operator) keeps a host-side ipset whose membership tracks the set
of meshed-pod IPs (a subset of what's in the ipcache). A host-PREROUTING
iptables rule matches `src,dst ∈ ipset` and writes the DSCP byte. This is the
istio/istio#58285 / Calico-Felix design transplanted to Cilium.

##### Pros

* No new BPF code.

##### Cons

* **Adds a host-side iptables rule and a parallel ipset** — both worsen
  limitation #4 (we want to *drop* iptables long-term) and require consistency
  plumbing between the ipset and the ipcache under pod churn.
* Only attractive if the BPF helper proves infeasible for some reason not yet
  identified.

### Impact: Trust assumption on source ztunnel

The design assumes source ztunnel is trusted. The outer dport is *asserted* by
source ztunnel, so a compromised source ztunnel could open outer TCP to `:8080`
while tunnelling an H2 CONNECT for `:5432` inside. Hardening that case is out of
scope (Cilium owns L4 enforcement, not ztunnel), but the assumption is
load-bearing and should be called out explicitly to maintainers.

### Key Question: Migration path

How do we roll out without breaking existing namespace-enrolled workloads?
Feature-flag + parallel iptables for one release, then cut over? What is the
rollback story for in-flight conntrack entries?

### Key Question: ipcache churn at scale

Option I argues the `FlagMeshed` bit adds no steady-state sync churn — it rides
the existing change-driven ipcache propagation and only flips when a namespace's
enrolment label is toggled (a one-time burst over that namespace's IPs). Confirm
this holds at scale: does toggling enrolment on a large namespace, or high
namespace / pod churn under clustermesh fan-out, produce a measurable ipcache
re-sync spike worth rate-limiting?

## Future Milestones

### Replace in-pod iptables with a BPF redirect (addresses limitation #4)

The source-side fix leaves the iptables `REDIRECT --to-ports 15001` rule in
place — it works, and the dport-loss problem it caused is no longer a blocker
once the upstream ztunnel patch lands. A natural follow-up, independent of L4
policy, is to replace that iptables rule with a **BPF-based redirect** in the pod
netns to address the "no-iptables environments" limitation. Two plausible BPF
entry points:

* **cgroup `connect4`/`connect6`** attached to the pod's cgroup, rewriting the
  destination to the local ztunnel listener at `connect()` time.
* **tc-egress** on the pod-side of the veth, redirecting matched packets to
  ztunnel's socket via `bpf_sk_assign` / sockmap.

Both are larger ztunnel-side changes than the source-side fix (ztunnel currently
relies on `getsockopt(SO_ORIGINAL_DST)` from netfilter conntrack; a BPF redirect
does not populate that, so an explicit metadata channel from BPF to ztunnel is
required). iptables TPROXY is **not** a candidate for the egress side. This work
is sequenced *after* the source-side fix, not as a prerequisite to it.

### L7 policy on meshed flows (plaintext HTTP, and HTTPS MITM)

Preserving the workload dport is a *precondition* for L7 policy — an L7 rule is
nested under `toPorts`, so today it could only be written against `15008` — but
it is not sufficient. Two independent blockers stack, and they should not be
conflated:

**1. Placement (applies to plain HTTP too).** Cilium enforces L7 by redirecting
the flow to Envoy, which runs host-networked (`hostNetwork: true` in the
`cilium-envoy` DaemonSet), so Envoy only sees what crosses the veth. For a
meshed flow that is HBONE ciphertext: ztunnel runs *inside* the pod netns and,
on ingress, terminates the H2 CONNECT and connects to the workload address from
within that same netns — so the decrypted plaintext never crosses the veth.
Cilium's existing HTTP L7 policy therefore does not "just work" on meshed flows
even for plain HTTP; the obstacle is *where* the plaintext exists, not whether
it is parseable. Three shapes of fix, in rough order of cost:

* **Envoy waypoint** — route the flow through an ambient-style waypoint that
  terminates HBONE, applies L7, then re-originates. Most aligned with the
  ambient model; largest new moving part in the path.
* **ztunnel co-operation** — have destination ztunnel hand the decrypted stream
  to Cilium's Envoy before delivering it to the workload. Smaller topology
  change, but requires a real upstream ztunnel API.
* **In-netns L7 enforcement** — move the L7 hook into the pod netns where the
  plaintext already is. Avoids a hairpin but duplicates proxy plumbing per pod.

**2. TLS interception (applies only when the app itself speaks TLS).** Once
placement is solved, plain HTTP is parseable directly — that part is close to
out-of-the-box. If the workload speaks HTTPS, the L7 hook sees app-level TLS
*inside* the HBONE tunnel and must MITM it to parse. Cilium already has the
primitive: TLS visibility via `terminatingTLS` / `originatingTLS` on a `toPorts`
rule, which redirects the connection to Envoy to terminate and re-originate it.
The cost is the standard MITM cost rather than anything new — an internal CA
whose certificate every client workload must trust, plus a per-destination
signed certificate — with the wrinkle that it adds a TLS termination and
re-origination to a flow ztunnel has already terminated once. Whether that is
acceptable for a mesh whose premise is end-to-end mTLS is a policy question, not
a datapath one.

Net: plain HTTP needs (1); HTTPS needs (1) and (2). Both are sequenced after
this CFP.

### Deferred: cache `is_meshed` in a CT bit

Amortize Option I's per-packet ipcache flag-read to one read per flow by caching
the result in a free `ct_entry` bit, deferred until profiling shows the
per-packet read is a hot path. (Owed: confirm the CT lookup precedes the demux
attach point on the same-node, native-routing, and VXLAN/Geneve paths.)

### The other four documented limitations

This CFP addresses only limitation #5 (L4 policy). The remaining four —
enrolled ↔ non-enrolled traffic (#1), per-pod opt-in/opt-out enrolment (#2),
TCP-only (#3), and iptables-required (#4) — are acknowledged but out of scope
and can be addressed independently.

## References

* [istio/ztunnel#1665](https://github.com/istio/ztunnel/pull/1665) — "Add
  transparent network policy support for HBONE connections" (source-side fix).
* [istio/istio#58285](https://github.com/istio/istio/pull/58285) — DSCP
  destination-demux pattern (Calico Felix ipset), the alignment for DSCP=`0x17`.
* `pkg/ztunnel/iptables/inpod.go` — current iptables REDIRECT rules.
* `pkg/ztunnel/table/enrolled_namespaces.go` — `io.cilium/mtls-enabled`
  namespace-label gate.
* `pkg/ztunnel/reconciler/reconciler.go` — per-namespace endpoint enrollment;
  no per-pod opt-out exists today.
* `Documentation/security/network/encryption-ztunnel.rst` — user-facing
  documentation, including the five limitations cited above.
* `bpf/bpf_lxc.c` — `cil_from_container` (egress) and `cil_to_container`
  (ingress) entry points; tail-call chain through `tail_ipv4_policy` /
  `tail_ipv4_to_endpoint`.
* `install/kubernetes/cilium/templates/cilium-envoy/daemonset.yaml` —
  `hostNetwork: true`; why the L7 proxy cannot see plaintext that stays inside
  the pod netns.
* `Documentation/security/tls-visibility.rst` — `terminatingTLS` /
  `originatingTLS`, Cilium's existing TLS-interception (MITM) primitive.
* ztunnel `src/proxy/inbound.rs`, `src/inpod/` — inbound HBONE termination
  connects to the workload address from inside the pod's network namespace.
