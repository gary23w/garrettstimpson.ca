---
layout: post
title: "A Go Mirai Variant That Hides Behind cpufreqd"
date: 2026-06-02
categories: [malware, analysis]
tags: [mirai, golang, linux, ddos, systemd-persistence, mitre-attack]
excerpt: "A fresh Go DDoS bot showed up on Bazaar masquerading as a Linux power daemon, floods with fasthttp, and forgot to strip its symbols."
---

## What showed up

On June 1st a reporter going by NullBlue67 dropped two ELF binaries onto MalwareBazaar, both first seen around 16:59 UTC. One is built for x86_64, the other for ARM aarch64. The arm64 file is named `c2c_agent_arm64.elf`, weighs in at about 9.1 MB, and carries the SHA256 `5bf67d64e94a8ed6b81a0855fee52626eb0f4caf1772518fc2404883030451c2`. Bazaar tags it Mirai, with six vendor detections and a `new-family` label. Sample page is here for reference: [https://bazaar.abuse.ch/sample/5bf67d64e94a8ed6b81a0855fee52626eb0f4caf1772518fc2404883030451c2/](https://bazaar.abuse.ch/sample/5bf67d64e94a8ed6b81a0855fee52626eb0f4caf1772518fc2404883030451c2/). To be clear, that hash is for identification only, not a download.

What caught my eye is the rest of the tag set: `go`, `http-flood`, `cpufreqd-disguise`. This is not the usual C-compiled Mirai droplet that a thousand IoT cameras already host. It is a Go program, and the honeypot operator left a comment that fills in the gaps nicely. Captured over SSH, origin Spain, internal module name `c2c/cmd/agent`, HTTP flood implemented with the `fasthttp` library, and persistence through a systemd unit pretending to be `cpufreqd`. Go 1.26.3. Debug info not stripped. That last detail is going to matter.

## What makes it work

Start with how it stays alive. The bot installs itself as a systemd service, and it picks the name `cpufreqd` on purpose. `cpufreqd` is a real, old Linux daemon that adjusts CPU frequency based on policy. Most admins have heard the name, few have it actually installed, and almost nobody audits it. So a unit file sitting at `/etc/systemd/system/cpufreqd.service` or under `/usr/lib/systemd/system/` reads as boring infrastructure. That is the whole trick. MITRE files this under T1543.002 (Create or Modify System Process: Systemd Service) combined with T1036.005 (Masquerading: Match Legitimate Name or Location). Systemd executes whatever `ExecStart` points at on every boot, runs it as root if the unit lives in the system directories, and restarts it for you if it dies. The attacker gets free reliability engineering from the OS.

Getting on the box in the first place was nothing clever. It landed on an SSH honeypot, which means credential brute forcing or a reused password, T1110. Commodity entry, commodity foothold. The interesting part is what runs after.

The payload is a DDoS agent. It dials home to its C2 over a web protocol (T1071.001) and waits for flood commands. The honeypot operator named two of them, `directhttp` and `betterhttp`, and both ride on `fasthttp`. The choice of library is deliberate. Go's standard `net/http` is fine, but `fasthttp` is built to minimize allocations and reuse connection objects, so a single modest VPS can push request volumes that hurt. Layer 7 floods like this fall under T1498 (Network Denial of Service), and they are nasty precisely because each request looks like a real request. Cloudflare and others have been reporting that the bulk of HTTP-layer attacks in 2025 were short and intense, most finishing inside ten minutes, long enough to lock users out and fail transactions while staying under the radar of slow human response.

Why Go at all? Cross compilation. One `GOOS=linux GOARCH=arm64 go build` and you have an arm64 binary; flip the arch and you have x86_64. That is exactly why we got two architectures in the same upload. Mirai has always wanted to be everywhere, and Go makes "everywhere" a build flag instead of a toolchain headache. The Darkreading crowd noticed this shift a while back when Mirai-lineage actors started rewriting controllers and then bots in Go for reach.

Now the part that made me laugh. The author did not strip the binary. In a Go ELF, the function metadata lives in the `gopclntab` section whether or not you strip the regular symbol table, so even a stripped Go binary leaks structure. This one did not even bother. The `c2c/cmd/agent` module path is right there. Tools like Radare2 or the go-re toolkit parse `gopclntab` automatically on Linux Go binaries and hand you function names, so an analyst opens this and gets a near-source-level map of the command handlers. For a botnet author that is a real OPSEC miss. It tells me this is either early development, a hobbyist, or someone who simply does not care because the bot is disposable. Given the `new-family` tag, my money is on early development.

## Local educational sample

Here is the persistence idea, written in Go, stripped of anything harmful. It writes a unit named `cpufreqd-demo` whose `ExecStart` is `/bin/true`, so it does nothing. The point is to show the file layout and the systemd handoff, not to ship a payload.

```go
// EDUCATIONAL SAMPLE - demonstrates systemd service masquerade (T1543.002 / T1036.005)
// This does NOT contain any malicious payload
// For research and defensive awareness only
package main

import (
	"os"
	"os/exec"
)

const unit = `[Unit]
Description=CPU Frequency Daemon (demo, harmless)

[Service]
Type=simple
ExecStart=/bin/true
Restart=always

[Install]
WantedBy=multi-user.target
`

func main() {
	// Real malware writes to /etc/systemd/system to blend with system services.
	// We write a clearly named demo unit so nobody confuses this with the real thing.
	path := "/etc/systemd/system/cpufreqd-demo.service"
	if err := os.WriteFile(path, []byte(unit), 0644); err != nil {
		panic(err)
	}
	// systemd reads the unit, enables boot persistence, and starts it.
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "--now", "cpufreqd-demo.service").Run()
	// Cleanup: systemctl disable --now cpufreqd-demo && rm the unit file.
}
```

And the flood primitive, reduced to a single honest request so you can see the `fasthttp` shape without the loop that turns it into an attack.

```go
// EDUCATIONAL SAMPLE - demonstrates the fasthttp request primitive only
// No flood loop, no concurrency, no target list. One request to one host.
// For research and defensive awareness only
package main

import (
	"fmt"

	"github.com/valyala/fasthttp"
)

func main() {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://example.com/")
	req.Header.SetMethod("GET")

	if err := fasthttp.Do(req, resp); err != nil {
		panic(err)
	}
	fmt.Println("status:", resp.StatusCode())
}
```

The weaponized version wraps that primitive in a goroutine pool driven by C2 commands. The defensive lesson is that the request itself is indistinguishable from legitimate traffic. You defend against the volume and the source, not the packet.

## Detection and defense

The sample lit up twenty YARA rules on Bazaar, most of them generic Go detectors like `DetectGoMethodSignatures`, `Suspicious_Golang_Binary`, and CYFARE's `TH_Generic_MassHunt_Linux_Malware_2026`. Generic is fine here. A small rule keyed to the masquerade plus the module path catches this specific family:

```yara
rule Go_Mirai_cpufreqd_disguise
{
    meta:
        author = "Garrett Stimpson"
        description = "Go DDoS agent masquerading as cpufreqd systemd service"
        reference = "MalwareBazaar 5bf67d64...30451c2"
    strings:
        $mod  = "c2c/cmd/agent"
        $svc  = "cpufreqd"
        $cmd1 = "directhttp"
        $cmd2 = "betterhttp"
        $go   = "go1.26"
    condition:
        uint32(0) == 0x464c457f and $mod and $svc and ($cmd1 or $cmd2) and $go
}
```

On the host, Sysmon for Linux is your friend. Event ID 1 (process creation) catches the agent spawning and, just as useful, catches `systemctl enable` and `systemctl daemon-reload` running with a parent that is not a package manager or an admin shell. Event ID 3 (network connection) catches the outbound C2 dial and the flood traffic leaving the box. Pair those two and you have the full story from install to attack.

Watch the systemd directories directly. An auditd watch on `/etc/systemd/system/` and `/usr/lib/systemd/system/` flags new `.service` files as they are written. Then verify ownership: a real distro daemon belongs to a package, so `dpkg -S /etc/systemd/system/cpufreqd.service` or `rpm -qf` returning "no package owns" on something claiming to be `cpufreqd` is your tell. There are public Sigma rules for systemd service creation under the auditd category that map cleanly onto this. For mitigation, the boring advice is the advice that works: kill password SSH and use keys, put fail2ban or equivalent in front of the daemon, and filter egress so a compromised host cannot reach arbitrary C2 or pour L7 floods outward. The bot needs the network to matter. Take the network away.

This one is not sophisticated. It is a clean example of where commodity Linux malware is heading, though: Go for portability, a legitimate service name for cover, and a fast HTTP library doing the loud work. The unstripped symbols are a gift. Read them while they last.
