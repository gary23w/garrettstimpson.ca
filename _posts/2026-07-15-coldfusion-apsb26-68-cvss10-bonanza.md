---
layout: post
title: "ColdFusion APSB26-68: Seven CVSS 10.0 Flaws and a Two-Hour Exploitation Window"
date: 2026-07-15
categories: [exploits, web, vuln-research]
tags: [CVE-2026-48282, CVE-2026-48276, CVE-2026-48277, CVE-2026-48281, CVE-2026-48316, CVE-2026-48283, CVE-2026-48286, adobe, coldfusion, RCE, path-traversal, unrestricted-upload, CISA-KEV, watchtowr]
excerpt: "Adobe dropped patches for 11 critical ColdFusion flaws — six of them CVSS 10.0 — on June 30. Attackers had working exploits against CVE-2026-48282 within two hours of disclosure. This is the anatomy of the RDS FILEIO path traversal and the unrestricted upload bugs that made it possible, why ColdFusion keeps getting hammered, and what to do if you're still running a vulnerable instance."
---

**CVE:** CVE-2026-48282, CVE-2026-48276, CVE-2026-48277, CVE-2026-48281, CVE-2026-48316, CVE-2026-48283, CVE-2026-48286  
**CVSS:** 10.0 (Critical) — seven of them  
**Disclosed:** June 30, 2026  
**Affected:** ColdFusion 2025 Update 9 and earlier, ColdFusion 2023 Update 20 and earlier, Campaign Classic v7.4.3 build 9396 and earlier  
**Fixed in:** ColdFusion 2025 Update 10, ColdFusion 2023 Update 21, Campaign Classic v7.4.3 build 9397  
**CISA KEV:** CVE-2026-48282 added July 7, 2026  
**Public analysis:** [watchTowr Labs](https://labs.watchtowr.com/its-37oc-and-all-we-can-think-about-is-coldfusion-adobe-coldfusion-security-bulletin-apsb26-68-cve-bonanza/)

---

On June 30, 2026, Adobe published APSB26-68, a security bulletin covering 11 critical vulnerabilities in ColdFusion 2023 and 2025. Six of them carry CVSS 10.0 — the maximum possible score. A seventh, in Adobe Campaign Classic, also scores 10.0. That is not a typo. Seven distinct vulnerabilities that each earn a perfect severity rating, all fixed in the same patch release.

What happened next is a case study in how fast modern exploitation moves. Two days after the bulletin, watchTowr researchers published a technical analysis breaking down the RDS FILEIO path traversal (CVE-2026-48282) and the unrestricted file upload bugs. Within two hours of that publication, KEVIntel's global honeypot network recorded active exploit traffic. An actor operating from Indian infrastructure was already probing every internet-facing ColdFusion server they could find.

CISA added CVE-2026-48282 to its Known Exploited Vulnerabilities catalog on July 7. As of this week, Shadowserver tracks roughly 750 publicly exposed ColdFusion instances. How many are patched is anyone's guess.

This post walks through the two most interesting bugs — the RDS FILEIO path traversal and the unrestricted file upload — then discusses why ColdFusion keeps generating these clusters of maximum-severity vulnerabilities and what defenders can actually do about it.

---

## The Bug That Blew Up First: CVE-2026-48282 (RDS FILEIO Path Traversal)

ColdFusion's Remote Development Services (RDS) is a legacy feature dating back to the Dreamweaver era. It lets an IDE — historically ColdFusion Builder, Dreamweaver, or the Eclipse plugin — communicate with a running ColdFusion server over HTTP-based RPC. Through RDS a developer can browse the filesystem, execute database queries, deploy files, and debug applications.

One of the RDS services is **FILEIO**, a servlet that handles remote file operations: read, write, copy, delete, list directory contents. It was designed for developer convenience, not for exposure to the open internet. But ColdFusion servers often sit behind a web server that passes requests through, and RDS is enabled by default in many configurations.

The vulnerability is a path traversal in the FILEIO handler. The servlet constructs file paths from user-supplied parameters without adequate validation, and the ColdFusion server runs with high integrity (often `NT AUTHORITY\SYSTEM` on Windows or root-equivalent on Linux). An unauthenticated attacker sends a crafted POST request to:

```
POST /CFIDE/main/ide.cfm?ACTION=FILEIO
Content-Type: application/octet-stream

<length-prefixed RDS body with path=../../../../../../inetpub/wwwroot/shell.cfm>
```

The server resolves the path, writes the file to the web root, and the attacker accesses it directly via the web server to execute arbitrary CFML code. No login. No interaction. One request.

The request flow looks like this:

```
Attacker                  ColdFusion Server
   │                            │
   │  POST /CFIDE/main/ide.cfm  │
   │  ?ACTION=FILEIO            │
   │  path=../../../www/shell.cfm │
   │───────────────────────────►│
   │                            │
   │                    RdsFrontEndServlet
   │                            │
   │                    ┌───────┴────────┐
   │                    │  FILEIOServlet  │
   │                    │  processCmd()   │
   │                    │  writeFile()    │
   │                    └───────┬────────┘
   │                            │
   │  <length-prefixed RDS      │
   │   response: OK>            │
   │◄───────────────────────────│
   │                            │
   │  GET /shell.cfm            │
   │───────────────────────────►│
   │                            │
   │  HTTP 200 (RCE achieved)   │
   │◄───────────────────────────│
```

watchTowr's analysis confirmed that the FILEIO handler uses a `processCmd()` dispatch that maps the `ACTION` parameter directly to command implementations. The `writeFile` command takes a `path` parameter and writes the request body to that location. Path traversal sequences like `../` are not stripped or validated.

The researchers described it in characteristically blunt terms during their July 2 write-up:

> *"We can write a file anywhere on the filesystem. Since ColdFusion serves CFM templates from its web root, we can simply write a .cfm shell and execute it."*

## The Unrestricted Upload: CVE-2026-48276

While CVE-2026-48282 is the headline grabber due to confirmed active exploitation, CVE-2026-48276 is arguably worse in coverage. It is an unrestricted file upload vulnerability (CWE-434) in a different code path that also allows an unauthenticated attacker to upload a file with a dangerous type.

The key difference: CVE-2026-48276 does not require RDS to be enabled. It targets a separate file upload handler that accepts multipart form data and writes uploaded files to disk without validating the file extension or content type. A `.cfm`, `.jsp`, or `.exe` file can be uploaded and subsequently executed.

Where CVE-2026-48282 requires the RDS feature to be accessible (a condition that varies by deployment), CVE-2026-48276 is reachable on any ColdFusion server that exposes a file upload endpoint — and ColdFusion's default configuration includes several of those.

Both bugs achieve the same end state: unauthenticated remote code execution with a single HTTP request.

## Why Seven CVSS 10.0s in One Bulletin?

This is not an isolated incident. ColdFusion has a long track record of critical vulnerabilities. Sixteen ColdFusion CVEs already sit in the CISA KEV catalog. A 2023 patch batch included multiple CVSS 9.8 RCE flaws. In 2024, attackers exploited ColdFusion vulnerabilities to deploy webshells on government servers.

The pattern is structural, not accidental. Several factors converge:

**Legacy surface area.** RDS, the admin console (`/CFIDE/administrator/`), and various built-in file upload handlers date back 15-20 years. They were designed for a different threat model — internal networks, trusted developers, no internet exposure. They have not been meaningfully refactored.

**Java stack complexity.** ColdFusion runs on a Java server engine that layers CFML on top of the JVM. The attack surface includes the Java servlets that implement RDS, the CFML interpreter itself, the tag libraries, and the connector layer to the web server. Each layer introduces its own parsing and validation logic, and the interactions between them are where path traversals and file type confusion bugs live.

**Slow patching cadence in the installed base.** ColdFusion is disproportionately deployed in enterprise and government environments where patching cycles are measured in weeks or months. Attackers know this. The economics of developing an exploit for ColdFusion are favorable because the window between disclosure and mass patching is reliably long.

**Credentialed vs. unauthenticated confusion.** Several of the CVSS 10.0 bugs in this batch were initially flagged as requiring authentication. Subsequent analysis showed they are reachable without it. The distinction between "requires admin console access" and "requires authentication" gets blurry when the admin console itself is reachable without authentication in default configurations.

## The Two-Hour Window

The timeline of CVE-2026-48282 exploitation is worth restating because it sets a new baseline for how fast the window can close:

- **June 30** — Adobe releases APSB26-68 with patches. The bulletin includes minimal technical detail.
- **July 2** — watchTowr publishes technical analysis of the RDS FILEIO path traversal, including request structures and exploitation mechanics.
- **July 2 (2 hours later)** — KEVIntel's honeypot network detects active exploitation attempts. The attacker infrastructure routes through Indian IP space.
- **July 7** — CISA adds CVE-2026-48282 to the KEV catalog. BOD 26-04 requires federal agencies to patch within 21 days.

The takeaway: the window between "technical details published" and "active scanning at internet scale" is now measured in hours, not days. If you do not have a mechanism to patch critical-severity vulnerabilities within 24 hours of public disclosure, you are racing the attackers and losing.

## Detection

For CVE-2026-48282 (RDS path traversal):

**Network-level:**
```
POST /CFIDE/main/ide.cfm
ACTION=FILEIO
Content-Type: application/octet-stream
```

Monitor for POST requests to `/CFIDE/main/ide.cfm` with `ACTION=FILEIO` originating from IPs not in your trusted development range. In most production environments, there should be zero traffic to this endpoint.

**File-system level:**
```
find /opt/coldfusion/wwwroot -name "*.cfm" -newer /opt/coldfusion/lib/patches.txt
```

Unexpected `.cfm` files appearing in the web root after June 30, 2026, are indicators of compromise. Check file creation timestamps against your patch deployment date.

For CVE-2026-48276 (unrestricted upload):

Monitor for multipart file uploads that result in `.cfm`, `.jsp`, or `.exe` files being written to the web root. Legitimate ColdFusion upload functionality typically restricts uploads to non-executable directories or validates file extensions.

## Mitigation (If You Cannot Patch Immediately)

1. **Disable RDS** if you are not actively using remote development:

   In `ColdFusion Administrator → Server Settings → Settings`, uncheck "Enable RDS". Alternatively, block `/CFIDE/main/ide.cfm` at the web server level:

   ```apache
   # Apache
   <LocationMatch "^/CFIDE/main/ide\.cfm">
       Require ip 10.0.0.0/8
   </LocationMatch>

   # IIS
   <location path="CFIDE/main/ide.cfm">
       <system.webServer>
           <security>
               <ipSecurity allowUnlisted="false">
                   <add ipAddress="10.0.0.0" subnetMask="255.0.0.0" allowed="true"/>
               </ipSecurity>
           </security>
       </system.webServer>
   </location>

   # Nginx
   location ~ ^/CFIDE/main/ide\.cfm {
       allow 10.0.0.0/8;
       deny all;
   }
   ```

2. **Do not expose the ColdFusion admin console to the internet.** The `/CFIDE/administrator/` path should be restricted to internal networks or VPN only. This is not a complete mitigation for CVE-2026-48276 (which does not require RDS), but it reduces the overall attack surface.

3. **Remove sample applications** and the default cfdocs folder if present. Old ColdFusion installs ship with sample files that include additional upload handlers.

4. **Run a ColdFusion-specific WAF rule** blocking path traversal sequences (`../`, `..\`, URL-encoded variants) in the `path` parameter of requests to `/CFIDE/main/ide.cfm`.

## The Pattern and What It Means

ColdFusion is not going away. It runs in too many enterprises, governments, and universities. But it has become a reliable source of maximum-severity, remotely exploitable vulnerabilities that attackers weaponize within hours of disclosure.

The lesson from APSB26-68 is not specific to Adobe or ColdFusion. It is a lesson about legacy surface area on the internet. Any application platform that:
- was designed before 2010,
- exposes administrative or development endpoints via HTTP,
- runs with high OS privileges,
- has a long patch cycle in its user base,

...will eventually produce a bulletin like this one. The only question is when.

For defenders running ColdFusion, the playbook is straightforward but requires discipline: inventory every instance, verify the version, apply Update 10 (2025) or Update 21 (2023) immediately, disable RDS where it is not needed, and monitor for unexpected `.cfm` files appearing in web-accessible directories. The attackers are already scanning. Assume they found you before you read this sentence.

---

*Based on analysis from [watchTowr Labs](https://labs.watchtowr.com/its-37oc-and-all-we-can-think-about-is-coldfusion-adobe-coldfusion-security-bulletin-apsb26-68-cve-bonanza/), [KEVIntel](https://kevintel.io), [Resecurity](https://www.resecurity.com/blog/article/cve-2026-48282-adobe-coldfusion-rds-path-traversal-leading-to-rce), [Hive Pro](https://www.hivepro.com/threat-advisory/coldfusion-path-traversal-cve-2026-48282-under-active-attack), [BleepingComputer](https://www.bleepingcomputer.com/news/security/max-severity-adobe-coldfusion-flaw-now-exploited-in-attacks/), and [CISA](https://www.cisa.gov/news-events/alerts/2026/07/07/cisa-adds-one-known-exploited-vulnerability-catalog).*
