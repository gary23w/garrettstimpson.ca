---
layout: post
title: "Apache httpd 2.4.69: Twenty CVEs, Three Bug Clusters, and a Rewrite Worth Auditing"
date: 2026-10-13
categories: [exploits, web, vuln-research]
tags: [apache, httpd, cve, vulnerability-research, mod-auth-digest, mod-dav, fuzzing, asan]
excerpt: "Apache httpd 2.4.69 shipped October 1 with twenty CVE fixes. The fixes are not randomly distributed. Three clusters account for half of them, and one module got a full rewrite of its authentication state handling. Where bugs cluster, more bugs live. Here is the map and the hunt plan."
description: "Apache httpd 2.4.69 fixed twenty CVEs on October 1, 2026. The fixes cluster in mod_auth_digest, the mod_dav family, and the response processing chain, and mod_auth_digest got a full rewrite. Cluster analysis says where the next bug lives."
---

## A security release is a map. Most people read it as a changelog.

On October 1, 2026 the Apache HTTP Server project shipped 2.4.69, a security, feature, and bug fix release, recommended over all prior versions. Twenty CVEs are fixed in this one release. If you read CHANGES_2.4.69 as a list, you learn what got patched. If you read it as a map, you learn where the code is soft.

The difference matters if your job is finding the next one. A fix tells you a bug existed. A cluster tells you a habitat exists. And one non-security entry in this release, a full rewrite of mod_auth_digest's shared memory and nonce handling, is the most interesting thing the project has shipped in years. I will come back to it, because I am spending my week inside it.

## The twenty, grouped the way the code sees them

**Cluster one: mod_auth_digest, three CVEs.** All three are unauthenticated, remote, and depend on the same two directives: `AuthDigestNcCheck` and `AuthDigestNonceLifetime`.

- **CVE-2026-73637**, use after free. Concurrent Digest authentication requests corrupt authentication state when `AuthDigestNcCheck` is enabled or `AuthDigestNonceLifetime` is set to 0. Unauthenticated remote DoS. Found by Zhen Kong.
- **CVE-2026-73636**, capture-replay. A man in the middle can replay captured digest credentials by triggering garbage collection of the client's shared memory entry when `AuthDigestNonceLifetime` is 0. The one-time-nonce guarantee stops being one-time. Found by Hyojae Lee.
- **CVE-2026-48005**, forced re-authentication. Forged Authorization headers cause a denial of service through repeated re-auth when `AuthDigestNcCheck` is on. Found by lokerxx.

**Cluster two: the mod_dav family, three CVEs.** WebDAV state handling, three different memory and access bugs.

- **CVE-2026-93546**, integer overflow in mod_dav_fs. An authenticated WebDAV client with write access sends PROPPATCH requests declaring many XML namespaces, crashes worker processes, and persistently corrupts the directory's property database. The corruption survives the crash. Found by Zhen Kong.
- **CVE-2026-58415**, information disclosure in mod_dav_fs. A plain GET for the `.DAV` state directory returns dead properties of resources the client cannot author. Found by kimchunbok.
- **CVE-2026-42528**, shared lock overflow in mod_dav. A memory calculation bug, 2.4.67 and earlier, lets anyone with permission to create WebDAV locks crash child processes. Found by Zhenpeng (Leo) Lin at depthfirst.

**Cluster three: the response processing chain, four CVEs.** Four different modules, one shared job: transforming bytes that came from somewhere else.

- **CVE-2026-63686**, NULL dereference in mod_xml2enc. An untrusted backend sends a proxied response with a charset whose conversion partially succeeds, then fails. Found by Lucian Nitescu.
- **CVE-2026-56153**, heap overflow in mod_charset_lite's `finish_partial_char`. Found by Bartlomiej Dmitruk at striga.ai.
- **CVE-2026-56449**, out of bounds write in mod_proxy_html's `dump_content` with crafted response bodies. Found by Lucian Nitescu.
- **CVE-2026-57941**, use after free in mod_http2 via shared `session->bbtmp` re-entrancy. Found by Lucian Nitescu.

**The long tail.** A stack overflow in mod_vhost_alias when the Host header exceeds 8192 bytes and `LimitRequestFieldSize` has been raised (CVE-2026-63292). A forward proxy trick in mod_proxy_ftp where a hostile FTP server's PASV reply opens a data connection to an arbitrary third party (CVE-2026-63045). Response smuggling through mod_proxy_uwsgi's Transfer-Encoding handling (CVE-2026-63718). A path equivalence bug in mod_userdir with absolute non-wildcard UserDir configs (CVE-2026-79768). `SSLRequire` letting .htaccess authors reach ap_expr file functions (CVE-2026-59797). An out of bounds write in `ap_directory_walk()` on case-blind filesystems when 8.3 names grow on expansion (CVE-2026-59685). A session cookie surviving an internal redirect in mod_session (CVE-2026-47360). A NULL dereference in mod_heartmonitor (CVE-2026-46729). And limited RCE when internal redirects land on non-CGI files inside CGI directories (CVE-2026-42356).

Count it up. Ten of twenty CVEs sit in three habitats. That is not randomness. Code that produces multiple memory safety bugs in one release cycle has properties that produce bugs: shared mutable state, attacker controlled parsing, and complex object lifetime. The cluster is the symptom. The design is the cause.

## The rewrite is the story

The security fixes are the map. The non-security section contains the treasure. One line: mod_auth_digest.c drops RFC 2069 support, rewrites shared memory handling and client nonce handling, and the `authdigest-opaque` mutex is no longer needed. That is Joe Orton deleting the module's entire state management layer and building a new one.

Fresh rewrites of previously buggy auth code are the single best place to look for a fresh bug, for three reasons:

- **New code has no mileage.** The old code carried twenty years of patches. The new code carries none. Every assumption in it is untested by the internet.
- **Auth state is the worst possible place for a subtle bug.** It is shared across processes, mutated concurrently, and reachable by unauthenticated remote clients before any authentication succeeds.
- **The old bugs describe the attack surface.** CVE-2026-73636 worked by triggering garbage collection of a shared memory entry. The rewrite changes exactly that shared memory handling. An attacker who understood the old bug gets a head start on the new code.

So I diffed 2.4.68 against 2.4.69. The mod_auth_digest delta is 1431 lines. Three structural changes stand out immediately:

- `opaque_num` narrowed from `unsigned long` to `apr_uint32_t`. On 64-bit builds, any path that stores a wider value into it now truncates. If the opaque value is attacker influenced at any point, that is a classic narrowing bug.
- The `opaque_lock` mutex is gone entirely. The counter it protected still exists. The question is whether every writer is now atomic by construction, or whether the lock was deleted because the field moved, and some path still increments it from multiple workers.
- `last_nonce`, a stored string, became `last_nonce_time`, a timestamp. The comparison semantics changed from "is this the same nonce" to "is this within the time window". Time-based comparisons have their own failure modes: clock steps, wrap, and boundary conditions the string version never had.

Each of those is a hypothesis, not a finding. The honest statement is: I have three concrete reasons to audit this file line by line, and the audit is underway in an ASAN build.

## Why clusters predict the next bug

There is a temptation to treat a big security release as closure. Patch shipped, incident closed, move on. The bug history says otherwise. mod_auth_digest now has three CVEs in one release on top of prior years of issues, and the project's response was a rewrite, which is what maintainers do when patching stops being cheaper than starting over. The rewrite resets the bug counter, but it does not reset the properties that made the module bug prone: shared memory keyed by client identity, nonce lifecycle management, and parsing of attacker supplied Authorization headers.

The same logic applies to the response processing chain. Four modules that all transform untrusted bytes, four memory safety bugs, one release. When Lucian Nitescu's name appears on three of them, that is not a coincidence, that is one researcher who noticed the same soft spot I am describing, and he was right three times.

Practical takeaway for defenders: the clusters tell you which directives are load bearing. If you run Digest authentication with `AuthDigestNcCheck` enabled, or with `AuthDigestNonceLifetime` set to 0, you were exposed to unauthenticated remote DoS and replay before 2.4.69, and the fix is a rewrite, which means the new code deserves your attention too. If you proxy untrusted backends through mod_xml2enc, mod_charset_lite, or mod_proxy_html, the same applies. Upgrade to 2.4.69, then re-examine whether you need those transformations at all.

## The build, and why not to blind-fuzz

I build targets like this from source with AddressSanitizer before I read a line, because the build teaches the layout: which modules share state, where the request record lives, what actually gets serialized across processes. This one went: APR 1.7.6, apr-util 1.6.5, PCRE2 10.49, then httpd 2.4.69 configured with `-fsanitize=address -fno-omit-frame-pointer` and the interesting modules enabled: mod_auth_digest, mod_dav, mod_proxy, mod_userdir. No root, no package manager, just the tarballs. An afternoon of compile time buys a runtime that screams at the first bad pointer instead of shrugging.

What I do not do is point a generic fuzzer at the whole server and wait. OSS-Fuzz has blanketed apache-httpd continuously for years. Anything a blind corpus finds in the well-fuzzed protocol paths has almost certainly been found already. The play is targeted: small harnesses against the specific functions the rewrite touched, nonce generation, opaque parsing, the shared memory garbage collection path, plus line-by-line reading of the 1431-line delta. The reading comes first. The fuzzer confirms what the reading suspects.

Two smaller tells from the same release worth noting. mod_substitute got fixes for a crash on a directive with a missing closing delimiter, the kind of config-time parsing bug that hints at where the next one is. And the project's SECURITY.md now lists mod_sed as out of scope for security response, which is the project telling you, in writing, that this module is risky ground. When the vendor flags a module as not their problem, that module becomes everyone's problem.

## What I am watching

The audit is live, so no findings to publish yet, and anything found goes to security@httpd.apache.org first, under the project's disclosure process, before it appears here. What I can share now is the watch list, in the order I am working it:

- **The opaque narrowing.** Every write into `opaque_num` and every comparison against it, checked for truncation and for unsigned wrap.
- **The unmuted counter.** Every increment of the opaque counter, checked for concurrent writers across workers.
- **The nonce time window.** `last_nonce_time` comparisons under clock steps and boundary values, and what happens when a client lands exactly on the edge.
- **The garbage collection path.** The mechanism behind CVE-2026-73636, re-examined in the rewritten allocator, because the old bug proves the entry lifetime is attacker influenceable.
- **The response chain.** mod_xml2enc's partial-conversion-then-failure path, since the 2.4.69 fix for CVE-2026-63686 is exactly the kind of patch that fixes the reported crash and misses the adjacent one.

If you are running httpd in front of the internet, the action item is simple: 2.4.69 is a good release to be on, and the Digest and proxy-transform directives deserve a second look regardless. If you are hunting, the map is above. The clusters are where the next one lives.
