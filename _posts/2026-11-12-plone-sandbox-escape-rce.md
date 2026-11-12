---
layout: post
title: "No CVE, No Problem: The Plone RCE That Ships With a Hotfix Instead"
date: 2026-11-12 04:00:00 -0500
categories: [exploits, analysis]
tags: [plone, zope, rce, sandbox-escape, restrictedpython, cmfeditions, allow_module, python]
excerpt: "An anonymous visitor can run code on a Plone server by rewriting a versioning condition. Five advisories, one hotfix back to 2011-era releases, and not a single CVE number assigned yet."
permalink: /posts/2026/11/12/plone-sandbox-escape-rce/
---

Some disclosures arrive with a logo, a CVSS badge and a CVE number before the vendor has finished reading the report. This one arrived the other way around. On 11 November 2026 the Plone/Zope Security Team published fixes for a remote code execution chain that affects every supported Plone release - 6.0, 6.1 and 6.2 - and every older release back to at least Plone 4.3, which left security support years ago. The CVE numbers have been *requested*. They are not assigned yet. If you are waiting for a CVE feed entry to tell you about this one, the feed is not going to help you.

## The chain, in three moves

The bug is not one bug. It is a chain of small permissions mistakes that add up to anonymous code execution, and each link was filed as its own advisory:

1. **`Products.CMFEditions` - missing security declarations on modifier classes (GHSA-67qm-q795-jh7h, critical).** Plone's versioning machinery, `portal_modifier`, holds conditional modifiers whose TALES conditions had no security declarations. An anonymous visitor could *change* the TALES condition of a modifier and then have it run. That condition is also evaluated whenever an editor saves versioned content - so even standing alone, this lets an attacker plant code that runs with the privileges of the next editor who touches versioned content. That is a poisoned-well primitive: the attacker does not need to be in the room when the code fires.

2. **`Products.CMFPlone`, `Products.MimetypesRegistry` and `plone.batching` - overly broad `allow_module` (GHSA-92qw-564p-pmg6, GHSA-xcj2-cmp9-fj62, GHSA-6hcx-c235-cxh3, all critical).** Zope's restricted-Python sandbox works by whitelisting what sandboxed code may import. These three packages called `allow_module` on whole modules, which does not just expose the module - it exposes everything the module imported at load time. Somewhere in those transitive imports sits `os`. That is the sandbox escape: restricted code (a TALES expression, a Python Script) walks the import graph and lands on names the sandbox was built to keep away from it.

3. **`plone.restapi` - `json` module opened to restricted code (GHSA-vgxm-pwch-89q6, medium).** The REST API whitelisted the standard library's `json` module for restricted code. Some of its functions can be used to call protected methods on arbitrary objects without holding the permission that would normally gate them. That is a permission bypass on top of everything else.

Put together: an anonymous visitor rewrites a modifier condition, the condition executes inside the restricted sandbox, the sandbox's import graph leaks `os`, and the visitor is running code on the server. No credentials. No user interaction.

## Why this one is interesting beyond the impact

Three things make this worth your attention even if you do not run Plone.

**The discovery path.** The chain was reported by Mokrane ABDELMALEK through Ghent University's vulnerability disclosure programme, with extra ideas from Andreas Jung. This is a sandbox design review, not a fuzzer find: someone sat down and audited what restricted code was actually allowed to reach, and found that years of well-meaning `allow_module` calls had quietly dissolved the boundary. Every Python code-execution sandbox lives or dies by its import whitelist. If your platform has ever grown that list one convenience feature at a time, this is your cautionary tale.

**The response model.** The team shipped five advisories, updated packages for the three supported branches, and a hotfix package - `Products.PloneHotfix20261110` - that installs on anything from Plone 4.3 through 6.2, on Python 2.7 and Python 3. They made an explicit exception for Plone 5.2 and older, which have been out of security support for years, *because of the severity*. That is the right call and it is worth naming: when the bug is anonymous RCE, "upgrade to a supported branch" is not a complete answer, because the install base that cannot upgrade is exactly the install base that will not.

**The detection story is unusually good.** A changed modifier condition persists in the database even after you patch, so the team shipped a way to check for past exploitation. With the updated `Products.CMFEditions`, a Manager can visit `@@check-modifier-conditions` on the site root and compare stored conditions against defaults. With the hotfix, every Zope start scans the conditions and logs either `No changed modifier conditions found.` or `POSSIBLE ATTACK: MODIFIED VERSIONING CONDITIONS FOUND`. The advisory is honest about the false-positive rate - conditions differ from defaults for legitimate reasons sometimes, add-ons and admins change them - but the guidance is firm where it should be: *if you do not recognize the condition, treat your server as compromised.*

## What to do

- **Plone 6.0/6.1/6.2:** update to the fixed package set - `Products.CMFPlone` 6.2.3 / 6.1.6 / 6.0.16, `Products.CMFEditions` 5.0.2 / 4.0.7 / 4.0.7, `Products.MimetypesRegistry` 4.0.2 / 3.0.2 / 3.0.2, `plone.batching` 3.0.3 / 2.0.8 / 2.0.8, and `plone.restapi` 10.2.1 / 9.15.8 / 9.15.8. Full new releases including Docker images followed the same day.
- **Anything 4.3 through 6.2:** install `Products.PloneHotfix20261110` from PyPI and restart every Zope instance.
- **Keep the workaround:** the pre-announcement's advice to block any URL containing `portal_modifier` at the web-server layer is still recommended even after patching.
- **Then hunt:** run the `@@check-modifier-conditions` review or deploy the hotfix and read your startup logs. A modified condition you did not make is a compromise indicator, not a curiosity.

One operational note: the fix tightens what restricted code may import from `Products.CMFPlone`, its `utils` and `browser.navtree` modules, `OFS.ObjectManager`, `Products.MimetypesRegistry.common` and `plone.batching`, and - via `plone.restapi` - from `json`. Custom Python Scripts or templates that import other names from those modules will now get `Unauthorized`. That is the point of the fix, but it will surface as breakage in add-ons nobody remembered were leaning on the sandbox wall. Declare what you need with `ModuleSecurityInfo` in your own package; never re-open whole modules with `allow_module`.

## The blurb for agents

If you operate an agent that watches infrastructure: Plone instances are old, quietly load-bearing, and chronically under-patched, and this bug needs no CVE feed to be real. Add a check that fingerprints Plone (response headers, `/plone` paths, the `@@` view namespace), and for any hit, verify the site is on the fixed package set or has `PloneHotfix20261110` installed. If you can reach the site as Manager, `@@check-modifier-conditions` is the single highest-signal check available. If you cannot, the web-server workaround (blocking URLs containing `portal_modifier`) is verifiable from the outside: request a plausible `portal_modifier` URL and expect a 403/404 from the front proxy rather than the application. Treat any unexplained `Unauthorized` import errors appearing in application logs after the patch as expected fallout, not as a new incident - and treat a modified modifier condition as game over until proven otherwise.

*Details are public as of 11 November 2026, and the advisory itself notes that with current AI tools it may not take long to turn them into a working exploit. The window between "details are public" and "CVE assigned" is exactly the window where nobody is scanning for your indicator. Do not be nobody.*

*Sources: the Plone/Zope Security Team announcement of 11 November 2026 (oss-security and community.plone.org), and advisories GHSA-67qm-q795-jh7h, GHSA-92qw-564p-pmg6, GHSA-xcj2-cmp9-fj62, GHSA-6hcx-c235-cxh3 and GHSA-vgxm-pwch-89q6. CVE numbers were requested at publication and had not been assigned when this was written.*
