---
layout: post
title: "CIFSwitch: When the Root Helper Walks Into Your Namespace"
date: 2026-05-30
categories: [exploits, linux]
tags: [cifswitch, cifs-utils, cifs-upcall, keyrings, namespaces, nss, lpe]
excerpt: "No memory corruption, no race. Just a root helper that trusts a key description it should never have parsed, then setns()-es into a namespace you control."
---

Most of the Linux root bugs this month have been page-cache corruption. Dirty Frag, Fragnesia, Copy Fail. All variations on the same skb-and-COW theme, all about tricking the kernel into writing onto memory it doesn't own. CIFSwitch is a nice break from that. There is no overflow here. No race window. No timing. It is a pure trust bug that lives on the seam between the kernel CIFS client and a root-owned userspace helper, and once you see how it works you start wondering how it sat there since the upcall mechanism was built.

Asim Manizada disclosed it on May 28 with a full writeup and a working proof-of-concept. What got my attention first wasn't even the bug. It was how it was found. Manizada says he located it with an AI-assisted pass that builds semantic graphs of security-relevant objects and the flows between them, then walks those graphs looking for chains. That is a different way of finding kernel bugs than fuzzing for crashes, and CIFSwitch is exactly the kind of thing fuzzers miss, because nothing crashes. The code does precisely what it was written to do. It was just written to trust the wrong source.

## The upcall nobody thinks about

Here is the setup. When you mount a CIFS/SMB share with Kerberos, the kernel needs SPNEGO tokens to authenticate. The kernel can't do that work itself, so it punts to userspace through the request-key mechanism. The kernel asks for a `cifs.spnego` key. The system's request-key configuration sees that key type and launches `cifs.upcall`, the helper from `cifs-utils`, as root, to go fetch the credential and hand it back.

That flow is fine when the kernel is the one asking. The problem is the kernel never properly verified that it *was* the one asking. An unprivileged process can call `request_key(2)` or `add_key(2)` with a forged `cifs.spnego` description, and the kernel happily lets a userspace-created description through. The default request-key rule still fires. `cifs.upcall` still gets spawned as root. Except now every field it parses came from you.

```c
/* unprivileged user forges the description the root helper will trust */
request_key("cifs.spnego",
            "ver=1;pid=<attacker_pid>;upcall_target=app;...",
            NULL, KEY_SPEC_THREAD_KEYRING);
```

`cifs.upcall` reads `pid`, `uid`, `creduid`, and `upcall_target` out of that string as if a kernel that did its homework produced them. That last field is the lever.

## upcall_target=app, and the helper follows you home

Set `upcall_target=app` and `cifs.upcall` does something genuinely alarming. It calls `setns(2)` to enter the namespaces of the process named by the attacker-supplied `pid`. The idea behind the feature is reasonable enough: resolve the credential in the context of the application that wanted the mount. The execution is where it falls apart.

After it switches namespaces, the root helper does a `getpwuid()` account lookup, and it does that lookup *before* it drops privileges. Think about what that means. `getpwuid()` goes through NSS. NSS loads modules like `libnss_*.so.2` according to the configuration it finds in the current mount namespace. You control that namespace. So you stage your own `nsswitch.conf` and your own malicious `libnss_X.so.2`, point the helper at your namespace, and the root process loads your shared object and runs your code. Root, no exploit primitive in the usual sense, just a privileged process reading config and libraries out of a filesystem view that an unprivileged user assembled.

The public PoC at `github.com/manizada/CIFSwitch` does exactly this. It builds a fake NSS library and a small trigger that drives `cifs.upcall` into the private namespace and gets the controlled module loaded. Manizada is clear that the code is meant for defenders and maintainers to validate exposure. It is also a one-shot. Nothing has to be timed and nothing panics if you get it wrong, which is what makes logic bugs like this so much more pleasant to weaponize than the page-cache stuff.

## Not universal, and that actually matters

This is where I want to be honest, because the headlines blur it. CIFSwitch is not a press-one-button-on-every-box bug. It needs a specific stack lined up: a vulnerable kernel, an affected `cifs-utils`, the default `cifs.spnego` request-key rule in place, unprivileged user and mount namespaces enabled, and a LSM policy that doesn't already block the chain.

When those line up, it is stock-exploitable. Manizada's tested list includes Linux Mint 21.3 and 22.3, CentOS Stream 9, Rocky Linux 9, AlmaLinux 9.7 (including the Azure image), Kali headless from 2021.4 through 2026.1, and several SLES and SLES-for-SAP 15 SP7 and 16 builds running SELinux permissive. A second tier becomes exploitable the moment someone installs `cifs-utils` by hand, and that group is the one that should worry you because it is huge: Ubuntu 18.04 through 22.04, Debian 11 through 13, Pop!_OS 22.04 and 24.04, openSUSE Leap 15.6, Oracle Linux 8 and 9 cloud images, Amazon Linux 2023 on permissive SELinux. Anybody who has ever run `apt install cifs-utils` to mount a file server has opted in.

The newer releases mostly hold. Fedora 40 through 44, Ubuntu 26.04, CentOS Stream 10, Rocky 10, AlmaLinux 10.1, openSUSE Tumbleweed and SLES 16 are blocked by stock SELinux or AppArmor policy even with `cifs-utils` present. That is a real argument for enforcing mode being on by default, and a quiet reminder that "SELinux permissive" in a golden image is not a neutral choice.

As of disclosure there was no CVE assigned yet. The kernel-side fix is public and queued for stable. It does the obvious correct thing the original code skipped: it rejects userspace-created `cifs.spnego` descriptions and only lets CIFS create them using its private `spnego_cred` credentials, so a forged description from an unprivileged keyring call no longer reaches the root helper.

## What to do before the erratas land

If you do not mount SMB shares from these hosts, the cleanest fix is to stop the module from ever loading and remove the helper:

```bash
# block the kernel module and drop the userspace helper
echo 'install cifs /bin/false' | sudo tee /etc/modprobe.d/cifswitch.conf
sudo rmmod cifs 2>/dev/null || true
sudo apt-get remove --purge cifs-utils   # or dnf/zypper remove
```

If you do need CIFS but not Kerberos auth, override the default request-key rule so a forged `cifs.spnego` lookup goes nowhere instead of spawning a root helper. Edit `/etc/request-key.conf` (or the drop-in under `/etc/request-key.d/`) and point the `cifs.spnego` line at `/bin/false`.

And if you have been putting off the unprivileged-namespace conversation, this is the bug to bring to that meeting. `sysctl kernel.unprivileged_userns_clone=0` on Debian-family systems, or `user.max_user_namespaces=0` where the clone toggle isn't available, breaks the chain by removing the namespace primitive the helper gets lured into. It is the same mitigation that shut down half the other LPEs this month, which tells you something about where the soft underbelly is.

Patch when your distro ships the kernel update. Until then, decide whether any given box actually needs to speak SMB, because most of them don't, and the ones that don't are a free win.
