---
layout: post
title: "shellDojo is live — train like they're already inside"
date: "2026-08-03"
categories: ["garrettstimpson.ca", "shell-dojo"]
tags: ["shell-dojo", "security", "training", "blue-team", "terminal", "ctf"]
excerpt: "shellDojo is a blue team training range disguised as a terminal. Drop into a simulated Linux or Windows box that's already compromised and hunt the intruder with real commands — 591 operations, S-to-C grading, and output that matches a real machine exactly."
---

A while back I got tired of training ranges that felt like board games. Capture-the-flag is a fine way to learn what a flag is, but it teaches you almost nothing about what an actual incident looks like — the messy middle where you don't even know what's wrong yet, the tool you need isn't handed to you, and the output on your screen is the only truth you've got.

So I built shellDojo.

**shellDojo is a blue team training range disguised as a terminal.** Every scenario drops you into a simulated Linux or Windows machine that is *already compromised*. Your job: hunt the intruder, prove their tradecraft, and evict them — by typing real incident-response commands. No multiple choice, no "click the vulnerability" minigame, no hand-holding. Just you, a shell, and a box that's owned by someone else.

The tagline says it better than I ever could: **train like they're already inside.**

## Why the output is the whole point

The thing I care about most is fidelity. When you run `ps aux` in a shellDojo mission, what comes back has to be exactly what a real compromised box would show you — the odd process name, the parent PID that doesn't line up, the user that shouldn't be there. When you run `ss -tunap`, you get the sockets, the foreign addresses, the PIDs. When you `cat` a config file, you get the real thing, formatting and all.

That's a genuinely hard problem, and it's the whole reason the project exists. A training range that shows you sanitized output teaches you sanitized thinking. A range that shows you the real thing — including the ambiguity, the noise, and the rabbit holes — teaches you to actually *read a box*. Every command, every flag, every argument is interpreted the way it would be in the real world, and the output is generated to match: the same tools, the same flags, the same output shape you'd see on a live machine. And when you do get it wrong, the command brief decodes what you just ran — the binary, the flags, the hook — so a fumbled `find` invocation doesn't just earn you a "wrong," it tells you what you were actually doing.

## How the range works

You pick an operation and get dropped straight into the terminal. The machine is already owned — your job is to figure out how, by whom, and how to kick them out. Most operations are Linux boxes; a solid chunk are Windows. Difficulty runs 1 to 5, and the catalog runs from ten-minute warm-ups to eighty-minute marathons.

Finish an operation and you get an after-action report: grade, accuracy, first-try rate, hint spend, per-step pacing, and whether you beat par. Your record persists in your browser — rank and XP accumulate, and badges unlock for things worth being able to do: a flawless run, an S grade, a full sweep of every operation, and a clean clear with the range's ghost switched off.

Grades run S (near-perfect accuracy, no hint spend, inside par) down to C. Accuracy is correct commands over commands entered, plus how many steps you cleared on the first try — because accuracy is what separates an operator from someone who reads a runbook aloud. Every miss gets answered in-world and then explained: read the blue ▶ lines, they're the actual lesson.

Two commands talk to the range itself rather than the scenario — `hint` (reveals more of the command, costs you score) and `status` (live accuracy, pace, and score). Everything else is the box.

## The catalog

Right now there are **591 operations** in the range, spread across disciplines — Forensics, War Games, Lockout, Trace, long-form investigations, and practical response — plus a growing handful of AI-flavoured ones. A few I'm proud of:

| Operation | Premise | Box | Diff | Size |
|---|---|---|---|---|
| Ghost Signal | A web server is mining crypto for someone who isn't you | linux | 1 | ~20 min |
| Paper Oracle | AI-themed forensics — the kind that ends in a model you can't trust | linux | 2 | 11 steps |
| Paper Trail | Trace work that starts small and keeps pulling threads | linux | 2 | 10 steps |
| Hydra Protocol | AI-themed, short and nasty | linux | 3 | 12 steps |
| Flash Point | A compromised agent is spawning workloads faster than you can delete them. Stop chasing. | linux | 3 | 13 steps |
| Undertow | War games. It earns the name. | linux | 5 | 22 steps |
| Broken Chain | Long-form — a whole campaign, start to finish | linux | 5 | 29 steps |
| Blue Water | Contacts that are not there, a position that jumps, a chart display that believes all of it | linux | 5 | 19 steps |
| Hollow Crown | A nation-state-grade domain compromise. Work it to first contact and find out who really opened the door. | windows | 5 | 50 steps |

## The AI ones

This is the part I'm having the most fun with right now. The catalog has a whole thread of missions about the mess AI has made of operations — `false-copilot`, `runaway-agent`, `whisper-net`, `paper-oracle`. Runaway Agent is exactly what it sounds like: an agent that was left running and is now doing things nobody asked it to do. These are the new frontier of incident response, and most ranges won't touch them yet because most ranges are still teaching you how to find a webshell. The people defending real networks are already getting tickets that say "why is the CI runner calling some endpoint at 3am" — a training range that ignores that isn't training you for the world you actually live in.

## Under the hood

shellDojo is a Flask + Python app running on Vercel with a terminal client in the browser. No install, no VM, no setup — you open the page and you're in a shell. Every mission is a deterministic simulation: the same commands, the same flags, the same output a real box would show you, every single run. No real machines are harmed in the making of your training.

## Go get your hands dirty

If any of that sounds like your kind of Friday, the range is live at [shell-dojo.vercel.app](https://shell-dojo.vercel.app/). It's free, it runs in your browser, and the first warm-up takes about ten minutes. Start with Operation Ghost Signal — a web server mining crypto for someone who isn't you — and try not to touch `hint`. Your score will thank you.

— Garrett
