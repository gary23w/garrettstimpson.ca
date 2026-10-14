---
layout: post
title: "AGENT GARRETT: Cloud Attack Response"
date: 2026-10-14
categories: [security, agent-garrett]
tags: [agent-garrett, incident-response, cloud-security, nl-veil, ai-agents]
excerpt: "I gave Agent Garrett a cloud incident with symptoms, not an attack map. Here is how it investigated, contained the compromise, and handled a follow-up probe in NL-Veil."
description: "A recorded Agent Garrett incident-response exercise in NL-Veil: evidence gathering, cloud containment, eradication, retesting, and infrastructure tracking."
image: /assets/img/agent-garrett-incident-promo-poster.png
---

An incident rarely arrives with a neat diagram of how the attacker got in. It starts with an application behaving strangely and a few signals that may or may not be related. That is the situation I wanted Agent Garrett to face.

For this exercise, I gave it a short alert: the cloud-hosted `orders-api` was throwing errors, a service identity was being used in an unusual way, and outbound traffic needed a closer look. I did **not** give it the attack sequence or tell it which controls had failed. Agent Garrett had to find those answers in the evidence, through its connection in the NL-Veil desktop app.

<figure class="agent-demo">
  <video controls playsinline preload="metadata" width="1920" height="1080" poster="{{ '/assets/img/agent-garrett-incident-promo-poster.png' | relative_url }}" aria-label="Agent Garrett cloud attack response simulation in NL-Veil">
    <source src="{{ '/assets/video/agent-garrett-cloud-attack-response.mp4' | relative_url }}" type="video/mp4">
    Your browser does not support this video. <a href="{{ '/assets/video/agent-garrett-cloud-attack-response.mp4' | relative_url }}">Download the demo</a>.
  </video>
  <figcaption>Agent Garrett in NL-Veil, using Kimi K2.7 Code. This is an isolated, synthetic cloud incident. The 63-second cut accelerates the waiting and tool-heavy stretches of a recorded desktop session.</figcaption>
</figure>

## What Garrett found

It began with the unglamorous work: pulling status, cloud state, and telemetry, then asking for the full records when an initial result was clipped. That mattered. Some early probes were blocked, but a legacy renderer request had succeeded. The evidence then pointed to a stolen service token, synthetic data leaving the environment, and two persistence mechanisms: a scheduled job and a runtime artifact.

That distinction between a blocked attempt and a successful one is the heart of the exercise. A dashboard full of denied requests can look reassuring while one older route remains open. Garrett built the chain from the records it could see instead of treating every alert as the same event.

## The response, in the same session

Once it had a working picture, Garrett moved through containment and recovery: isolate the affected workload, revoke the stolen token, block the outbound path, remove the scheduled job and runtime artifact, patch the renderer, rotate the underlying secret, restore the service, and add the observed indicators to a watchlist. The video shows the actions and the resulting state in the NL-Veil chat.

The retest was the part I cared about most. A normal order lookup still returned **200**. The renderer replay and synthetic egress attempts returned **403**; reuse of the stolen token returned **401**; both persistence checks returned **404**. In other words, the service was back, and the paths used in the exercise no longer worked.

Then I introduced one more edge event. Garrett checked it against the earlier evidence and watchlist, linked it to the same observed infrastructure, and reran the relevant controls. The follow-up probe was blocked by the patched route. It did **not** turn an IP address into a claim about a named attacker. The lab evidence supported infrastructure tracking, not human attribution.

## Why I built the demo this way

Agent Garrett is the security backend behind the connection. NL-Veil is the desktop interface, and Kimi K2.7 Code drove this recorded session. I wanted to show a single workflow crossing investigation, cloud state, response actions, verification, and follow-up without handing the agent the answer at the start.

This was a controlled simulation, not a production breach or proof that any tool can defend every environment. It does show the behavior I want from a first line of defense: work from evidence, take authorized action, check whether the fix held, and be honest about what the evidence cannot identify.

If you want to connect Agent Garrett to your own MCP client, [start here]({{ site.agent_url }}).
