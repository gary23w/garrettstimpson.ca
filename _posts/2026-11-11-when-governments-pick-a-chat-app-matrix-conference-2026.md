---
layout: post
title: "When Governments Pick a Chat App: Dispatches from Matrix Conference 2026"
date: 2026-11-11 04:00:00 -0500
categories: [privacy, politics, analysis]
tags: [matrix, digital-sovereignty, element, e2ee, starlink, government, malmö]
excerpt: "340 attendees, civil servants from 15 nations, and one Starlink incident that changed how governments think about who owns their messaging. Notes from The Matrix Conference 2026 in Malmö."
---

This one is not a CVE write-up. No PoC, no root cause, no patch diff. It is a report from The Matrix Conference 2026 in Malmö, which wrapped up at the end of October, and the reason I am covering it on a security blog is simple: the most interesting thing happening in secure messaging right now is not a vulnerability. It is a migration. Governments are moving their communications off proprietary platforms, onto Matrix, and the trigger was a satellite.

## The Starlink moment

Just before the conference opened, Starlink throttled Ukrainian access to its satellite internet service in an attempt to halt strikes against Russia. Whatever your read on that specific decision, the structural lesson landed hard in every government hallway in Malmö: if your critical communications run through a single private company, that company can turn you off. Not because it is breached. Not because it is malicious. Because it can.

Matthew Hodgetts opened the conference by calling Matrix "an interesting experiment" that has become "an existential requirement." That is a strong sentence for a chat protocol, but it tracks with what the European Commission said in June, when it unveiled its European Tech Sovereignty Package: roughly 264 billion euros is spent every year on services, and in 2025 the Commission had already recommended that EU governments consider Matrix for real-time communication. The money and the recommendation are now converging on the same conclusion - a communications layer you cannot control is a communications layer you do not own.

## Who is actually moving

The most striking session of the conference was not a talk about the protocol at all. It was civil servants from fifteen different nations and intergovernmental organizations, on stage, one after another, explaining why their institutions are migrating:

- **Germany** - the Federal IT Cooperation (FITKO) laid out its federation-wide deployment, and Germany's health sector is moving to TI-Messenger, a Matrix-based system for the national health insurer. Austria is adopting TI-Messenger too.
- **Sweden** - the Social Insurance Agency (Försäkringskassan) talked about running sovereign messaging for a state agency that handles some of the most sensitive personal data a government holds.
- **France** - DINUM, the Interministerial Directorate for Digital Affairs, presented its continued deployment (Tchap's successor infrastructure).
- **Luxembourg** - a whole government, one of the smallest in Europe, choosing federation over a platform.
- **The United Nations** - UNICC described its journey toward serving 100 UN entities with sovereign, federated communications. That is not a pilot. That is the UN's shared back office.
- **NATO** - the alliance discussed scaling up NI2CE, a Matrix-based messenger, as an alternative to WhatsApp and Signal for operational communication. The interesting part of that talk was not the choice of Matrix; it was the admission of how hard institutional adoption is when your users are used to consumer apps.
- **Brazil and the Netherlands** - new deployments in development, announced at the conference.

There were also sessions from regulated industries - health insurers, financial institutions, legal enterprises - whose reasoning is different but converging: they cannot ship personally identifiable information through a foreign-owned cloud, and data sovereignty law is closing off the easy options one jurisdiction at a time.

## Sovereign does not mean alone

Renato Becker of Rocket.Chat made the point that matters most for how this plays out: "Every organisation that adopts the Matrix federation makes the protocol more valuable." That is the actual argument for federation over yet another government-run silo. A ministry deploying its own WhatsApp clone creates a walled garden with one occupant. A ministry deploying Matrix connects to a network where the Swedish insurance agency, a German hospital, a NATO working group and the UN computing centre already exist - and no single operator sits between them.

The conference demonstrated this live: a federated group call across three different MatrixRTC applications (Visio, Tammy and Element Call), interoperating in real time. It is a small demo, but it is the property the big platforms structurally cannot offer - the protocol is the interoperability layer, not one vendor's goodwill.

## The part nobody wants to fund

Here is the uncomfortable bit, and it is where this story gets political in a way security people should pay attention to. Amandine, the Matrix.org Foundation's acting Managing Director, put it plainly: Matrix is free to use, "it is not free to maintain." The Foundation is a non-profit that exists to steward the specification, run the matrix.org homeserver, host bridges, and handle trust and safety - and it runs on donations and membership.

Sovereignty, she said, "is only real if it is sustainable." That is the sentence I would tattoo on every government digital-sovereignty program. It is easy to fund features. It is politically awkward to fund the boring, unglamorous maintenance of the open standard underneath them - spec work, community management, advocacy, trust and safety. If fifteen governments each deploy Matrix and none of them fund the Foundation, they have built their sovereignty on a volunteer-maintained floor. The Foundation's membership program is the mechanism on the table, and the conference made the pitch explicitly. Watch whether the same governments that adopted the protocol start paying for it. That is the real test of whether this migration is serious.

## The ecosystem is not just Element

A pleasant surprise from the community track: the ecosystem around the spec has genuinely diversified.

- **Continuwuity**, a community-created homeserver, is 18 months old and already running 1,500 Matrix servers. The Foundation funded the maintainers' travel through a new community attendance sponsorship (backed by Famedly), and their talks were among the most popular of the event. A healthy protocol has more than one implementation, and this is the healthiest signal of the whole conference.
- **Matrix Wrench** - a multipurpose tool for community managers.
- **Gua** - an attempt to build a client with the simplicity of WhatsApp without giving up federation.
- The Rust rewrite of Element Web and the expanding Rust SDKs are speeding up the client side considerably.

The Foundation also previewed what is being called Matrix 2.0: custom profiles with transient states (in a meeting, on vacation), a reworked timeline model, and protocol security improvements. More than 25 hours of talks are on the conference watch page if you want the detail.

## What happens next

The community is co-hosting a Decentralised Messaging devroom at FOSDEM 2027 in Brussels (30-31 January) with the XMPP Standards Foundation and DeltaChat - notable in itself, because XMPP and Matrix have historically been rivals, and a shared devroom signals a shared adversary: the closed platforms. The next Matrix Conference will be in the Netherlands.

## Why this matters

I cover exploits because they are the sharp end of security. But the boring structural question - who owns the pipes your messages travel through - decides more in a crisis than any single vulnerability. The Starlink incident in Ukraine made that question un-ignorable, and the answer fifteen governments are converging on is an open, federated, end-to-end-encrypted protocol stewarded by a non-profit that most of them have not yet paid a cent to sustain.

That last clause is the story. Everything else is a detail.

---

*Sources: The Matrix Conference 2026 wrap-up on matrix.org (2026-10-30), This Week in Matrix 2026-11-06, and the European Commission's European Tech Sovereignty Package (June 2026). All quotes are from the wrap-up post and conference sessions.*
