---
layout: post
title: "Your Private Life Is Cheap to Buy and Expensive to Lose"
seo_title: "Data Brokers, Your Private Life, and AI in 2027"
author: Garrett Stimpson
date: 2026-11-26 11:30:00 -0500
categories: [privacy, investigations]
tags: [data-brokers, privacy, artificial-intelligence, ai, location-data, health-data, personal-data, opt-out]
excerpt: "Data brokers can package your movements, health interests, finances, family, and vulnerabilities for pennies a record. AI is about to make those fragments far more dangerous, which is why removal matters heading into 2027."
description: "An evidence-backed investigation of how data brokers collect and sell intimate personal details, what one person's data is really worth, how AI changes privacy risk in 2027, and how to remove your information."
permalink: /posts/2026/11/26/data-brokers-intimate-details-ai-2027/
---

There is a version of you for sale that you have never met.

It knows the address where you sleep. It knows the phone number you gave up in 2019, the people who live with you, the clinic you visited last spring, the building you walk into every Sunday morning. It knows what you buy at 1 a.m. and what you search for when nobody else is in the room. Some of it is wrong. That doesn't make it harmless, because a buyer who acts on a wrong conclusion can hurt you just as badly as one who acts on a right one.

I went into this investigation with a number stuck in my head, the same one you have probably seen: one person's data is supposedly worth almost **$300,000**. It sounds right. Our digital lives feel priceless. So I went looking for the source, and I couldn't find one. I traced enforcement records, broker purchases, and academic studies, and nowhere did that number hold up.

What I found instead is stranger, and honestly more disturbing. Individual records about real people sell for pennies. The machinery that stitches those pennies into a whole human being is worth a fortune. And the harm that falls on the person inside that profile is the one number nobody can put on a slide.

## The $300,000 claim doesn't survive contact with evidence

I want to be careful here, because I'm not claiming the figure has never appeared anywhere. I'm saying I found no accessible primary source showing that brokers pay, earn, or realize anything close to $300,000 for one person's data. If someone repeats that number at you, ask them for the source and the math. Watch what happens.

Part of the problem is that people smoosh four completely different things into one dramatic figure:

1. **Transaction price:** what a buyer actually pays for a record or dataset.
2. **Corporate revenue:** what a platform earns across millions of people.
3. **Economic value:** a modeled estimate of what data is worth to a company.
4. **Harm:** what happens to you when it's misused.

Those are not the same thing. A company making billions off a hundred million users is not evidence that your file alone is worth $300,000 any more than a casino's revenue means your single bet was a good one.

Here's what an actual observed price looks like. A [2023 Duke University study](https://techpolicy.sanford.duke.edu/data-brokers-and-the-sale-of-data-on-us-military-personnel/) had researchers approach data brokers selling information about U.S. military personnel. Active-duty service members, veterans, their families. Identified or identifiable records were advertised for roughly **US$0.12 to US$0.32 each**, sometimes with barely any screening.

Read that again. The home address of a serving soldier, connected to the fact that they serve, for about a quarter.

<figure>
  <img src="/assets/img/posts/data-broker-observed-prices.svg" alt="Graph showing an observed price range of 12 to 32 US cents for one military-related broker record, with arithmetic illustrations of 12 to 32 dollars for 100 records and 1,200 to 3,200 dollars for 10,000 records." loading="lazy">
  <figcaption><strong>Figure 1.</strong> Duke researchers reported military-related records advertised at US$0.12 to US$0.32 each in 2023. The 100-record and 10,000-record figures are arithmetic illustrations at that unchanged unit range, not additional observed transactions. The bars do not share one linear scale. Download the <a href="/assets/data/data-broker-observed-prices.csv">underlying CSV data</a>.</figcaption>
</figure>

And that's the paradox at the center of this whole story: your record is cheap because it's easy to copy, not because it doesn't matter. A digital file costs nothing to duplicate, so supply is effectively infinite and the price collapses. The thing being priced isn't you. It's a copy of you. The damage that copy can do has no relationship to what it sold for.

## What's actually being sold

"Personal data" is a bloodless phrase. The enforcement record is not.

When the FTC went after data broker [X-Mode Social and Outlogic](https://www.federalregister.gov/documents/2024/01/18/2024-00928/x-mode-social-inc-public-comment), the allegations included location data precise enough to identify visits to medical and reproductive-health clinics, places of worship, domestic-abuse shelters, and addiction-recovery facilities. Think about what that means in practice. Your phone quietly says you were at a pregnancy clinic for 40 minutes. A shelter. A meeting. The FTC's 2024 order barred the companies from selling or sharing precise location data in important circumstances.

The case against [Gravy Analytics and Venntel](https://www.federalregister.gov/documents/2024/12/06/2024-28738/gravy-analytics-inc-analysis-of-proposed-consent-order-to-aid-public-comment) followed the same shape: sensitive location information collected and sold without meaningful consent verification. The government's own analysis said the data could tie people to sensitive locations and expose them to discrimination, violence, and emotional distress.

Location is just the headline. A mature broker profile can include or infer your relatives and household, your old addresses, your income band, your debts, your purchases, your browsing interests, your health and pregnancy-related interests, your religion, your politics, your military affiliation. Not every broker holds every field, and the inferred labels are sometimes flat wrong. The danger isn't one field. It's scale, linkage, and persistence, plus the fact that a buyer will treat a probabilistic guess as settled fact.

## How fragments become a dossier

None of this arrives at the broker in one piece. Your phone app hands over a device identifier and a location. A retailer logs a purchase. A website fires advertising events. Public records contribute an address. A loyalty program ties a transaction to your email. A people-search site ties that email to your relatives and every home you've had. Someone buys the stitched result, enriches it, and sells it again.

Real-time advertising makes the copies multiply. The Irish Council for Civil Liberties, in its [investigation of real-time bidding](https://www.iccl.ie/digital-data/americas-hidden-security-crisis/), estimated that data about a U.S. person's online activity and location was broadcast in RTB systems hundreds of times per day on average. That's an estimate about broadcasts inside an ad ecosystem, not proof that every recipient keeps everything. But it tells you how often your data leaves the screen it started on, to places you have never heard of, under contracts you will never read.

So no, removing yourself from one visible people-search page does not call every copy home. The copies have copies.

## Why 2027 is the year this gets worse

Data brokers existed long before generative AI, and I want to be clear that AI did not invent this problem. What AI changes is the cost of doing something with the pile.

Ten years ago, joining messy datasets, classifying purchases into sensitive categories, or ranking a million people by predicted vulnerability took a data science team. Now it's a prompt. A capable system can help join inconsistent names, addresses, and devices across datasets. It can classify free text and browsing history into sensitive categories. It can predict traits nobody ever told it about. It can rank people for targeting, scrutiny, exclusion, or fraud. It can write a personalized message that uses real details from your profile. It can let an ordinary employee query millions of rows in plain English instead of SQL. And it can take an "anonymous" dataset and try to reidentify it against outside records.

The [NIST Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence) flags exactly these privacy risks: leakage of sensitive information, harmful inferences, and the difficulty of managing data across AI systems. NIST isn't saying every model can unmask every person, and neither am I. Reidentification depends on granularity, uniqueness, outside information, and access controls.

But there are two distinct harms here, and people usually only think of the first. An AI-derived conclusion might be accurate, revealing something you never chose to disclose. Or it might be wrong, and still quietly decide how you get treated.

My honest forecast for 2027: the risk isn't some cartoonish all-knowing AI. It's ordinary organizations, your employer, your insurer, a landlord, a scammer, getting cheap tools to search, summarize, score, and personalize data they already hold. The records and the pipelines are already built. AI just hands the keys to everyone at once.

## Why removal still matters

Data has legitimate uses. Fraud prevention, regulated credit decisions, research, and public-record access are not the same activity as selling a pregnant woman's clinic visits. The problem is that you can't see the chain, you can't correct false data, you don't know who received it, and you never consented to most of the downstream uses.

Removal won't make you invisible. I'm not going to pretend otherwise. But it adds friction, and friction matters. Every profile that doesn't exist is one an impersonator can't use against you. Suppressing your home address and relatives makes life harder for a stalker. Deleting broker records starves the AI-assisted linkage and targeting of inputs. Correcting a false profile stops a bad inference from propagating. And repeating the process limits the fresh copies that pile up.

Privacy isn't an on-off switch. Reducing exposure is worth doing even when perfect erasure is impossible.

## A practical removal plan

**See what's already exposed.** Search your exact name with your city, phone number, emails, old addresses, and common usernames. Check the people-search results. Keep URLs and screenshots for your own tracking, but don't republish the sensitive details.

**Cut collection at the source.** Delete unused accounts and apps. Review location, contacts, microphone, and photo permissions. Prefer "while using" location access when an app genuinely needs it. Turn off ad personalization and reset your advertising identifier. Downstream opt-outs can never compensate for continuous upstream collection, so this step does more than any removal request.

**Use the official universal tools.** If you live in California, the state runs a free [Delete Request and Opt-out Platform, DROP](https://privacy.ca.gov/drop/). Per the state, one request goes to more than 600 registered data brokers, which began processing requests on August 1, 2026 and must check the system at least every 45 days. Eligibility and implementation can change, so use the official site, not an imitation. If you're elsewhere, check your state or national privacy regulator for the deletion and opt-out rights you actually have.

**Opt out of the people-search sites.** Use each company's official suppression page. Keep a simple table: broker, URL, request date, confirmation number, recheck date. Give no more identity documentation than the process requires, and redact anything unrelated when you can.

**Protect what can't be deleted.** Unique passwords, multifactor authentication, a credit freeze where appropriate, a PIN on your mobile-carrier account. And treat unexpected messages that contain accurate personal details as untrusted. The accuracy is what makes a scam work; it doesn't make it legitimate.

**Recheck.** Broker ownership changes, public records update, apps collect again, and a suppressed profile can reappear under a new address or spelling. Quarterly is reasonable for most people. If you're facing stalking or harassment, skip the forms for now and get safety-focused help first.

Paid removal services can save you labor. No credible one promises permanent deletion from the entire ecosystem, and any that does is lying. Read what they cover, how often they rescan, and what they do with the information you hand them.

## What removal cannot promise

A removal request may hide a public profile without deleting internal, archival, legally retained, or already-transferred copies. Public records stay at their source. A recipient may be allowed to keep what they received. The verification process itself can require sharing information. Rights vary by where you live.

And if you are in immediate danger, your physical safety comes first. Account security, credit protection, and local professional help. Do not spend the first critical hours filling out dozens of broker forms.

## The real value of your data

I can't prove your data is worth $300,000, and I don't think anyone should use that figure without showing the source and the math.

What I can prove is more revealing. Identifiable records about sensitive populations have been offered for cents. Regulators have documented markets in precise location and visits to deeply personal places. Advertising systems broadcast behavioral data hundreds of times a day. And AI is making those fragments cheaper every quarter to join, search, infer from, and act on.

The buyer's price is not your value.

A list can sell for pennies and still expose a pregnancy, a medical scare, a faith, a military family, a frightened person looking for a shelter, or the address where your children sleep. That's why removal is worth considering. Not because it erases you, but because every unnecessary copy of you is one more decision about your life that somebody else gets to make.
