---
layout: post
title: "I Open-Sourced My Data Broker Removal Tool So Nobody Has to Pay for Privacy"
seo_title: "f*ck_data_brokers: A Free, Open-Source Data Broker Removal Tool"
author: Garrett Stimpson
date: 2026-11-26 14:00:00 -0500
categories: [privacy, tools]
tags: [data-brokers, privacy, open-source, opt-out, data-removal, python, agent-garrett]
excerpt: "Removing your data from 600+ brokers normally costs a subscription. I open-sourced my removal tool so anyone who cannot afford that can still do it themselves, for free, on their own computer."
description: "f*ck_data_brokers is a free, open-source, one-file Python tool that writes legal deletion letters to 600+ registered data brokers on your behalf. Here is what it does, who it is for, and when the paid option is worth it."
permalink: /posts/2026/11/26/f-ck-data-brokers-open-source-removal/
---

Last week I wrote about what data brokers sell and what it costs you. A few people read it and asked the same question: okay, so how do I actually get out?

The honest answer has always had two parts. Part one: there are services, including mine, that do it for you for a subscription. Part two: if you cannot afford a subscription, you were mostly stuck spending your evenings filling out forms.

That second part bothered me. Privacy should not be a luxury good. So I did something about it.

## The tool

I put my removal tool on GitHub. It is called [f*ck_data_brokers](https://github.com/gary23w/f-ck_data_brokers), and it is one Python file with no dependencies, no account, and no subscription. Free, forever, MIT licensed.

It runs on your computer. Your details stay on your computer, in one file, in one folder. Delete the folder and it is all gone. Nothing is uploaded anywhere.

Here is what it actually does:

1. Pulls the list of registered data brokers, all 600 and more, from the California Privacy Protection Agency's public registry. You do not have to live in California to write to these companies.
2. Writes each one a real legal deletion and opt-out letter in your name, citing the law where you live.
3. Sends the letters from your own email, or hands them to you ready to send.
4. Reads the replies and tells you which excuse the broker is using and what to answer.
5. Chases the ones that go quiet, and tells you which regulator to complain to about the ones that refuse.

The tool is rude about data brokers. The letters are not. They are firm, correct, and legal, because the goal is to leave a broker with nothing to hide behind.

## How to use it

You need Python 3.8 or newer and an email address. That is the whole list.

Download `fuck_data_brokers.py`, open a terminal in that folder, and run:

```
python fuck_data_brokers.py
```

You get a menu. Walk down it. Tell it who you are, get the broker list, write the letters (it does 20 at a time so you do not get buried), send them, and then come back when brokers start replying. Because they will reply, and some of the replies are pure theater.

The tool translates it for you. "We received your request" means a robot said hello. "Please send your ID" means a seller of personal data is asking for more personal data, and the tool writes your refusal for you. "We cannot process this" means they refused and hoped you would go away, so it writes one more answer and then a final notice with seven days to act. After that it points you at the privacy regulator for your law and shows you how to file. Regulators read those.

It will never send your street address, your birthday, or your ID. It will never click a link in a broker's email. It will never get past a CAPTCHA for you, and it will never tell you that you are deleted when all it knows is that a letter was sent. If you use an AI assistant with it, it is told to ask before sending anything and never invent your details.

## The catch, and I will not pretend there is not one

The tool is free. It is also work.

Six hundred companies, their excuses, their forms, their silence. And then, next month, some of them collect you again, because collecting is their entire business. You will come back now and then, pick "Chase the quiet ones," and keep at it. Removal is not one letter. It is the letter that never stops coming.

If you have the time and the stubbornness, that is fine. A lot of people do not.

## When the subscription is worth it

I am not going to pretend my own service is not the better option, because it is. [Agent Garrett](https://agent.garrettstimpson.ca) does everything above, continuously, without you. Set it and forget it. Persistence is guaranteed, and I mean that as a promise, not a slogan: it does not get bored, does not get tired, and does not take "use our form" for an answer. A broker can stall a person for months. It cannot outlast a machine that never stops asking.

So the honest breakdown is:

- **Cannot afford a subscription, or want to stay off payment systems entirely:** use the tool. It is exactly why I released it.
- **Can afford it and want this handled forever:** sign up and never think about it again.

Both paths end in the same place. One of them just does not need you to show up every month.

## One more thing

Every star on the repository is one more person these companies have to answer. It costs you one click. It costs them a compliance department.

If you use the tool, tell someone else about it. Privacy works a little better when it is not a solo fight.

The code is at [github.com/gary23w/f-ck_data_brokers](https://github.com/gary23w/f-ck_data_brokers). Take it, change it, share it. That is the point.
