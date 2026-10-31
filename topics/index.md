---
layout: page
title: Topics
description: "Research on garrettstimpson.ca grouped by topic: Linux kernel, Windows, malware, web, network, hardware, embedded, cloud, AI and defense."
permalink: /topics/
---

<p class="text-muted">{{ site.posts | size }} posts grouped into {{ site.data.topics | size }} topics. A post can sit in more than one topic. Every individual tag is listed on the <a href="{{ '/tags/' | relative_url }}">tags page</a>.</p>

<ul class="topic-list">
{%- for topic in site.data.topics -%}
  {%- include topic-posts.html slug=topic.slug -%}
  <li class="topic-item">
    <h2 class="topic-name"><a href="{{ '/topics/' | append: topic.slug | append: '/' | relative_url }}">{{ topic.name }}</a> <span class="tag-count">{{ topic_posts.size }}</span></h2>
    <p>{{ topic.description }}</p>
  </li>
{%- endfor -%}
</ul>
