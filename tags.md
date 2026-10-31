---
layout: page
title: Tags
permalink: /tags/
toc: false
description: "Every tag used across the research posts on garrettstimpson.ca, each linked to the posts that use it. Browse by topic for the main research areas."
---

<p class="text-muted">Browse research by topic — {{ site.tags | size }} tags across {{ site.posts | size }} posts. For the main research areas, see <a href="{{ '/topics/' | relative_url }}">topics</a>.</p>

{%- assign sorted_tags = site.tags | sort -%}

<div class="tag-cloud">
{%- for tag in sorted_tags -%}
  <a class="tag tag-link" href="#tag-{{ tag[0] | slugify }}">{{ tag[0] }} <span class="tag-count">{{ tag[1] | size }}</span></a>
{%- endfor -%}
</div>

{%- for tag in sorted_tags -%}
<h2 id="tag-{{ tag[0] | slugify }}" class="tag-section">// {{ tag[0] }}</h2>
<ul class="tag-posts">
  {%- for post in tag[1] -%}
  <li><span class="tag-post-date">{{ post.date | date: "%Y.%m.%d" }}</span><a href="{{ post.url | relative_url }}">{{ post.title | escape }}</a></li>
  {%- endfor -%}
</ul>
{%- endfor -%}
