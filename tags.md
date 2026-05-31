---
layout: page
title: Tags
permalink: /tags/
---

<p class="text-muted">Browse research by topic — {{ site.tags | size }} tags across {{ site.posts | size }} posts.</p>

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
