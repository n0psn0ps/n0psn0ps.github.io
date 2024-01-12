---
layout: page
title: "CVEs"
permalink: /cves/
---

<ul>
  {% for post in site.cves %}
    <li>
      <a href="{{ cves.url }}">{{ cves.title }}</a>
    </li>
  {% endfor %}
</ul>
