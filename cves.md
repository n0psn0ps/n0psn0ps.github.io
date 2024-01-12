---
layout: page
title: "CVEs"
permalink: /cves/
---

<ul>
  {% for cve in site.cves %}
    <li>
      <a href="{{ cve.url }}">{{ cve.title }}</a>
    </li>
  {% endfor %}
</ul>
