---
layout: page
title: "¿Un qué? Un Café"
icon: fas fa-coffee
order: 5
---

<p id="msg" style="font-weight:600;margin-top:2rem">
  Redirigiéndote a Buy&nbsp;Me&nbsp;a&nbsp;Coffee… ✨
</p>

<script>
  /* 1 s: cambia el texto */
  setTimeout(() => {
    document.getElementById('msg').textContent =
      '¡Que sea un doble americano, pls! ';
  }, 1000);

  /* 2 s: salta a tu página de donaciones */
  setTimeout(() => {
    window.location.replace('https://buymeacoffee.com/kesero');
  }, 2000);
</script>

<!-- Fallback para navegadores sin JS -->
<noscript>
  <meta http-equiv="refresh" content="2; url=https://buymeacoffee.com/kesero">
</noscript>
