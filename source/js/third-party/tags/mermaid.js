/* global mermaid */

(function() {
  var CDN = 'https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.9.0/mermaid.min.js';

  function init() {
    var pres = document.querySelectorAll('pre.mermaid');
    if (!pres.length) return;

    // Convert pre.mermaid to div.mermaid for Mermaid to process
    pres.forEach(function(pre) {
      var div = document.createElement('div');
      div.className = 'mermaid';
      div.textContent = pre.textContent;
      pre.parentNode.replaceChild(div, pre);
    });

    function render() {
      mermaid.initialize({ startOnLoad: false, theme: 'default', flowchart: { curve: 'linear' } });
      mermaid.init(undefined, document.querySelectorAll('.mermaid'));
    }

    if (window.mermaid) {
      render();
    } else {
      var s = document.createElement('script');
      s.src = CDN;
      s.onload = render;
      s.onerror = function() { console.warn('Mermaid CDN failed'); };
      document.head.appendChild(s);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
  document.addEventListener('page:loaded', init);
})();
