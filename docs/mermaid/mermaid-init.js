// Render ```mermaid blocks. mdBook emits them as <code class="language-mermaid">;
// this swaps each for a <pre class="mermaid"> and lets the vendored Mermaid
// (docs/mermaid/mermaid.min.js, version and checksum in docs/mermaid/README.md)
// draw it in the theme the reader picked.
(function () {
  function darkTheme() {
    var cls = document.documentElement.classList;
    return cls.contains("coal") || cls.contains("navy") || cls.contains("ayu");
  }
  function render() {
    var blocks = document.querySelectorAll("code.language-mermaid");
    blocks.forEach(function (code) {
      var pre = document.createElement("pre");
      pre.className = "mermaid";
      pre.textContent = code.textContent;
      code.parentElement.replaceWith(pre);
    });
    mermaid.initialize({ startOnLoad: false, theme: darkTheme() ? "dark" : "neutral", securityLevel: "strict" });
    mermaid.run({ querySelector: "pre.mermaid" });
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", render);
  } else {
    render();
  }
})();
