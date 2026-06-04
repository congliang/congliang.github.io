// Hexo filter: fix mermaid selector to work with highlight.js wrapping
// This patches the Next theme's mermaid.js to find pre.mermaid elements

const fs = require('fs');
const path = require('path');

hexo.extend.filter.register('after_generate', function () {
    const mermaidJsPath = path.join(hexo.public_dir, 'js', 'third-party', 'tags', 'mermaid.js');

    if (!fs.existsSync(mermaidJsPath)) {
        hexo.log.warn('[fix-mermaid] mermaid.js not found at ' + mermaidJsPath);
        return;
    }

    let content = fs.readFileSync(mermaidJsPath, 'utf8');

    // Fix: querySelectorAll to match both pre.mermaid and pre > .mermaid
    if (content.includes("pre > .mermaid")) {
        content = content.replace(
            "pre > .mermaid",
            "pre.mermaid, pre > .mermaid, pre > code.mermaid"
        );
        fs.writeFileSync(mermaidJsPath, content, 'utf8');
        hexo.log.info('[fix-mermaid] Patched selector in mermaid.js');
    } else if (content.includes("pre.mermaid, pre > .mermaid")) {
        hexo.log.info('[fix-mermaid] Already patched');
    } else {
        hexo.log.warn('[fix-mermaid] Unknown mermaid.js format, selector not found');
    }
});
