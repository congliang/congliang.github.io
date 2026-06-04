const fs = require("fs");
const path = require("path");
const dir = "source/_posts";

let mermaidFixed = 0;
let brFixed = 0;
let emojiFixed = 0;
let styleFixed = 0;

for (const file of fs.readdirSync(dir).filter(f => f.endsWith(".md"))) {
    const fp = path.join(dir, file);
    let content = fs.readFileSync(fp, "utf8");
    let modified = false;

    // Find all mermaid blocks
    const mermaidRegex = /```mermaid\n([\s\S]*?)```/g;
    let match;
    while ((match = mermaidRegex.exec(content)) !== null) {
        let block = match[1];
        const original = block;

        // 1. Remove `<br/>` tags inside mermaid nodes (replace with space)
        if (block.includes("<br/>") || block.includes("<br>") || block.includes("<br />")) {
            block = block.replace(/<br\s*\/?>/g, " ");
            brFixed++;
        }

        // 2. Remove emoji characters from mermaid blocks
        const emojiRegex = /[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F900}-\u{1F9FF}\u{1FA00}-\u{1FA6F}\u{1FA70}-\u{1FAFF}]/gu;
        if (emojiRegex.test(block)) {
            block = block.replace(emojiRegex, "");
            emojiFixed++;
        }

        // 3. Remove `style ...` lines (unsupported in older Mermaid)
        if (/^style\s+\w+\s+/.test(block)) {
            block = block.replace(/^style\s+\w+\s+.*$/gm, "");
            styleFixed++;
        }

        // 4. Fix chinese punctuation in node IDs - wrap in quotes if needed
        // Already handled by default encoding in Hexo

        if (block !== original) {
            content = content.replace(match[0], "```mermaid\n" + block + "```");
            modified = true;
            mermaidFixed++;
        }
    }

    if (modified) {
        fs.writeFileSync(fp, content, "utf8");
    }
}

console.log(`Fixed ${mermaidFixed} mermaid blocks across files`);
console.log(`  - HTML tags removed: ${brFixed}`);
console.log(`  - Emoji removed: ${emojiFixed}`);
console.log(`  - Style lines removed: ${styleFixed}`);
