const fs = require("fs");
const path = require("path");
const dir = "source/_posts";
let nodeCount = 0;
let fileCount = 0;

for (const file of fs.readdirSync(dir).filter(f => f.endsWith(".md"))) {
    const fp = path.join(dir, file);
    let content = fs.readFileSync(fp, "utf8");
    const regex = /```mermaid\n([\s\S]*?)```/g;
    let match;
    let modified = false;

    while ((match = regex.exec(content)) !== null) {
        let block = match[1];
        const original = block;

        // Quote all unquoted square-bracket nodes containing / ! & < >
        block = block.replace(/\[([^\]]*?)\]/g, (full, text) => {
            if (text.startsWith('"') || text.startsWith("'")) return full;
            if (/[\/!&<>]/.test(text)) {
                nodeCount++;
                return '["' + text.replace(/"/g, "'") + '"]';
            }
            return full;
        });

        if (block !== original) {
            content = content.replace(match[0], "```mermaid\n" + block + "```");
            modified = true;
        }
    }

    if (modified) {
        fs.writeFileSync(fp, content, "utf8");
        fileCount++;
        console.log("Fixed: " + file);
    }
}

console.log("Done. Fixed " + nodeCount + " nodes in " + fileCount + " files.");
