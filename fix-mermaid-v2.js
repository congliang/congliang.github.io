const fs = require("fs");
const path = require("path");
const dir = "source/_posts";

let total = 0;
let styleRemoved = 0;
let colonFixed = 0;
let specialFixed = 0;

for (const file of fs.readdirSync(dir).filter(f => f.endsWith(".md"))) {
    const fp = path.join(dir, file);
    let content = fs.readFileSync(fp, "utf8");
    let modified = false;

    // Find all mermaid blocks
    const regex = /```mermaid\n([\s\S]*?)```/g;
    let match;
    while ((match = regex.exec(content)) !== null) {
        let block = match[1];
        const original = block;
        const lines = block.split("\n");
        const newLines = [];

        for (let line of lines) {
            // 1. Remove style lines (not supported by some Mermaid renderers)
            if (/^\s*style\s+\w+\s+/.test(line.trim())) {
                styleRemoved++;
                continue; // skip this line
            }

            // 2. Fix unquoted nodes with special chars: & < > "
            // Only applies to lines with --> between nodes
            if (line.includes("-->")) {
                // Replace & in node text (Mermaid uses & for special things)
                line = line.replace(/\[([^\]]*?)&([^\]]*?)\]/g, (m, a, b) => `["${a}&${b}"]`);
                line = line.replace(/\(([^)]*?)&([^)]*?)\)/g, (m, a, b) => `("${a}&${b}")`);
                line = line.replace(/\{([^}]*?)&([^}]*?)\}/g, (m, a, b) => `{"${a}&${b}"}`);

                // Fix unquoted square bracket nodes with : or /
                line = line.replace(/\[([^\]"]+:[^\]]*?)\]/g, (m, txt) => {
                    if (txt.includes('"')) return m; // already quoted
                    colonFixed++;
                    return `["${txt}"]`;
                });

                // Fix < and > in unquoted nodes
                line = line.replace(/\[([^\]]*?[<>][^\]]*?)\]/g, (m, txt) => {
                    if (txt.includes('"')) return m;
                    specialFixed++;
                    return `["${txt}"]`;
                });
            }

            newLines.push(line);
        }

        block = newLines.join("\n");
        if (block !== original) {
            content = content.replace(match[0], "```mermaid\n" + block + "```");
            modified = true;
            total++;
        }
    }

    if (modified) {
        fs.writeFileSync(fp, content, "utf8");
    }
}

console.log(`Fixed ${total} mermaid blocks:`);
console.log(`  Style lines removed: ${styleRemoved}`);
console.log(`  Colons in nodes fixed: ${colonFixed}`);
console.log(`  Special chars fixed: ${specialFixed}`);
