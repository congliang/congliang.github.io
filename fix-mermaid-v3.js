const fs = require("fs");
const path = require("path");
const dir = "source/_posts";

let total = 0;
let quoted = 0;

for (const file of fs.readdirSync(dir).filter(f => f.endsWith(".md"))) {
    const fp = path.join(dir, file);
    let content = fs.readFileSync(fp, "utf8");
    let modified = false;

    const regex = /```mermaid\n([\s\S]*?)```/g;
    let match;
    while ((match = regex.exec(content)) !== null) {
        let block = match[1];
        const original = block;

        // Quote ALL unquoted square bracket node labels
        // Pattern: [text] or ["text"] or [...] on arrow lines
        // We want to quote text that contains special chars: / - . : ( ) & < >
        let newBlock = block.replace(/\[([^\]]*?)\]/g, (full, text) => {
            // Already quoted
            if (text.startsWith('"') && text.endsWith('"')) return full;
            // Already in quotes (single)
            if (text.startsWith("'") && text.endsWith("'")) return full;
            // Check if it contains special chars that need quoting
            if (/[\/\-\.:\(\)&<>]/.test(text)) {
                quoted++;
                // Escape any internal double quotes
                text = text.replace(/"/g, "'");
                return '["' + text + '"]';
            }
            return full;
        });

        // Also quote round bracket nodes () containing special chars
        newBlock = newBlock.replace(/\(([^)]*?)\)/g, (full, text) => {
            if (text.startsWith('"') && text.endsWith('"')) return full;
            if (text.startsWith("'") && text.endsWith("'")) return full;
            if (/[\/\-\.:\(\)&<>]/.test(text)) {
                quoted++;
                return '("' + text + '")';
            }
            return full;
        });

        // Quote curly bracket nodes {} containing special chars
        newBlock = newBlock.replace(/\{([^}]*?)\}/g, (full, text) => {
            if (text.startsWith('"') && text.endsWith('"')) return full;
            if (text.startsWith("'") && text.endsWith("'")) return full;
            if (/[\/\-\.:\(\)&<>]/.test(text)) {
                quoted++;
                return '{"' + text + '"}';
            }
            return full;
        });

        if (newBlock !== original) {
            content = content.replace(match[0], "```mermaid\n" + newBlock + "```");
            modified = true;
            total++;
        }
    }

    if (modified) {
        fs.writeFileSync(fp, content, "utf8");
    }
}

console.log(`Fixed ${total} mermaid blocks, quoted ${quoted} nodes`);
