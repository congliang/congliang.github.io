const fs = require("fs");
const path = require("path");
const dir = "source/_posts";
const MAX_LEN = 120;

let trimmed = 0;
for (const file of fs.readdirSync(dir).filter(f => f.endsWith(".md"))) {
    const fp = path.join(dir, file);
    let content = fs.readFileSync(fp, "utf8");
    const descMatch = content.match(/^description:\s*(.+)$/m);
    if (!descMatch) continue;

    let desc = descMatch[1].trim();
    if (desc.length <= MAX_LEN) continue;

    // Trim at last period/comma/semicolon within limit
    let cut = desc.lastIndexOf("。", MAX_LEN);
    if (cut < 80) cut = desc.lastIndexOf("，", MAX_LEN);
    if (cut < 80) cut = desc.lastIndexOf("；", MAX_LEN);
    if (cut < 80) cut = desc.lastIndexOf("、", MAX_LEN);
    if (cut < 80) cut = MAX_LEN;

    desc = desc.substring(0, cut + 1);
    content = content.replace(descMatch[1].trim(), desc);
    fs.writeFileSync(fp, content, "utf8");
    trimmed++;
    if (trimmed <= 5) console.log(file + ": " + descMatch[1].trim().length + " -> " + desc.length + " chars");
}

console.log("Trimmed " + trimmed + " descriptions to " + MAX_LEN + " chars max");
