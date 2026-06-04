const fs = require("fs");
const path = require("path");
const dir = "source/_posts";
let count = 0;
for (const file of fs.readdirSync(dir).filter(f => f.endsWith(".md"))) {
    const fp = path.join(dir, file);
    let content = fs.readFileSync(fp, "utf8");
    const lines = content.split("\n");
    const startIdx = lines.findIndex(l => l.trim() === "---");
    const endIdx = lines.slice(startIdx + 1).findIndex(l => l.trim() === "---") + startIdx + 1;
    const fmLines = lines.slice(startIdx + 1, endIdx);
    let seenDesc = false;
    const newFmLines = [];
    for (const line of fmLines) {
        if (/^\s*description:/.test(line)) {
            if (!seenDesc) {
                newFmLines.push(line);
                seenDesc = true;
            }
        } else {
            newFmLines.push(line);
        }
    }
    if (newFmLines.length !== fmLines.length) {
        lines.splice(startIdx + 1, fmLines.length, ...newFmLines);
        fs.writeFileSync(fp, lines.join("\n"), "utf8");
        count++;
    }
}
console.log("Fixed duplicates in " + count + " files");
