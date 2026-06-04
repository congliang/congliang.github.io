const fs = require("fs");
const path = require("path");
const dir = "source/_posts";

let count = 0;
for (const file of fs.readdirSync(dir).filter(f => f.endsWith(".md"))) {
    const fp = path.join(dir, file);
    let content = fs.readFileSync(fp, "utf8");

    // Skip if already has <!-- more --> tag
    if (content.includes("<!-- more -->") || content.includes("<!--more-->")) continue;

    // Find end of frontmatter (second ---)
    const lines = content.split("\n");
    let firstDash = -1, secondDash = -1;
    for (let i = 0; i < Math.min(lines.length, 50); i++) {
        if (lines[i].trim() === "---") {
            if (firstDash === -1) firstDash = i;
            else { secondDash = i; break; }
        }
    }

    if (secondDash === -1) {
        console.log("WARN: No frontmatter end in " + file);
        continue;
    }

    // Insert <!-- more --> after frontmatter (before the first content line)
    lines.splice(secondDash + 1, 0, "", "<!-- more -->");
    content = lines.join("\n");

    fs.writeFileSync(fp, content, "utf8");
    count++;
}

console.log("Added <!-- more --> to " + count + " articles");
