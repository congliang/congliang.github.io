const fs = require("fs");
const path = require("path");

// Get all source .md files
const dir = "source/_posts";
const sourceFiles = new Set(fs.readdirSync(dir).filter(f => f.endsWith(".md")).map(f => f.replace(".md", "")));

// Get all posts from db.json
const db = require("./db.json");
const posts = db.models?.Post || [];
const dbTitles = new Set(posts.map(p => p.source?.replace(/^_posts\//, "").replace(/\.md$/, "")));

// Find source files not in db
const missing = [...sourceFiles].filter(f => !dbTitles.has(f));
console.log("Missing from db:", missing.length);
missing.forEach(f => console.log("  -", f));

// Check each missing file for frontmatter issues
for (const name of missing) {
    const fp = path.join(dir, name + ".md");
    if (!fs.existsSync(fp)) continue;
    const content = fs.readFileSync(fp, "utf8");
    const lines = content.split("\n");
    const frontStart = lines.findIndex(l => l.trim() === "---");
    const frontEnd = lines.slice(frontStart + 1).findIndex(l => l.trim() === "---") + frontStart + 1;
    console.log("\n" + name + " frontmatter:");
    console.log(lines.slice(frontStart, frontEnd + 1).join("\n"));
}
