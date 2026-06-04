@echo off
cd /d %~dp0
echo Fixing all Mermaid nodes with special characters...
node -e "const fs=require('fs');const p=require('path');const d='source/_posts';let c=0;for(const f of fs.readdirSync(d).filter(x=>x.endsWith('.md'))){const fp=p.join(d,f);let con=fs.readFileSync(fp,'utf8');const re=/'''mermaid\n([\s\S]*?)'''/g;let m,mod=false;while((m=re.exec(con))!==null){let blk=m[1];const orig=blk;blk=blk.replace(/\[([^\]]*?)\]/g,(full,txt)=>{if(txt.startsWith('\"')||txt.startsWith(\"'\"))return full;if(/[\/!&<>]/.test(txt)){c++;return'[\"'+txt.replace(/\"/g,\"'\")+'\"]'}return full});if(blk!==orig){con=con.replace(m[0],'``\`mermaid\n'+blk+'``\`');mod=true}}if(mod)fs.writeFileSync(fp,con,'utf8')}console.log('Fixed '+c+' nodes')"
echo Done!
pause
