const fs = require("fs");
const path = require("path");

const fixes = {
  "MSSQL-CLR-Assembly-Privilege-Escalation.md": ["MSSQL CLR 程序集利用 — 从数据库权限到命令执行——渗透测试实战笔记，含完整攻击链路与防御方案。", "MSSQL CLR 程序集提权全流程实战。通过 SQL Server CLR 集成功能，编译 .NET DLL 创建自定义存储过程，以 SQL Server 服务账户身份执行系统命令，实现从数据库权限到操作系统命令执行的权限提升。"],
  "SRC-recon-asset-discovery.md": ["SRC 挖洞第一步：信息收集与资产梳理——渗透测试实战笔记，含完整攻击链路与防御方案。", "SRC 挖洞前置工作全记录。从根域名开始，子域名爆破、证书透明日志、空间搜索引擎、Web 指纹识别、API 接口发现、JS 敏感信息提取、GitHub 泄露监控，一步步把目标资产理清楚。"],
  "VulnHub-DC3-Joomla-SQL-Injection.md": ["VulnHub DC-3 靶机笔记 — Joomla 注入拿后台——渗透测试实战笔记，含完整攻击链路与防御方案。", "VulnHub DC-3 靶机渗透实战。通过 JoomScan 识别 CMS 版本后，利用 Joomla 3.7.0 SQL 注入漏洞（CVE-2017-8917）枚举数据库、获取用户凭据，最终 John 破解密码登录后台。"],
  "VulnHub-DC7-DC8-Pentest-Report.md": ["VulnHub DC7 & DC8 靶机笔记 — Drupal 漏洞链实战——渗透测试实战笔记，含完整攻击链路与防御方案。", "独立完成 VulnHub DC7 和 DC8 两台靶机的完整渗透测试，涵盖信息收集、漏洞利用、Getshell、权限提升全流程。"],
  "iptables-firewall-ftp-config.md": ["Linux 防火墙管理：iptables 基础与 vsftpd 配置——渗透测试实战笔记，含完整攻击链路与防御方案。", "实训笔记：iptables 防火墙规则管理（链、表、规则增删改），multiport 模块实战，vsftpd FTP 服务配置（主动/被动模式），以及 iptables 规则持久化。"],
  "pentestools.md": ["渗透工具常用命令速查（个人笔记）——渗透测试实战笔记，含完整攻击链路与防御方案。", "渗透测试常用工具速查，按信息收集、Web扫描、漏洞利用、密码攻击、后渗透分阶段整理，每条命令标注适用场景和风险注意。"],
  "xss-tips.md": ["XSS 绕过 WAF 的几个思路——渗透测试实战笔记，含完整攻击链路与防御方案。", "记录几种实际挖 SRC 时遇到的 XSS 绕过 WAF 手法，包括大小写混写、双写、编码绕过、标签属性组合、onerror 变体等。"],
};

const dir = "source/_posts";
for (const [file, [old, neu]] of Object.entries(fixes)) {
    const fp = path.join(dir, file);
    let content = fs.readFileSync(fp, "utf8");
    if (content.includes(old)) {
        content = content.replace(old, neu);
        fs.writeFileSync(fp, content, "utf8");
        console.log("Fixed: " + file);
    } else {
        console.log("NOT FOUND in " + file + ": " + old.substring(0, 60));
    }
}
