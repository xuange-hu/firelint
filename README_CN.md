# firelint

[![tests](https://img.shields.io/badge/tests-109-brightgreen)](https://github.com/xuange-hu/firelint/actions)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![deps](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](https://github.com/xuange-hu/firelint/blob/main/pyproject.toml)

**零依赖的主机防火墙规则审计器：iptables / nftables / ufw 三格式通吃。**
三遍扫描——规则行、链默认值、文件与协议族之间的关系——每条结论都指向具体行号与原始文本。

```console
$ firelint scan rules.v4
CRITICAL FWL201  INPUT default policy is ACCEPT: unmatched packets are allowed
         at rules.v4:2 (offset 22, len 24)
         saw: :INPUT ACCEPT [0:0]
         fix: Set the INPUT policy to DROP and allow explicitly: `iptables -P INPUT DROP` / `policy drop;` / `ufw default deny incoming`.
...
42 finding(s) across 4 ruleset(s): 9 critical, 3 high, 23 medium, 7 low
```

## 为什么还需要一个防火墙审计工具？

现有工具分三类，没有一类干得了这件事：

| | 是什么 | 缺什么 |
|---|---|---|
| `iptables -L -n` | 现场状态 | 只说规则「是什么」，不说「哪里错了」|
| 防火墙 UI / 云控制台 | 逐条编辑 | 没有跨规则推理：遮蔽、默认策略、IPv6 缺口 |
| 重型审计套件 | agent + 服务端 + 看板 | 在你刚接手的那台机器上根本跑不动 |

firelint 是一个**运行时零依赖**的单 Python 包。它读一份规则转储——任何机器
都能产出的东西，包括那些 `apt` 已成回忆的机器——离线推理。CI 里能跑，堡垒机
上能跑，应急响应的 shell 里能跑，编辑器 agent 里也能跑。

## 三步跑通

```console
# 1. 安装（无任何依赖需要解析）
pip install git+https://github.com/xuange-hu/firelint

# 2. 在目标机上导出规则（任选其一）
iptables-save > rules.v4
nft list ruleset > ruleset.nft
ufw status verbose > ufw.txt

# 3. 审计
firelint scan rules.v4 ruleset.nft ufw.txt
```

零配置、无守护进程、不发一个网络包。

## 三遍扫描

**`lines` 逐条规则**——这一行暴露了什么？管理端口对 anywhere 开放（FWL102）、
无状态放行（FWL105）、任意源 DNAT（FWL107）、只按源端口过滤（FWL106）。

**`chains` 链默认值与顺序**——INPUT 默认策略 ACCEPT（FWL201）、被无条件
verdict 压住永远匹配不到的死规则（FWL203）、挂了 hook 却没写 policy 的链
（FWL204：nftables 对这种链默认 ACCEPT）、记了日志却照样放行（FWL207）。

**`relations` 文件之间与协议族之间**——只有 IPv4 规则、IPv6 毫无约束
（FWL301：防火墙没错，只是看错了协议族）、ufw 与裸 iptables 在同一批表里
打架（FWL302）、iptables 与 nftables 双栈共存（FWL303）、`ufw inactive`
却列着一堆放行规则（FWL304）。

20 条规则，每条都有「为什么重要」和具体修法：
[`docs/rules.md`](docs/rules.md)。规则允许重叠是设计——一个暴露端口既是暴露
问题又是无状态放行问题，两个问题值得分开跟踪。

## 支持的格式

| 格式 | 导出命令 | 说明 |
|---|---|---|
| iptables-save | `iptables-save` / `ip6tables-save` | filter/nat/mangle/raw 全表 |
| nftables | `nft list ruleset` | `ip`/`ip6`/`inet` 族、内联集合、`dnat to` |
| ufw | `ufw status verbose` | status、logging、默认策略、放行/拒绝行、`(v6)` 行 |

解析器读不懂的行会变成 **FWL109 结论**，绝不会被静默跳过——「审计器漏看了我
半份规则」比「审计器看不懂一行」严重得多。

## 证据式结论

每条结论都带文件、行号、偏移、长度和它判定的原始文本：

```console
HIGH     FWL301  every rule in scope is IPv4; nothing constrains IPv6, which the kernel still accepts by default
         at rules.v4:6 (offset 78, len 44)
         saw: -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
         fix: Mirror the policy for IPv6 (ip6tables / `table ip6` / `table inet`), or disable IPv6 explicitly if it is unused.
```

结论是用来十秒钟人工复核的，不是让你盲信的。

## CI 集成

```console
firelint scan rules.v4 --fail-on high          # high/critical 即 exit 1
firelint scan rules.v4 --format sarif > firelint.sarif
```

退出码：`0` 干净（或低于 `--fail-on` 门槛）、`1` 门禁触发、`2` 用法错误。
`--fail-on none` 永远返回 0——只收集输出的 `--format json` 调用请加上它。

## MCP 服务（Claude Code / Cursor / Cline）

六个工具——`firelint_scan`、`firelint_demo`、`firelint_rules`、
`firelint_explain`、`firelint_parse`、`firelint_defaults`：

```console
uvx --from "git+https://github.com/xuange-hu/firelint" --with "mcp>=1.2,<2" firelint-mcp
```

MCP 客户端配置：

```json
{
  "mcpServers": {
    "firelint": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/xuange-hu/firelint", "--with", "mcp>=1.2,<2", "firelint-mcp"]
    }
  }
}
```

服务端刻意钉住 `mcp>=1.2,<2`：mcp 2.x 把 `FastMCP` 改了名也换了导入路径。

## 演示

```console
$ firelint demo
```

跑内置语料——一份粗心的防火墙、四份转储——20 条规则全部命中（42 条结论：
9 critical、3 high、23 medium、7 low）。语料内嵌在包里并被测试钉住，
演示永远不会与规则脱节。

## 设计说明

- **零依赖是特性不是炫技。** 审计必须能在被审计的机器上跑。`pip install firelint`
  不拉取任何第三方包。
- **统一归一化模型。** 三种方言解析成同一种规则形状（verdict、协议、地址、端口、
  状态、接口）；规则引擎从不按语法分叉。
- **确定性。** 同输入同输出，字节级一致。无 LLM、无网络、不看时钟。
- **退出码契约有测试**，两个方向都用真实文件断言。

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
