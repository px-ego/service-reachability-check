# AGENTS.md

本文件面向后续维护 `service-reachability-check` 的开发者和编码代理。除非产品负责人明确修改需求，否则保持以下行为和安全边界。

## 产品定位

本项目处理既有监控系统产生的“端口不可达”或“URL 不可达”飞书告警：

1. 过滤指定告警群和指定告警机器人。
2. 解析故障消息中的监控对象名称、原因和告警时间。
3. 使用路由表确定诊断类型、目标和负责人。
4. 通过 SSH 在 internal-probe 和 external-probe 分别探测。
5. 根据两侧证据给出谨慎的初步判断。
6. 只对异常、映射错误或运行错误发送飞书应用机器人通知。

它不是通用飞书机器人，不处理人工消息、其他机器人或非拨测内容。

## 固定产品规则

### 输入过滤

- 生产入口必须由 `pre_gateway_dispatch` 在 LLM 之前处理。
- 只处理配置群内、指定告警机器人发送、标题以 `监控告警:` 开头的消息。
- 只对 `[🔴 故障]` 或 `[发生故障]` 执行诊断。
- `[✅ 正常]`、`[恢复正常]`、人工消息、其他机器人、Hermes 自身和无关消息保持静默。
- 不得把计划、推理、命令、stdout JSON 或执行摘要回复到告警群。
- 保持消息去重，避免同一告警重复诊断。

### 告警结构

规范化输入：

```json
{
  "sender_name": "拨测通知机器人",
  "sender_id": "configured-id",
  "sender_type": "bot",
  "text": "监控告警: [🔴 故障] 示例HTTP服务\n\n[发生故障] Request timeout\n告警时间: 2026-01-01 10:00:00"
}
```

解析结果必须保留：

- `source_bot`
- `status`
- `monitor_name`
- `reason`
- `alert_time`
- `raw_text`

`alert_time` 使用告警机器人提供的时间，不用 Hermes 收到消息的时间替代。

### 路由

路由表是监控名称到诊断目标和负责人的唯一可信来源：

- 精确 `monitor_name` 优先于 `monitor_name_regex`。
- 正则使用完整字符串匹配。
- 多条规则命中返回 `route_conflict`。
- 未命中返回 `route_not_found`。
- 映射命中前不执行网络探测。
- 不从模糊标题猜测 URL、host 或 port。
- 每条路由必须配置诊断目标和 owners。
- 映射错误使用 `fallback.owners`。
- 负责人通过 `feishu_user_id_env` 引用当前飞书应用范围内的 Open ID。

HTTP 路由支持共享 `url` 或 internal/external `targets`。TCP 路由支持共享 `host`/`port` 或两侧 `targets`。

### 双侧探测

- Hermes 本机不直接探测目标。
- internal-probe 和 external-probe 必须都执行；单侧失败不阻断另一侧。
- TCP 使用 `tcping <host> <port>`。
- HTTP 使用无认证 curl，只检查最终状态码是否严格等于配置值，默认 `200`。
- 非成功状态码、超时、DNS、连接、TLS、SSH、命令缺失和命令失败都转成结构化失败。
- 重试次数、间隔和超时全部来自配置。
- 远程命令使用校验后的 argv 和安全 shell quoting，不拼接原始告警文本。

判定表：

| internal | external | 结果 |
| --- | --- | --- |
| 成功 | 成功 | 当前正常或瞬时抖动，不通知 |
| 成功 | 失败 | 更可能是外部访问路径问题 |
| 失败 | 成功 | 更可能是内部访问路径问题 |
| 失败 | 失败 | 更可能是服务、目标侧或共同依赖问题 |

文案只使用“更可能是”“建议优先检查”，不得声称已经确定根因。

### 飞书发送

需要通知：

- 至少一侧探测失败；
- probe 执行失败；
- 映射缺失或冲突；
- 配置加载或其他运行错误。

保持以下发送语义：

- 一次 fan-out 只获取一次 `tenant_access_token`。
- 群卡片优先回复原告警。
- 回复明确业务失败时才回退群顶层消息。
- 回复发生超时等不确定失败时不补发群消息，避免重复。
- 群卡片使用 Open ID 生成真实 `<at>`。
- 私聊卡片只显示负责人名称，不包含 `<at>`。
- 按去重后的负责人 Open ID 使用 `receive_id_type=open_id` 逐人私聊。
- 群消息和各私聊相互独立，单个失败不阻止其他发送。
- 不自动重试发送。
- 聚合结果不得暴露 Open ID、token、应用密钥或 webhook。

正常、恢复和被过滤消息不得发送群消息或私聊。

## 配置与敏感信息

配置优先级：

```text
CLI 参数 > 环境变量 > config/default.yaml
```

生产环境需要配置：

- 告警机器人 sender ID；
- 告警群 chat ID；
- 飞书应用 ID、密钥和域名；
- 两个 probe 的 SSH host、port、user 和私钥路径引用；
- 路由、目标、负责人和 fallback；
- 重试和超时。

不得提交或打包：

- `.env`
- 密码和私钥内容
- 应用密钥、token、webhook
- 真实 Open ID
- 本机绝对路径
- 真实环境日志和调试 payload

`SKILL.md`、README、示例配置和测试必须保持环境无关。正式运行配置只留在部署环境；交付 ZIP 由脱敏模板生成。

## 代码结构与接口

- `scripts/config_loader.py`：配置校验和 owner 环境变量解析。
- `scripts/feishu_event_parser.py`：来源过滤和消息解析。
- `scripts/alert_router.py`：路由匹配。
- `scripts/probe_executor.py`：SSH 和探测命令。
- `scripts/diagnosis_engine.py`：纯判定逻辑。
- `scripts/feishu_notify.py`：群/私聊卡片及 sender。
- `scripts/manual_diagnosis_pipeline.py`：端到端管线。
- `scripts/hermes_gateway_dispatch.py`：生产 gateway hook。
- `scripts/service_reachability_check.py`：CLI 和脱敏输出。
- `hermes-plugin/service-reachability-dispatch`：需要复制到 Hermes plugins 的入口插件。

兼容约束：

- `FeishuMessageBuildResult.payload` 始终表示群卡片。
- `FeishuMessageBuildResult.private_payload` 表示无群聊 @ 的私聊卡片。
- 保留旧 custom-bot webhook sender 供手动兼容。
- 生产 gateway 使用应用机器人 fan-out，不经过 LLM。
- CLI JSON 只用于日志和排查。

## 测试要求

每次行为变化至少覆盖：

- 故障、恢复、人工、其他机器人、Hermes 自身和无关消息；
- 标题完整与只含标题的告警；
- 精确、正则、缺失和冲突路由；
- HTTP/TCP 合法与非法目标；
- internal/external 四种判定组合；
- 重试和超时配置；
- 单侧失败不阻断另一侧；
- 群卡片真实 @、私聊卡片无 @；
- 多负责人去重；
- 群失败、单个私聊失败、token 失败和部分成功；
- 正常与恢复不调用任何 sender；
- CLI、日志和聚合结果脱敏；
- gateway 运行错误使用固定兜底负责人。

单元测试必须 mock SSH 和飞书网络请求。真实 SSH、真实飞书、真实 gateway 重启只在明确验收时执行。

完整测试：

```bash
python -m unittest discover -s tests
```

完成后使用 `skill-creator` 的 `quick_validate.py` 校验 Skill。

## 非目标

- 不实现定时循环或常驻调度器。
- 不自动修复。
- 不登录被监控目标机器。
- 不判断 HTTP 业务响应体。
- 不把全部 2xx 或 3xx 视为成功。
- 不做通用聊天或 Open ID 收集机器人。
- 不在仓库或发布包保存真实凭据。

## 交付维护

- 人类安装、配置和排障说明维护在 `README.md`。
- Hermes 执行契约维护在 `SKILL.md`。
- 产品与代码约束维护在本文件。
- 打包必须使用白名单，将 `config/*.example.yaml` 映射为发布包中的运行配置。
- 禁止直接压缩工作目录。
