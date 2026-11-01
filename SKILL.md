---
name: service-reachability-check
description: Handle Feishu “端口不可达” and “URL 不可达” probe alerts in Hermes by filtering the configured alert bot, resolving targets and owners, diagnosing from internal and external probes, and notifying only on abnormal or failed handling. Use for automatic reachability-alert diagnosis, manual normalized-event validation, route troubleshooting, and deployment handoff of this workflow.
---

# Service Reachability Check

把本 Skill 用于“端口不可达”或“URL 不可达”类拨测告警。不要把它当作通用群聊机器人。入口说明见 [README.md](README.md)，配置、安装和故障排查见 [docs/deployment.md](docs/deployment.md)，当前代码的行为边界见 [docs/architecture.md](docs/architecture.md)。

## 输入与静默规则

只接受 Hermes 传入的规范化飞书事件：

```json
{
  "sender_name": "configured alert bot",
  "sender_id": "configured sender id",
  "sender_type": "bot",
  "text": "监控告警: [🔴 故障] <monitor name>\n<reason and alert time>"
}
```

按以下顺序处理：

1. 先校验告警群、发送者身份和标题格式。
2. 忽略人工消息、其他机器人、Hermes 自身消息和无关内容。
3. 恢复或正常消息不诊断、不通知。
4. 故障消息先解析，再查路由；路由命中前不得执行探测。

生产入口由 `pre_gateway_dispatch` 在 LLM 之前拦截。指定群内检查 bot 身份和 sender ID；手动 CLI 的解析器支持名称或 ID 匹配，不替代生产入口鉴权。不得把计划、推理、命令、stdout JSON 或执行摘要回复到告警群。CLI 的 JSON 仅用于日志和排查。

## 路由契约

从部署指定的路由 YAML 读取监控对象、诊断目标和负责人：

- 精确 `monitor_name` 优先于 `monitor_name_regex`。
- 多条规则命中时报映射冲突，不随机选择。
- 未命中时报映射缺失，不猜测目标。
- `tcp` 路由配置 host 和 port。
- `http` 路由配置完整的 HTTP 或 HTTPS URL。
- 可为 internal/external 配置不同目标，也可配置相同目标以仅区分网络视角。
- 负责人使用 `feishu_user_id_env` 引用当前飞书应用范围内的 Open ID。不得把 Open ID 直接写入版本化配置。
- 映射错误使用 `fallback.owners`；运行时错误使用约定的兜底负责人环境变量。

加载配置后，环境变量引用会解析为兼容字段 `feishu_user_id`。不要在日志或 CLI 输出中暴露解析后的标识。

## 双侧探测

必须通过 SSH 分别在 internal-probe 和 external-probe 执行探测；不要在 Hermes 本机直接探测目标。

- TCP：执行 `tcping <host> <port>`。
- HTTP：执行无认证 `curl`，只检查返回的状态码是否严格等于配置的成功状态码，默认 `200`。当前命令不跟随重定向、不读取业务响应体。
- 非配置成功状态码、超时、DNS、连接、TLS、SSH、命令缺失或命令失败均为探测失败。
- 两侧按 internal、external 顺序执行；一侧失败不得阻止另一侧。
- 重试次数、重试间隔和超时都来自配置，不得在业务逻辑中硬编码。
- 远程命令必须由受校验参数安全构造，不得拼接原始告警文本。

判定规则：

- internal 成功、external 成功：更可能已恢复或瞬时抖动，保持静默。
- internal 成功、external 失败：更可能是外部访问路径问题。
- internal 失败、external 成功：更可能是内部访问路径问题。
- 两侧都失败：更可能是服务、目标侧或共同依赖问题。

结论使用“更可能是”和“建议优先检查”，并保留两侧证据。

## 飞书通知

只对以下结果构建并发送应用机器人卡片：

- 至少一侧探测失败的异常诊断；
- 映射缺失或冲突；
- probe、配置加载或其他运行错误。

一次通知使用同一个 `tenant_access_token`：

1. 优先回复原告警；只有明确的飞书业务失败才回退为群顶层消息。回复发生超时等不确定失败时不得补发群消息，以免重复。
2. 群卡片用 Open ID 生成真实 `<at>` 标签。
3. 使用 `receive_id_type=open_id` 给去重后的每位负责人发送无 `<at>` 的私聊卡片。
4. 群发送和各私聊相互独立；单个失败不得阻止其余发送，不自动重试。
5. 返回成功、部分失败或全部失败的脱敏聚合结果。

正常、恢复、人工消息、其他机器人消息和无关消息不得发送群消息或私聊。

## 配置契约

配置优先级概括为 CLI 参数、环境变量、默认 YAML；具体实现为 `--config` 选择配置、`--routes` 覆盖 YAML 路由路径、已有进程环境优先于项目 `.env`。环境变量只用于显式引用的字段和 gateway 固定变量，不自动覆盖数值配置。进入新环境时配置：

- 告警机器人 sender ID 和告警群 chat ID；
- 两个 probe 的 SSH 主机、端口、用户和私钥路径环境变量；
- 路由表路径、诊断目标、负责人环境变量引用和 fallback；
- 飞书应用 ID、应用密钥和域名；
- 重试、SSH、命令、TCP 与 HTTP 超时。

密码、私钥内容、应用密钥、token、webhook 和 Open ID 只放在部署环境或未提交的本地环境文件中。不要写入本文件、README、版本化 YAML、测试数据或代码。

仓库只提交示例 YAML；首次部署由示例复制运行配置。`runtime.dry_run` 当前只用于摘要，不是探测或发送开关。生产入口所需 bot/chat 变量必须预先存在于 gateway 进程环境。gateway 运行错误兜底独立使用固定应用环境变量；完全停用时禁用插件。

## 执行入口

在 skill 目录运行规范化事件：

```bash
uv run --isolated --with-requirements requirements.txt python scripts/service_reachability_check.py --config <config-path> --routes <routes-path> --hermes-event-json -
```

使用 `--resolve-event-json` 验证解析和映射，使用 `--diagnose-event-json` 做默认不发送的双 probe 验证；该模式显式提供 `--send-feishu` 才调用旧 webhook sender。`--hermes-event-json` 为兼容 CLI，自动请求旧 webhook 发送，受 `feishu.enabled` 限制；它不是生产应用机器人 fan-out。生产 gateway 直接调用 Python 管线和应用机器人 sender，不经过 LLM。去重仅在单进程内存中保存，不承诺跨重启或多实例去重。
