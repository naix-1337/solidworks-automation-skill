# CAD 尺寸证据信任链

本文定义 `cad-measurement-attestation/v1` 的信任边界、协议和部署前提。它解决的
是“Agent 只要写出匹配数字的 JSON 就能通过尺寸门禁”的缺陷，不宣称自动证明完整
工程意图或制造合理性。

## 1. 信任边界

Agent 与 CAD Studio 同 Windows 用户运行，视为不可信。Agent 可以修改工作区、
伪造 `cad_spec`、`measurement_source`、命令说明和 Agent JSON 回执，因此这些都
不能产生 `PASS`。

可以签发最终尺寸结论的只有受保护自托管 Runner。Runner 从控制面取得锁定规格和
一次性证明包，使用私有 OCCT/OCP 解析产物，并用只存在于 Environment Secret 或
KMS 中的 Ed25519 私钥签名。测量签名私钥与控制面在线状态签名私钥必须分离；
前者只供 Runner 使用，后者只供控制面使用。两个私钥都不得由本项目工作区、Agent
进程或普通用户进程读取。

本机安装目录、操作系统、`cad-validation` Environment 和私有 Runner 属于信任根
边界。若攻击者能修改桌面应用二进制、Runner、Environment Secret 或操作系统，
本机制不能提供针对主机管理员的独立安全。

## 2. 支持的尺寸证据

首版只对以下开放 B-Rep 执行尺寸复测：

| 格式 | 尺寸门禁 |
| --- | --- |
| STEP / STP | 受信 OCCT 重开、实体有效性、包围盒、内圆柱孔 |
| IGES / IGS | 受信 OCCT 重开、实体有效性、包围盒、内圆柱孔 |
| BREP | 受信 OCCT 重开、实体有效性、包围盒、内圆柱孔 |
| SLDPRT / SLDASM / SLDDRW | 最高 `review_required`，等待独立原生 CAD Runner |
| STL / OBJ / GLB / DXF / PDF / PNG / SVG | 不作为 B-Rep 尺寸证明 |

系统使用整数微米保存尺寸、公差和测量值，签名 JSON 禁止浮点数。默认尺寸公差为
`1 μm`。包围盒比较忽略 XYZ 轴顺序；所有声明的必需 B-Rep 产物都必须分别满足
锁定规格。

STEP 从文件单位声明归一化为毫米，支持项目当前识别的毫米、厘米、米、英寸和英尺；
IGES 从 Global 段单位名归一化；无法识别单位时 `blocked`。OCCT BREP 格式本身不保存
物理单位，本项目首版明确规定 BREP 坐标按毫米解释。

## 3. 数据流

1. CAD Studio 在 Agent 启动前从明确需求生成 `cad-dimension-verification/v1`。
   多个冲突外形尺寸或无法确定的孔径数量会停止任务并要求用户确认。
   用户确认后将 `verificationSpecConfirmed` 设为 `true` 再重试；锁定规格的
   `source` 会变为 `user_confirmed`，并由新的 SHA-256 绑定到远程会话。
2. Worker 将锁定规格摘要发给私有控制面，取得一次性 `sessionId`、`nonce` 和
   上传能力。Agent 不持有控制面令牌或签名私钥。
   一次性 `uploadUrl` 只保存在 Worker 内存，不写入队列 Job；队列只持久化
   session、run、nonce 和规格摘要等绑定字段。
3. Agent 完成后，Worker 只封装当前轮次、白名单目录内的 STEP/IGES/BREP 普通文件；
   符号链接、硬链接、路径逃逸、重复成员和超过 512 MiB 的包全部拒绝。
4. Runner 从控制面取得规格和证明包。包内只允许 `manifest.json` 与
   `artifacts/*.step|iges|brep`，包内代码不会执行。
5. Runner 重新读取 B-Rep，生成整数微米测量和几何指纹，计算规范 JSON 摘要并签发
   Ed25519 证明。证明记录 workflow 仓库、ref、commit SHA、脚本与依赖锁工具链
   SHA-256、Python 版本、平台、Runner 名称、PID、进程创建时间、实际 argv、argv
   摘要和退出码。

几何指纹覆盖实体数、体积、表面积、包围盒、面/边类型与量化后的面积/长度/中心，
以及圆柱轴和内外属性。证据仍同时绑定原始文件 SHA-256；几何指纹用于说明“实际测到
的形状”，文件哈希用于说明“测的是哪一组字节”。
6. Reviewer Gate 验证证明签名、在线状态签名、密钥撤销状态、验证器版本策略、
   session/job/run/nonce/spec 绑定以及交付文件当前 SHA-256。全部一致才是 `pass`。

## 4. 协议

仓库内 Schema：

- `apps/desktop/cad_workbench/schemas/dimension_verification.schema.json`
- `apps/desktop/cad_workbench/schemas/measurement_attestation.schema.json`
- `apps/desktop/cad_workbench/schemas/measurement_attestation_status.schema.json`

控制面接口：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `POST` | `/v1/verification-sessions` | 用锁定规格创建一次性会话 |
| `PUT` | 会话返回的 HTTPS `uploadUrl` | 上传受控证明包 |
| `POST` | `/v1/verification-sessions/{id}/finalize` | 通知 Runner 开始验证 |
| `GET` | `/v1/verification-sessions/{id}/attestation` | 读取签名证明 |
| `GET` | `/v1/verification-sessions/{id}` | Runner 读取控制面锁定会话 |
| `GET` | `/v1/verification-sessions/{id}/bundle` | Runner 下载一次性证明包 |
| `PUT` | `/v1/verification-sessions/{id}/attestation` | Runner 回传签名证明 |
| `GET` | `/v1/attestations/{id}/status` | 每次本地验收在线确认状态和验证器策略 |

在线状态响应必须包括当前批准的：

```json
{
  "verifierPolicy": {
    "workflowRepository": "owner/repository",
    "workflowRef": "refs/heads/main",
    "workflowSha": "<40 hex commit>",
    "toolkitSha256": "<64 hex>",
    "pythonVersion": "3.12.x",
    "platform": "<approved runner platform>",
    "dependencyLockSha256": "<64 hex>",
    "dependencyVersionsSha256": "<64 hex>"
  }
}
```

本地证明最长有效 1 小时，在线状态最长有效 1 分钟。离线、状态过期、状态服务异常、
密钥未知或撤销时保持 `blocked`，不允许用缓存证明获得 `PASS`。

## 5. 部署与轮换

1. 创建 `cad-validation` Environment，只允许固定 `main` 工作流使用。
2. 注册私有、短生命周期自托管 Windows Runner，标签为
   `self-hosted, Windows, CAD-EVIDENCE`。工作流只安装
   `requirements-evidence-verifier.txt` 中的精确版本。
3. 配置 Environment Secret `CAD_EVIDENCE_PRIVATE_KEY_PEM` 和
   `CAD_EVIDENCE_CONTROL_TOKEN`，配置变量 `CAD_EVIDENCE_CONTROL_URL`。
4. 将控制面限制为只接受受信桌面后端调用；上传 URL 必须 HTTPS、一次性且很快过期。
   控制面接收 Runner 证明后必须先按测量公钥和用途验签，再登记为可查询的 `active`
   状态；控制面的状态私钥不能签发测量证明。
5. 生成两套用途分离的 Ed25519 密钥对。测量私钥只进入 Runner 的受保护
   Secret/KMS，状态私钥只进入控制面的受保护 Secret/KMS；两个公钥写入
   `C:\Program Files\CAD Studio\evidence\measurement_trust_root.json`，文件 ACL
   对普通用户只读。示例结构见 `config/measurement_trust_root.example.json`。
6. Runner 产物最多保留 24 小时；签名结论和最小审计元数据保留 90 天。
7. 轮换时先加入新公钥和 `notBefore`，同时向只追加 `rotationLog` 登记
   `keyId`、`addedAt` 和原因，部署在线批准策略，更新本地信任根，再给旧公钥写
   `revokedAt`。不得复用 `keyId`。

工作流入口为 `.github/workflows/cad-evidence-verify.yml`。它只固定检出 `main`，
不检出 Agent 分支，不执行证明包代码。当前仓库尚未配置真实
`cad-validation` Environment、自托管 Runner、控制面服务或生产签名密钥；缺失时
尺寸任务按设计保持 `blocked`。

## 6. 验证

```powershell
python -m pytest -q tests/test_measurement_trust.py tests/test_measurement_bundle_verifier.py tests/test_measurement_remote.py
node --test tests/test_measurement_trust_signing.cjs
```

审查报告中的以下检查共同构成尺寸证据链：

- `measurement-attestation-signature`
- `measurement-attestation-binding`
- `measurement-attestation-artifact-binding`
- `measurement-attestation-online`
- `spec-envelope-dimensions`
- `spec-hole-diameters`

Agent 的 `verification` 字段仍显示在报告中，但固定标记为“仅展示，不参与最终门禁”。
