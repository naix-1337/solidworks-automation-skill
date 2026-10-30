# runtime 配置模板

`config/runtime.example.json` 是 Golden 工作流的可选运行配置模板。复制到任意位置后按需修改，
用 `--runtime-config <path>` 传给用例脚本。

```bash
python tests/solidworks_golden_workflow.py \
  --case parallel_gripper_retention_travel \
  --output output/verify \
  --runs 1 \
  --runtime-config config/runtime.example.json
```

## 字段白名单

配置只允许下面这些字段。**任何未知字段都会被拒绝**（`BLOCKED: runtime-config 含未知或禁止的字段`），
这是刻意的：该文件不能用于修改 SolidWorks 版本、几何公差或跳过审查。

| 字段 | 类型 | 缺省 | 说明 |
| --- | --- | --- | --- |
| `part_template` | string \| null | `null` | 零件模板 `.prtdot`；`null` 表示从 SolidWorks 用户偏好自动探测 |
| `assembly_template` | string \| null | `null` | 装配模板 `.asmdot`；**仅装配类用例（`native_extension=SLDASM`）接受该字段** |
| `material_database` | string \| null | `null` | 材料库 `.sldmat`；`null` 表示从安装目录自动探测 |
| `connect_timeout_seconds` | int | `60` | 连接 SolidWorks 超时，允许 `5..120` |
| `cleanup_timeout_seconds` | int | `30` | 关闭与清理超时，允许 `5..60` |

## 路径解析规则

- **相对路径**以**配置文件所在目录**为基准解析，便于随项目一起搬运；
- **绝对路径**原样使用；
- 非 `null` 的模板与材料库路径必须是**真实存在的文件**且扩展名匹配，否则立即 `BLOCKED`，
  不会静默回退。

因此本模板默认全部写 `null`——即"全部自动探测"，这在任何一台正确安装 SolidWorks 的机器上都应可用。
只有自动探测失败时，才需要填成具体路径。

## 填写示例（请替换为你的实际路径）

```jsonc
{
  "part_template": "relative/to/this/file/templates/gb_part.prtdot",
  "assembly_template": "C:\\ProgramData\\SolidWorks\\SOLIDWORKS 2026\\templates\\gb_assembly.asmdot",
  "material_database": "C:\\ProgramData\\SolidWorks\\SOLIDWORKS 2026\\lang\\chinese-simplified\\sldmaterials\\solidworks materials.sldmat",
  "connect_timeout_seconds": 90,
  "cleanup_timeout_seconds": 30
}
```

> 模板里的 SolidWorks 版本号目录（如 `SOLIDWORKS 2026`）随安装而异，不要直接照抄。
> 本仓库此前使用的本机配置含开发者专属盘符，**不会**以任何形式写入公开示例。

## 自动探测的兜底逻辑

| 项 | 兜底顺序 |
| --- | --- |
| 模板 | 配置值 → SolidWorks 用户偏好中的默认模板 |
| 材料库 | 配置值 → 安装目录下 `lang/english/sldmaterials` → `lang/chinese-simplified/sldmaterials` |
| 类型库 | 见 `docs/architecture/` 与 `scripts/sw_capability_probe.py`：注册表/快捷方式发现 → `SOLIDWORKS_TYPELIB_DIRS` → 通用安装路径 |

## 环境变量

| 变量 | 用途 |
| --- | --- |
| `SOLIDWORKS_TYPELIB_DIRS` | 非标准安装位置下，显式指定类型库与模板所在目录（`os.pathsep` 分隔） |
| `CADSTUDIO_SOLVER_DIRS` | 显式指定 CalculiX 求解器根目录（`os.pathsep` 分隔） |

这两个变量只影响**发现顺序**，不改变任何几何、公差或验收判据。

## 受信尺寸证明配置

- `measurement_trust_root.example.json`：生产 Ed25519 公钥与只追加轮换日志的示例；
  实际文件必须部署到 `C:\Program Files\CAD Studio\evidence\measurement_trust_root.json`，
  不能放在 Agent 可写工作区。
- `measurement_trust_root.schema.json`：信任根结构约束。
- `measurement_control_plane.openapi.yaml`：私有一次性验证会话、上传、证明与在线状态接口。

Worker 只从进程环境读取 `CAD_EVIDENCE_CONTROL_URL` 和
`CAD_EVIDENCE_CONTROL_TOKEN`，并在启动 Agent 前移除所有 `CAD_EVIDENCE_*` 变量。
完整威胁模型见
[`docs/architecture/measurement-evidence-trust-chain.md`](../docs/architecture/measurement-evidence-trust-chain.md)。
