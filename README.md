# 作业提交系统

> 一个部署在 Cloudflare Workers 上的轻量级作业收集平台，面向教学场景，支持小组制与个人模式。
>
> 本文档与系统代码的主要逻辑由 **混元AI** 辅助完成。

---

## 特性一览

| 能力 | 说明 |
|------|------|
| **双存储后端** | S3 兼容接口 / WebDAV 二选一，Admin 后台一键切换并测试连接 |
| **Durable Object 防并发** | 同组提交自动串行化，杜绝覆盖与成员串组 |
| **小组制 / 个人模式** | 随时切换，个人模式自动归入 `personal` 组 |
| **灵活的提交类型** | 视频 / 音频 / 图片 / PPT / 其他文档，可多选 |
| **截止时间控制** | 定时截止 / 立即截止 / 随时清除 |
| **学号名单可自定义** | 支持范围语法 `1~48`、逗号分隔、或混合形式 |
| **学号 → 姓名映射** | 下载时自动用真实姓名命名文件 |
| **图片自动转 PNG** | 前端 Canvas 统一转换，避免格式混乱 |
| **批量 ZIP 打包下载** | Admin 后台勾选即打包，可同步标记"已下载" |
| **深浅色主题** | 自动跟随系统偏好，也可手动切换 |
| **零服务器运维** | 跑在 Cloudflare Workers 边缘节点，免费额度覆盖教学场景 |

## 架构概览

```
学生浏览器                    Cloudflare Workers                   对象存储 / WebDAV
┌──────────┐                 ┌────────────────┐                  ┌─────────────┐
│  提交页面 │ ──1.获取凭证──▶ │  /api/presign  │                  │             │
│  /        │ ◀─ token ──── │                │                  │   S3/B2     │
│          │ ──2.上传文件──▶ │ /api/upload-   │ ──直传/代理──▶  │   或 WebDAV │
│          │                 │   proxy        │                  │             │
│          │ ──3.记录提交──▶ │  /api/upload   │ ──DO 串行化──▶   │             │
│          │ ◀─ OK ──────── │                │                  │             │
└──────────┘                 └────────────────┘                  └─────────────┘
                                     │
                                     ▼
                              ┌──────────────┐
                              │ Durable Obj  │ ← 同组提交串行化
                              │   GroupDO    │    防止并发覆盖
                              └──────────────┘
```

## 部署教程

整个部署流程大约 5~10 分钟。需要一个 Cloudflare 账号（免费计划即可）。

### 前置条件

| 工具 | 最低版本 | 说明 |
|------|---------|------|
| Node.js | 18+ | 推荐 LTS，wrangler 5.x 要求 Node 18+ |
| npm / pnpm / yarn | 任意 | 任选其一，下面示例用 npm |
| Cloudflare 账号 | — | 免费计划即可，Durable Object 免费额度 100 万次/月 |

### 步骤一：安装并登录 wrangler

```bash
# 安装 wrangler CLI
npm install -g wrangler

# 验证安装
wrangler --version
# ⛅️ wrangler 5.12.0（示例版本）

# 登录 Cloudflare，会自动打开浏览器授权
wrangler login
```

登录成功后终端会输出 `Successfully logged in`。

### 步骤二：创建 Cloudflare 资源

系统需要两类 Cloudflare 资源：一个 KV Namespace 存状态，一个 Durable Object Class 做防并发。

```bash
# ── 创建 KV Namespace ──────────────────────
wrangler kv namespace create GROUP_KV

# 输出示例：
# 🌀 Creating namespace with title "homework-GROUP_KV"
# ✨ Success!
# Add the following to your configuration file in the kv_namespaces array:
# { binding = "GROUP_KV", id = "..." }

# 复制上面输出的 id（那个 32 位十六进制字符串）

# ── 创建 Durable Object Class ───────────────
wrangler durable-object class create GroupDO

# 输出示例：
# 🌀 Creating Durable Object class "GroupDO"
# ✨ Success!
# The class has been created.
# Migrations have been generated if needed.
```

### 步骤三：配置 wrangler.toml

打开项目根目录的 `wrangler.toml`，做一件事：**把步骤二里 KV 创建命令输出的 id 填进去**。

```toml
[[kv_namespaces]]
binding = "GROUP_KV"
id = "..."   # ← 替换成你的id
```

文件里其他内容保持不变。注意：
- `ADMIN_USER`（管理员用户名）是明文写在 toml 里的，默认 `"admin"`，可以直接改
- 敏感信息 **不要** 写在 toml 里，用下一节的 `wrangler secret put`

### 步骤四：设置 Secrets

两个敏感变量必须用 `wrangler secret put` 设置——它们会被加密存储，**永远不会** 出现在 `wrangler.toml` 里。

```bash
# 管理员密码（Basic Auth 用）
wrangler secret put ADMIN_PASS
# 终端会提示输入，输入时不会回显，输完回车即可

# HMAC 签名密钥（用于上传凭证和管理 token 的签名）
wrangler secret put UPLOAD_SECRET
```

| Secret | 用途 | 建议 |
|--------|------|------|
| `ADMIN_PASS` | Admin 后台 Basic Auth 密码 | 强密码即可 |
| `UPLOAD_SECRET` | HMAC-SHA256 签名密钥 | ≥ 32 字节随机字符串，**不要** 和 `ADMIN_PASS` 相同 |

生成一个安全的 `UPLOAD_SECRET`：

```bash
openssl rand -hex 32
# 复制输出，然后 wrangler secret put UPLOAD_SECRET 粘贴进去
```

### 步骤五：本地开发（可选）

想先在本地跑起来看看效果：

```bash
cd homework
wrangler dev --local-durable-objects --local-kv

# 输出示例：
# ⛅️ wrangler 5.12.0
# ----------
# Uploaded home
#   worker.js
# Configuring local environment...
# Ready on http://localhost:8787
#  [proxy] Bundled project
```

Durable Object 和 KV 会用本地 SQLite 模拟，适合快速调试。注意本地模式下 `ADMIN_PASS` 和 `UPLOAD_SECRET` 需要用 `wrangler secret put` 写入（与生产环境共用），或者在 `.dev.vars` 文件里临时设置：

```bash
cat > .dev.vars << EOF
ADMIN_PASS=dev-password
UPLOAD_SECRET=local-development-secret-key-please-change
EOF
```

### 步骤六：生产部署

```bash
# 一键部署到 Cloudflare 边缘
wrangler deploy

# 输出示例：
# ⛅️ wrangler 5.12.0
# ----------
# Uploaded home
#   worker.js (42.7 KB)
# Deployed to https://homework-abc123.workers.dev
# ✨ Deployment complete
```

记下输出里的 `https://xxx.workers.dev` 地址。

### 步骤七：绑定自定义域名（推荐）

用默认的 `workers.dev` 域名也能用，但老师和学生访问起来不太正式。建议绑定一个自己的子域名：

```bash
wrangler routes create submit.yourdomain.com --service-name homework
```

或者在 Cloudflare Dashboard → Workers & Pages → 你的 Worker → Settings → Triggers → Custom Domains 里添加。

### 验证部署

部署完成后按顺序访问：

| URL | 期望结果 |
|-----|---------|
| `https://你的域名/` | 看到作业提交页面 |
| `https://你的域名/admin` | 浏览器弹出 Basic Auth 登录框，用户名密码是你之前设置的 |
| `https://你的域名/api/config` | 返回 JSON，包含 `groupMode`、`submitTypes`、`expectedSids` 等字段 |
| `https://你的域名/api/status` | 返回 JSON，`submitted: []`、`missing: [...]` |

### 常见部署错误排查

| 报错 | 原因 | 解决 |
|------|------|------|
| `KV namespace binding "GROUP_KV" not found` | wrangler.toml 里的 KV id 没填或填错 | 回到步骤二重新 `wrangler kv namespace create`，把新 id 填进 toml |
| `Durable Object migrations conflict` | 删过 Worker 重新部署，DO 状态和 migrations 不一致 | `wrangler durable-object class create GroupDO` 重新执行一次 |
| `missing secret ADMIN_PASS` | 没有执行 `wrangler secret put ADMIN_PASS` | 去步骤四补设置 |
| `上传凭证无效或已过期` | `UPLOAD_SECRET` 在部署后被更改过，旧 token 签名校验不通过 | 重新获取 presign 即可，前端会自动重试 |
| 部署成功但 500 | 大概率是 KV id 不匹配或 Durable Object 未初始化 | 看 `wrangler tail` 实时日志定位具体错误 |

开启实时日志：

```bash
wrangler tail
# 部署后另开一个终端执行，就能看到所有请求的运行时错误
```

---

### 首次使用 Checklist

部署完成后，按以下顺序快速跑通一次：

1. **打开 Admin 后台** — `https://你的域名/admin`，浏览器会弹出 Basic Auth
2. **存储设置** — 在 `存储设置` 页面选择 S3 / B2 / WebDAV，填写凭证，点击「测试连接」
3. **提交设置** — 选择小组制 / 个人模式、每组人数、允许的提交类型、学号范围
4. **名单管理**（可选）— 上传学号 → 姓名映射，下载文件时会自动替换命名
5. **前台访问** — `https://你的域名/`，填小组名 + 学号 + 选文件，点「提交」

## Admin API 一览

| 路径 | 方法 | 用途 |
|------|------|------|
| `/admin` | GET | 管理后台主页（Basic Auth） |
| `/admin/storage` | GET / POST | 存储后端配置 |
| `/admin/test-storage` | POST | 测试当前存储连接 |
| `/admin/config` | GET / POST | 小组制、提交类型、学号范围 |
| `/admin/names` | GET / POST | 学号 → 姓名映射 |
| `/admin/set-deadline` | POST | 设置 / 清除 / 立即截止 |
| `/admin/clear-submissions` | POST | 清空所有提交记录（不动存储桶文件） |
| `/admin/edit-members` | POST | 移除某个组的某个成员 |
| `/admin/delete/<group>` | POST | 删除整个组 |
| `/admin/delete-file/<key>` | POST | 删除单个文件 |
| `/admin/download/<key>` | GET | 下载单个文件（带签名 URL） |
| `/admin/download-zip` | POST | 批量打包下载 |
| `/admin/mark-downloaded/<key>` | POST | 标记已下载 |

## 学生端 API（公开）

| 路径 | 方法 | 用途 |
|------|------|------|
| `/` | GET | 提交页面 |
| `/api/config` | GET | 获取当前配置（小组模式、允许学号、允许的提交类型等） |
| `/api/storage-public` | GET | 获取当前存储后端类型 |
| `/api/deadline` | GET | 获取截止时间及是否已过 |
| `/api/status` | GET | 实时提交情况（已交 / 未交名单） |
| `/api/presign` | POST | 获取上传凭证（需传入 group / sids / filename / submitType） |
| `/api/upload-proxy` | POST | S3/B2 代理上传 |
| `/api/webdav-upload` | PUT | WebDAV 代理上传 |
| `/api/upload` | POST | 提交完成后记录信息（触发 DO 串行化） |

## 学号名单语法

在 `提交设置` 页面，学号范围字段支持：

| 写法 | 含义 |
|------|------|
| `1,2,3,5` | 列出四个独立学号 |
| `1~48` | 从 1 到 48 的连续学号（默认） |
| `1,3,5~20,22` | 混合写 |
| 空 | 退回到默认的 `1~48` |

分隔符可以是英文逗号 `,`、中文逗号 `，`、顿号 `、` 或空格。

## 安全设计

| 风险点 | 对策 |
|--------|------|
| 同组并发提交相互覆盖 | Durable Object `GroupDO.commit()` 用 `blockConcurrencyWhile` 串行化 |
| 上传凭证被重复使用 | nonce 机制：每次 presign 生成唯一 nonce，DO 侧 24h 过期回收 |
| 凭证过期后继续上传 | HMAC 签名 + 2h 过期时间，`readPayload` 校验失效即拒绝 |
| 伪造管理员身份 | Basic Auth + 二次 HMAC token，`timingSafeEqual` 抗时序攻击 |
| WebDAV 凭证下发到前端 | 代理上传，浏览器只拿到 DO 签名后的 token，不直接接触存储密码 |
| 组名跨组串成员 | presign 阶段查 `sid:<学号>` 是否已绑定到其他组，冲突即 409 |

## 文件结构

```
homework/
├── worker.js       # 全部逻辑（GroupDO + Worker 路由 + 前端 HTML/CSS）
├── wrangler.toml   # Cloudflare 部署配置
└── README.md
```

整个系统只有一个入口文件，方便审查与二次开发。如果你要扩展它，常见的改动点：

- **路由**：`worker.js` 底部的 `router()` 函数，在 `if (url.pathname === "...")` 处加新分支
- **Durable Object**：`class GroupDO`，改内部逻辑不需要 migrations
- **允许的扩展名**：顶部的 `ALLOWED_EXT` Set
- **默认学号范围**：`defaultSids()` 函数

## 常见问题

**Q: 文件大小有限制吗？**
A: Cloudflare Workers 代理上传时 body 有 100MB 限制。如果需要传更大的视频，建议改用 WebDAV 后端（代理流式转发，不受 100MB 限制）或者前端分片直传到 S3/B2。

**Q: 免费额度够吗？**
A: Durable Object 免费额度 100 万次请求/月，KV 免费额度 10 万次读/天。一个几十人的班级每学期交一次作业完全够用。

**Q: 清空提交会删除存储桶里的文件吗？**
A: 不会。Admin 的「清空提交」只清 KV 里的记录，存储桶文件需要手动清理。这是故意设计的，防止误删。

**Q: WebDAV 模式安全吗？**
A: 相对来说不如 S3 直传。建议使用专用低权限账号（只读 + 只写指定目录），并且全程 HTTPS。系统会在 Admin 后台用红色警告提醒。

**Q: 为什么不直接用 Canvas、不写后端？**
A: 因为文件需要长期存放，而且需要防止并发覆盖、需要管理员下载与统计。Durable Object + 对象存储的组合是 Cloudflare 边缘场景下最经济也最可靠的方案。

## 技术栈

| 组件 | 选型 | 说明 |
|------|------|------|
| 运行时 | Cloudflare Workers | 边缘执行，全球低延迟 |
| 状态存储 | Cloudflare KV | 配置、提交记录、学号映射 |
| 防并发 | Cloudflare Durable Object | `GroupDO` 串行化同组提交 |
| 对象存储 | S3 兼容 / WebDAV | Backblaze B2、Rain3、自建 Nextcloud 等 |
| 认证 | Basic Auth + HMAC-SHA256 | 零第三方依赖 |

---

> 系统核心逻辑由 **混元AI** 辅助生成，经人工审查与调优。
> 如有 bug 或改进建议，欢迎提交 Issue / PR。