# 本地认证与权限网关（FastAPI）

一套**本地可运行、无外部服务依赖、无真实凭据**的登录认证与权限控制流程。
会话状态完全由线程安全的内存存储模拟；凭据轮换、权限判定、异常处理在任何入口
（HTTP 路由 / 服务层 / 单元测试）下都经过同一条判定链，得到一致且可解释的结论。

## 快速开始

```bash
uv sync                      # 安装依赖（含 dev 的 pytest）
uv run python demo.py        # 命令行端到端演示
uv run python main.py        # 启动 HTTP 服务 http://127.0.0.1:8000
uv run pytest                # 运行全部测试
uv run pytest -o log_cli=true -o log_cli_level=INFO   # 同时打印判定日志
```

启动后可访问交互式文档 `/docs`。

## 凭据模型

| 凭据 | 用途 | TTL（默认） | 存放方式 |
| --- | --- | --- | --- |
| access token（访问凭据） | 每次请求放 `Authorization: Bearer <token>` | 900 秒 | 不透明随机串，仅存 SHA-256 指纹 |
| refresh token（刷新凭据） | 向 `/auth/refresh` 换取新的一对凭据 | 7 天 | 同上 |

- 令牌为 `secrets.token_hex(32)` 生成的高熵**不透明**串；服务端只保存
  `SHA-256` 指纹，原始值不入库。
- 密码使用 PBKDF2-SHA256（默认 260000 次迭代）加盐哈希。

### 刷新轮换与重放检测（核心安全语义）

1. 登录签发一对凭据，对应一个服务端 `SessionRecord`（`session_id` 在整个会话期不变）。
2. 每次刷新会**原子轮换**：旧 refresh 指纹进入“墓碑集合”，旧 access/refresh 索引摘除，
   新指纹建索引——**刷新后旧凭据立即失效**。
3. 当一个 refresh token 再次出现：
   - 命中墓碑集合 → 判定为**重放**：该 `session_id` 被**整体吊销**，
     返回 `401 refresh_token_replayed / reason=refresh_token_replay`。
   - 并发使用同一个 refresh token 时，全部判定在同一把存储锁内原子完成，
     **恰好一次成功**，其余全部识别为重放并吊销会话。
4. 重放吊销后，那次“唯一成功”轮换出的新 access/refresh 也会被拒绝，
   返回 `401 session_revoked / reason=refresh_token_replay`，原因可稳定归因。

### 错误原因（同状态码下仍可区分）

| 场景 | HTTP | error | reason |
| --- | --- | --- | --- |
| 未携带/方案非 Bearer | 401 | `access_token_missing` | `no_authorization_header` |
| access 无法识别（含轮换后旧凭据） | 401 | `access_token_invalid` | `unknown_or_rotated_token` |
| access 过期 | 401 | `access_token_expired` | `ttl_expired` |
| 会话被吊销（登出/重放） | 401 | `session_revoked` | `user_logout` / `refresh_token_replay` |
| refresh 无法识别 | 401 | `refresh_token_invalid` | `unknown_token` |
| refresh 过期 | 401 | `refresh_token_expired` | `ttl_expired` |
| **refresh 重放** | 401 | `refresh_token_replayed` | `refresh_token_replay` |
| 用户名/密码错误 | 401 | `invalid_credentials` | `bad_username_or_password` |
| 已认证但无权限 | 403 | `forbidden` | `missing_permission:<perm>` |
| 资源不存在 | 404 | `not_found` | `unknown_resource` |
| 连续失败触发锁定 | 423 | `account_locked`（含 `Retry-After`） | `too_many_failures` |
| 请求体不合法 | 400 | `invalid_request` | `validation_error` |
| 未预期内部错误 | 500 | `internal_error` | `internal_error` |

## 权限规则

角色 → 权限（见 `app/rbac.py`）：

| 角色 | `docs:read` | `docs:write` | `admin:panel` |
| --- | --- | --- | --- |
| viewer | ✅ | — | — |
| editor | ✅ | ✅ | — |
| admin | ✅ | ✅ | ✅ |

- 所有入口统一复用 `rbac.user_has_permission()`，不存在第二套判定逻辑。
- **权限调整生效语义（确定且稳定）**：凭据本身不携带权限快照，每个请求都基于
  当前 `User.roles` **实时判定（live evaluation）**。管理员调整角色后，用户
  **下一次携带仍有效 access token 的请求即生效**，无需重新登录、无需等待令牌过期。
  见测试 `test_permission_change_takes_effect_immediately`。

### 401 / 403 / 404 为什么不会混为一个状态码

`GET /resources/{key}` 的判定顺序有意固定为：

1. **先认证**：未认证一律 401（不泄露资源是否存在）；
2. **再查资源存在性**：key 不存在 → 404；
3. **最后授权**：资源存在但权限不足 → 403。

因此“存在但无权”是 403，“根本不存在”是 404，“没登录”是 401，三者严格可区分。

内置资源：`public-doc`（docs:read）、`draft-doc`（docs:write）、`admin-panel`（admin:panel）。

## 连续失败限制

- **账号级**计数，键为用户名：锁定只影响被攻击/失败的账号，**不误伤其他账号**。
- 默认连续失败达到 `max_failed_attempts=5` 即锁定 `lockout_seconds=300` 秒；
  触发阈值的当次请求本身也返回 423。
- 锁定期内即使输入正确密码也返回 423；锁定窗口结束自动清零并恢复。
- 计数与锁定状态的读写都在同一把锁内，并发下计数不会超计/少计（见
  `test_concurrent_failures_lock_exactly_once`）。
- 登录对“用户不存在”和“密码错误”返回完全相同结论，并用伪哈希校验避免用户名枚举。

## 异常归一化

- 底层库调用（`hashlib`/`hmac`/`secrets`/`pydantic`）全部收敛在 `app/security.py`
  与 `app/app_factory.py`，**库异常绝不直接透出**：底层异常 → 500 `internal_error`；
  请求体错误 → 400 `invalid_request`。
- 所有领域错误继承 `app/errors.py` 的 `AuthError`，携带稳定的 `code`/`reason`/
  `http_status`，由统一的 exception handler 输出。

## 配置项（`app/config.py: AuthConfig`）

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `access_token_ttl_seconds` | 900 | 访问凭据存活秒数 |
| `refresh_token_ttl_seconds` | 604800 | 刷新凭据存活秒数 |
| `max_failed_attempts` | 5 | 触发账号锁定的连续失败次数 |
| `lockout_seconds` | 300 | 锁定时长 |
| `pbkdf2_iterations` | 260000 | PBKDF2 迭代次数 |
| `token_bytes` | 32 | 随机令牌字节数（hex 后长度翻倍） |

测试通过夹具构造独立 `AuthConfig`（阈值更小、迭代次数更低），互不影响。

## HTTP 接口

- `POST /auth/login` `{username,password}` → 一对凭据
- `POST /auth/refresh` `{refresh_token}` → 新的一对凭据（旧的全部失效）
- `POST /auth/logout` `{refresh_token}` → 吊销会话（幂等）
- `GET  /resources/{key}` 带 Bearer → 按 401/404/403 顺序判定
- `GET  /health`

内置账号（仅演示用虚构弱密码）：

| 用户名 | 密码 | 角色 |
| --- | --- | --- |
| admin | admin-pass | admin |
| editor | editor-pass | editor |
| viewer | viewer-pass | viewer |

### curl 示例

```bash
# 登录
curl -s localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"viewer-pass"}'

# 访问（替换 <AT>）
curl -s localhost:8000/resources/public-doc -H 'Authorization: Bearer <AT>'

# 刷新（替换 <RT>）
curl -s localhost:8000/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<RT>"}'
# 再次用同一个 <RT> => 401 refresh_token_replayed，整个会话失效
```

## 测试覆盖（本地、无外部服务）

| 文件 | 重点 |
| --- | --- |
| `tests/test_refresh_replay.py` | 轮换失效、重放吊销、过期/无法识别可区分、登出幂等 |
| `tests/test_concurrent_refresh.py` | 12/16 路并发刷新恰好一次成功，其余重放且会话吊销 |
| `tests/test_rbac.py` | 角色矩阵、401/403/404 边界、权限实时调整即时生效 |
| `tests/test_lockout.py` | 阈值锁定、账号隔离、窗口过期恢复、并发计数一致性 |
| `tests/test_error_mapping.py` | 底层库异常归一化、状态码/error 稳定、过期可区分 |

关键输入与判定依据通过 `auth.*` logger 输出（用户名、角色、所需权限、
session_id、重放归因、失败计数等）；测试可用 `caplog` 断言，或加
`-o log_cli=true` 在控制台查看。

## 模块结构

```
app/
  config.py        配置
  errors.py        统一错误类型体系（code/reason/status）
  models.py        User / SessionRecord
  models_roles.py  Role / Permission 枚举
  security.py      密码哈希、随机令牌、指纹、恒定时间比较（库异常归一化）
  store.py         线程安全内存存储 + 刷新墓碑索引
  ratelimit.py     账号级连续失败锁定
  rbac.py          统一角色/权限判定（实时评估）
  resources.py     资源注册表（资源 -> 所需权限）
  auth_service.py  登录/刷新(轮换+重放)/登出/访问校验
  deps.py          FastAPI 认证/鉴权依赖（复用服务层与 RBAC）
  routes_auth.py   /auth/* 路由
  routes_resources.py  /resources/* 路由（固定 401->404->403 顺序）
  seed.py          内存演示数据
  app_factory.py   应用工厂 + 统一异常处理器
```
