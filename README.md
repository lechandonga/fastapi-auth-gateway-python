# 本地认证与权限控制网关（FastAPI）

一套**本地可运行、无外部服务依赖**的登录认证与接口访问控制实现。会话/凭据状态全部保存在
进程内的线程安全存储中（`app/storage.py`），目标是让**凭据轮换、权限判断、异常处理在任何
入口下都得到一致且可解释的结论**。

## 1. 快速开始

```bash
uv sync                       # 安装依赖（fastapi / pyjwt / pytest / httpx）
uv run python main.py         # 启动服务，默认 http://127.0.0.1:8000
uv run pytest                 # 运行全部测试（25 个用例）
uv run pytest -o log_cli=true # 同时查看判定日志（关键输入与判定依据）
```

启动后可访问交互式文档：`http://127.0.0.1:8000/docs`。

### 演示账号（本地弱口令，仅用于测试，无真实凭据）

| 用户名 | 口令 | 角色 | 权限 |
| --- | --- | --- | --- |
| `admin` | `admin12345` | `admin` | `read` `write` `manage` |
| `alice` | `alice12345` | `user` | `read` |
| `audrey` | `audit12345` | `auditor` | `read` `audit` |

## 2. 凭据模型

登录成功后签发**一对凭据**：

- **访问凭据 Access Token**：JWT（HS256），默认 15 分钟有效。
  - 声明：`sub`(用户) / `sid`(会话) / `fid`(凭据族) / `roles` / `permissions` / `iat` / `exp` / `iss` / `type=access`。
  - `roles`、`permissions` 在**签发时冻结为快照**（见 §4 的生效语义）。
  - 即使携带快照，每次请求仍会检查会话即时状态，会话被撤销时立即失效。
- **刷新凭据 Refresh Token**：256 bit 密码学随机不透明串，库中**只存 SHA-256 哈希**，默认 7 天有效。
  - 属于一个**凭据族（family_id）**：登录产生新族；每次刷新在族内轮换。
- 口令使用 PBKDF2-HMAC-SHA256（20 万轮，每用户独立盐）自描述格式存储。

### 刷新轮换与重放检测（核心安全语义）

调用 `POST /auth/refresh` 时在**同一把可重入锁内原子完成「查-判-标记-签发」**：

1. 刷新凭据从未签发过 → `401 token_invalid / refresh_token_unknown`（伪造，区别于重放）；
2. 该凭据**此前已被使用过**（重复或并发使用）→ 判定为**重放**：
   - 立即撤销**整个凭据族**的全部会话与凭据（包括轮换出来的新凭据）；
   - 返回 `401 refresh_replay / refresh_token_reused`；
3. 会话族已撤销且撤销原因是重放 → `401 refresh_replay / family_revoked_by_replay`
   （随后使用族内任何凭据，包括旧访问凭据，都得到同一可区分结论）；
4. 会话因登出/管理员撤销 → `401 session_revoked`；
5. 刷新凭据过期 → `401 token_invalid / refresh_expired`（不牵连会话族）；
6. 合法轮换：旧刷新凭据置 `used`，签发新一对凭据，`family_id` 不变。

> 并发结论：同一刷新凭据被 N 个请求并发使用时，**有且仅有一次成功**，其余全部判定为重放，
> 且会话最终状态确定（整族失效）。见 `tests/test_concurrency.py`（16 并发实测）。

## 3. 权限模型与统一判定

- 角色（role）与细粒度权限（permission）都支持；规则结构为 `AccessRule`：
  - `require_any_role`：命中任一角色即可；`None` 不限制；
  - `require_all_permissions`：必须**同时**具备全部权限；`None` 不要求。
- **所有入口共用同一份纯函数判定** `app/access_control.has_access(principal, rule)`，
  HTTP 依赖与单元测试复用同一逻辑，不允许各入口各写一套。
- 统一判定顺序固定，因此三类失败在任何入口下都可区分：

| 顺序 | 判定 | 失败结论 |
| --- | --- | --- |
| 1 | 认证（Bearer/JWT/会话状态） | `401 unauthenticated` / `token_invalid` / `session_revoked` / `refresh_replay` |
| 2 | 资源是否存在 | `404 not_found / resource_not_found` |
| 3 | 角色/权限是否满足 | `403 permission_denied / insufficient_permission` |

错误响应结构恒定：`{"error": <类型码>, "reason": <细分原因>, "message": <对外文案>}`。

资源示例（`GET /resources/{id}`）：

| 资源 | 规则 |
| --- | --- |
| `public-doc` | 仅需登录 |
| `admin-secret` | 需要 `admin` 角色 |
| `audit-log` | 需要 `audit` 权限 |

### 权限调整的生效时机（确定且稳定）

- 管理员通过 `PUT /admin/users/{username}/roles` 调整角色，调整**立即落库**；
- **已签发的访问凭据在其过期前仍按签发时的权限快照判定**，不会半途中突然生效或失效；
- 客户端用刷新凭据**轮换**或**重新登录**后才获得新权限（响应中 `effective=next_refresh_or_login`）；
- 与之相对，**会话撤销（登出 / 重放 / 管理员撤销）即时生效**，与尚未过期的访问凭据无关。
  这两条语义刻意区分：权限走快照（稳定），撤销走会话实时状态（即时）。

## 4. 登录失败与账号级限制

- 连续失败达到可配置阈值后，账号被临时锁定，锁定期间即使口令正确也返回
  `429 account_locked` 并带 `Retry-After`（剩余秒数）；
- 锁定状态**按提交的用户名隔离**，绝不误伤其他账号（测试覆盖）；
- 登录成功会清零连续失败计数；
- 「用户名不存在 / 账号停用 / 口令错误」对外文案统一（避免账号枚举），
  但 `reason` 分别为 `unknown_username` / `account_disabled` / `bad_password`，便于内部解释；
- 失败计数与锁定判定在同一临界区完成，并发登录不会丢更新。

## 5. 异常归一化（底层库异常不透出）

- 与底层库的唯一边界是 `app/security.py`：pyjwt 的 `ExpiredSignatureError` 及其余
  `InvalidTokenError` 子类在此统一转换为 `TokenInvalidError`（reason 细分
  `token_expired` / `token_invalid` / `token_wrong_type`）；
- 口令哈希格式损坏时 `verify_password` 返回 `False` 而非抛异常；
- `app/handlers.py` 把 `GatewayError` 映射为统一 JSON；未知异常兜底为
  `500 internal_error`，响应中绝不出现库异常类名或堆栈。

## 6. 配置项（均可通过环境变量覆盖）

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `AUTH_JWT_SECRET` | 本地开发密钥（≥32 字节） | JWT 签名密钥，生产必须覆盖 |
| `AUTH_JWT_ALGORITHM` | `HS256` | JWT 签名算法 |
| `AUTH_ACCESS_TTL` | `900` | 访问凭据有效期（秒） |
| `AUTH_REFRESH_TTL` | `604800` | 刷新凭据有效期（秒，7 天） |
| `AUTH_LOGIN_MAX_FAILURES` | `5` | 触发锁定的连续失败次数 |
| `AUTH_LOGIN_LOCK_SECONDS` | `300` | 锁定时长（秒） |
| `AUTH_ISSUER` | `local-auth-gateway` | JWT 签发方声明 |

## 7. API 一览

| 方法 路径 | 说明 | 主要错误码 |
| --- | --- | --- |
| `POST /auth/login` | 登录，返回凭据对 | `invalid_credentials` / `account_locked` |
| `POST /auth/refresh` | 刷新轮换（一次性，重放整族失效） | `refresh_replay` / `token_invalid` / `session_revoked` |
| `POST /auth/logout` | 撤销当前会话族 | `401` |
| `GET  /auth/me` | 查看当前身份与权限快照 | `401` |
| `GET  /resources/{id}` | 受保护资源（演示 401/403/404） | `unauthenticated` / `not_found` / `permission_denied` |
| `PUT  /admin/users/{username}/roles` | 调整角色（需 `manage` 权限） | `403` / `404 not_found(user_not_found)` |

### curl 速览

```bash
# 登录
curl -s localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice12345"}'

# 访问受保护资源
curl -s localhost:8000/resources/public-doc -H "Authorization: Bearer <ACCESS>"

# 刷新（只能成功一次）
curl -s localhost:8000/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<REFRESH>"}'
```

## 8. 验证方法与测试覆盖

```bash
uv run pytest -o log_cli=true
```

测试在**无外部服务、无真实凭据**条件下运行（FastAPI `TestClient` + 内存存储），
日志中打印关键输入（用户名、凭据前缀、失败次数）与判定依据（status / error / reason）：

- `tests/test_auth_flow.py`：登录、凭据对、刷新轮换、**重放整族失效**、原因可区分、登出；
- `tests/test_concurrency.py`：**16 并发刷新仅 1 次成功**；10 并发失败登录的计数/锁定一致性与账号隔离；
- `tests/test_access_control.py`：**401/403/404 状态矩阵**、角色与权限边界、
  **权限调整后旧凭据快照稳定 + 刷新后生效**；
- `tests/test_lockout_and_errors.py`：可配置阈值锁定、`Retry-After`、账号互不影响、
  成功清零计数、JWT 过期/伪造异常**归一化不透出**。

## 9. 代码结构

```
app/
  config.py          配置（环境变量覆盖）
  errors.py          对外错误类型体系（error_code / status_code / reason）
  models.py          用户/会话/刷新凭据/失败记录/Principal 数据模型
  security.py        口令哈希、随机凭据、JWT 编解码 —— 底层库唯一边界
  storage.py         线程安全进程内存储（RLock + 原子原语）
  auth_service.py    登录/刷新轮换/重放检测/锁定（复合流程整体持锁）
  access_control.py  AccessRule + has_access 纯函数统一判定
  dependencies.py    FastAPI 依赖：Bearer 提取、认证→存在性→权限
  handlers.py        异常归一化为统一 JSON
  bootstrap.py       应用装配 + 演示账号
  routers/           auth / resources / admin 三组入口
tests/               上述四类重点场景
main.py              create_app() 并启动 uvicorn
```
