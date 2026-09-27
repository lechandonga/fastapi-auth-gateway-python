"""安全原语：密码哈希（PBKDF2）、随机令牌、哈希指纹、恒定时间比较。

对底层库（hashlib/hmac/secrets）的所有调用都收敛在这里，
异常被归一化为 InternalAuthError，不向调用方透出。
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets

from .config import AuthConfig
from .errors import InternalAuthError

logger = logging.getLogger("auth.security")

_ALGO = "pbkdf2_sha256"


def _pbkdf2(password: bytes, salt: bytes, iterations: int) -> bytes:
    try:
        return hashlib.pbkdf2_hmac("sha256", password, salt, iterations)
    except Exception as exc:  # noqa: BLE001 - 底层库异常不得透出
        logger.error("pbkdf2 计算失败: algo=%s iterations=%s err=%s", _ALGO, iterations, exc)
        raise InternalAuthError("密码哈希计算失败") from exc


def hash_password(password: str, config: AuthConfig) -> str:
    """生成 `pbkdf2_sha256$iterations$salt_hex$hash_hex` 形式的存储串。"""
    salt = secrets.token_bytes(16)
    digest = _pbkdf2(password.encode("utf-8"), salt, config.pbkdf2_iterations)
    return f"{_ALGO}${config.pbkdf2_iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str, config: AuthConfig) -> bool:
    """验证密码；格式非法或参数异常时归一化为 False/InternalAuthError。"""
    try:
        parts = stored_hash.split("$")
        if len(parts) != 4 or parts[0] != _ALGO:
            logger.warning("密码存储格式非法，判定为不匹配")
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected = bytes.fromhex(parts[3])
    except (ValueError, TypeError) as exc:
        logger.warning("密码存储字段解析失败: err=%s", exc)
        return False

    candidate = _pbkdf2(password.encode("utf-8"), salt, iterations)
    matched = hmac.compare_digest(candidate, expected)
    logger.info(
        "密码校验完成: iterations=%s salt_prefix=%s matched=%s",
        iterations,
        parts[2][:8],
        matched,
    )
    return matched


def generate_token(config: AuthConfig) -> str:
    """生成高熵不透明凭据（hex 编码）。"""
    try:
        return secrets.token_hex(config.token_bytes)
    except Exception as exc:  # noqa: BLE001
        logger.error("随机令牌生成失败: err=%s", exc)
        raise InternalAuthError("凭据生成失败") from exc


def token_fingerprint(token: str) -> str:
    """令牌以 SHA-256 指纹形式落库，原始值不入库。"""
    try:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
    except Exception as exc:  # noqa: BLE001
        logger.error("令牌指纹计算失败: err=%s", exc)
        raise InternalAuthError("凭据处理失败") from exc


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
