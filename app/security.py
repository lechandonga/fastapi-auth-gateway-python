"""安全原语：口令哈希、随机凭据生成、JWT 访问凭据编解码。

本模块是与底层库（hashlib/hmac/secrets/pyjwt）的唯一边界：
底层库抛出的异常只允许在这里被捕获并归一化为 app.errors 中的类型，
上层永远不会直接看到 jwt.* / hashlib.* 的异常。
"""

import hashlib
import hmac
import logging
import secrets

import jwt

from app.config import Settings
from app.errors import TokenInvalidError
from app.models import Principal, now

logger = logging.getLogger("auth.security")

_PBKDF2_ROUNDS = 200_000
_HASH_PREFIX = "pbkdf2_sha256"


def generate_opaque_token(nbytes: int = 32) -> str:
    """生成密码学随机的不透明凭据（URL 安全，默认 256 bit 熵）。"""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """对不透明凭据做单向哈希后再入库，库中不存明文。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 口令哈希，返回自描述字符串。

    格式: pbkdf2_sha256$<rounds>$<salt_hex>$<hash_hex>
    """
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS
    )
    return f"{_HASH_PREFIX}${_PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """常量时间校验口令；存储格式损坏时返回 False 而非抛异常。"""
    try:
        scheme, rounds_raw, salt_hex, hash_hex = stored_hash.split("$", 3)
        if scheme != _HASH_PREFIX:
            logger.warning("password.verify", extra={"result": "unknown_scheme"})
            return False
        rounds = int(rounds_raw)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        logger.warning("password.verify", extra={"result": "malformed_stored_hash"})
        return False

    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, rounds
    )
    return hmac.compare_digest(candidate, expected)


def encode_access_token(principal: Principal, settings: Settings) -> tuple[str, int]:
    """签发 JWT 访问凭据，返回 (token, ttl_seconds)。

    roles/permissions 在此时冻结为快照；权限调整后，旧的访问凭据在其
    过期前仍按签发时的快照生效，刷新/重新登录后才拿到新权限——
    这是确定且稳定的生效语义。
    """
    ttl = settings.access_token_ttl_seconds
    iat = now()
    payload = {
        "sub": principal.username,
        "iss": settings.issuer,
        "iat": int(iat),
        "exp": int(iat + ttl),
        "sid": principal.session_id,
        "fid": principal.family_id,
        "roles": sorted(principal.roles),
        "permissions": sorted(principal.permissions),
        "type": "access",
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, ttl


def decode_access_token(token: str, settings: Settings) -> dict:
    """校验并解码 JWT。底层 jwt 库的所有异常在此归一化为 TokenInvalidError。"""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.issuer,
            options={"require": ["exp", "iat", "iss", "sub", "sid", "fid"]},
        )
    except jwt.ExpiredSignatureError as exc:
        logger.info("access_token.decode reason=expired")
        raise TokenInvalidError("访问凭据已过期", reason="token_expired") from exc
    except jwt.InvalidTokenError as exc:
        # 签名错误、格式错误、签发方不符、缺少声明等全部归一化，
        # 不把 pyjwt 的具体异常文本透出给调用方。
        logger.info("access_token.decode reason=invalid_token detail_type=%s",
                    type(exc).__name__)
        raise TokenInvalidError("访问凭据无效", reason="token_invalid") from exc

    if payload.get("type") != "access":
        logger.info("access_token.decode reason=wrong_type")
        raise TokenInvalidError("凭据类型错误", reason="token_wrong_type")
    return payload
