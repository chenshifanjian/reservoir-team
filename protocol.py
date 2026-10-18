#!/usr/bin/env python3
"""组队系统的密钥派生协议（客户端与协调服务共用同一份实现）

设计要点：
- 协调服务**只**需要 code_hash 来校验入队码，它不持有 code，因此派生不出 K_team
- K_team 绑定 team_id：同一个码在不同队伍里派生出不同密钥
- K_member 绑定 member_client_id：一个队员解不开别人的包
- 广播通道直接用 K_team：共享池里任一队员都能解（见文件末尾）

部署：本文件随 coordinator.py 一起放到 /opt/reservoir-team/（deploy.sh 会一并上传）。
"""
from __future__ import annotations

import hashlib

SCRYPT_N = 2 ** 15        # 阿里云实测 145ms/次 → 100 万种 6 位码全枚举 40 核·小时
SCRYPT_R = 8
SCRYPT_P = 1
MAXMEM = 64 * 1024 * 1024


def code_hash(code: str, salt_hex: str) -> str:
    """入队码的校验摘要。服务端存这个，从不见明文码。"""
    return hashlib.scrypt(
        code.encode("utf-8"), salt=bytes.fromhex(salt_hex),
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32, maxmem=MAXMEM,
    ).hex()


def derive_team_key(code: str, team_id: str, salt_hex: str) -> bytes:
    """队伍共享密钥。绑定 team_id，服务端没有 code 所以算不出来。"""
    return hashlib.scrypt(
        (code + team_id).encode("utf-8"), salt=bytes.fromhex(salt_hex),
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32, maxmem=MAXMEM,
    )


def derive_member_key(team_key: bytes, member_client_id: str) -> bytes:
    """按人加密的密钥。队长与该队员都能算，其他队员算不出。"""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=member_client_id.encode("utf-8"),
    ).derive(team_key)


def encrypt_for_member(team_key: bytes, member_client_id: str, plaintext: bytes) -> tuple[bytes, bytes]:
    """返回 (nonce, ciphertext)。用 AESGCM，密文比明文多 16 字节 tag。"""
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    key = derive_member_key(team_key, member_client_id)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt_as_member(team_key: bytes, member_client_id: str, nonce: bytes, ciphertext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = derive_member_key(team_key, member_client_id)
    return AESGCM(key).decrypt(nonce, ciphertext, None)

# ============================================================
# 全队广播（共享池）
# ============================================================
# 共享池里任何队员都能解，所以直接用 K_team，不做按人派生。
# 注意：广播意味着**全队可见** —— 客户端上传前必须先过队长白名单，
# 白名单不过的内容绝不能进这条通道。定向包（上面那对函数）仍然
# 用于「只给某一个人」的场景。

def encrypt_broadcast(team_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """返回 (nonce, ciphertext)，全队任一成员都能解。"""
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return nonce, AESGCM(team_key).encrypt(nonce, plaintext, None)


def decrypt_broadcast(team_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(team_key).decrypt(nonce, ciphertext, None)
