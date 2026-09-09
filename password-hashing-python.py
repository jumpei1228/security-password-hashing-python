"""
パスワードの安全な保存をPythonで実装する｜ソルトとハッシュ反復

元記事: https://security.yurufuwa.work/learn/password-hashing-python
ゆるふわサイバーセキュリティ (security.yurufuwa.work) の解説記事から抜粋したコードです。
"""

import hashlib, os

def hash_password(password, iterations=200_000):
    salt = os.urandom(16)                       # ユーザーごとにランダム
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, iterations
    )
    # ソルトと反復回数も一緒に保存する（あとで検証に必要）
    return f"{iterations}${salt.hex()}${dk.hex()}"

stored = hash_password("correct horse battery staple")
print(stored)   # 200000$<salt>$<hash> の形式で保存

import hmac

def verify_password(password, stored):
    iterations, salt_hex, hash_hex = stored.split("$")
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, int(iterations)
    )
    # タイミング攻撃を防ぐため compare_digest で比較
    return hmac.compare_digest(dk.hex(), hash_hex)

print(verify_password("correct horse battery staple", stored))  # True
print(verify_password("wrong password", stored))                # False

import time
for it in (10_000, 200_000, 1_000_000):
    t = time.time()
    hashlib.pbkdf2_hmac("sha256", b"pw", b"salt1234", it)
    print(f"{it:>9}回: {(time.time()-t)*1000:.1f} ms")
