from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import datetime
import random

# RSA 키 쌍 생성
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# RSA 키 쌍을 파일로 저장하는 함수
def save_rsa_keys_to_file(private_key, public_key, private_key_file='private_key.pem', public_key_file='public_key.pem'):
    # 개인키를 PEM 형식으로 직렬화
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 공개키를 PEM 형식으로 직렬화
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 개인키 파일 쓰기
    with open(private_key_file, 'wb') as priv_file:
        priv_file.write(pem_private)

    # 공개키 파일 쓰기
    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(pem_public)

    print(f"Keys saved to {private_key_file} and {public_key_file}")

# AES 키 생성
def generate_aes_key():
    return os.urandom(32)  # 256-bit 키

# 데이터를 AES로 암호화
def encrypt_with_aes(key, plaintext):
    iv = os.urandom(16)  # 초기화 벡터 생성
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext

# 데이터를 RSA로 암호화
def encrypt_with_rsa(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# AES 암호문을 복호화
def decrypt_with_aes(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# RSA 암호문을 복호화
def decrypt_with_rsa(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# 사용자 행동 데이터 시뮬레이션
user_activity_data = {
    'last_login': datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 10)),
    'login_frequency': random.randint(1, 10), # 1일에서 10일 사이의 빈도로 로그인
    'unusual_activity': random.choice([True, False]), # 비정상적 활동 유무
    'login_location_change': random.choice([True, False]) # 로그인 위치 변경 유무
}

#AI 모델
def ai_key_update_decision(user_activity_data):
    current_time = datetime.datetime.now()
    days_since_last_login = (current_time - user_activity_data['last_login']).days

    # 로그인 빈도 체크
    if days_since_last_login > user_activity_data['login_frequency']:
        return True

    # 비정상적 활동 또는 로그인 위치 변경 시 키 갱신
    if user_activity_data['unusual_activity'] or user_activity_data['login_location_change']:
        return True

    return False

# 하이브리드 암호화 시스템에 키 갱신 로직 통합
def main():
    # RSA 키 쌍 생성 및 파일에 저장
    private_key, public_key = generate_rsa_keys()
    save_rsa_keys_to_file(private_key, public_key)

    # 키 갱신 결정
    if ai_key_update_decision(user_activity_data):
        print("키 갱신 필요.")
        private_key, public_key = generate_rsa_keys() # 키 쌍 재생성
        save_rsa_keys_to_file(private_key, public_key) # 갱신된 키를 파일에 다시 저장

        # AES 키 생성 및 암호화
    aes_key = generate_aes_key()
    encrypted_aes_key = encrypt_with_rsa(public_key, aes_key)

    # 평문 암호화
    plaintext = b"Hello, this is a test message!"
    iv, encrypted_message = encrypt_with_aes(aes_key, plaintext)

    # 출력: 암호화된 메시지
    print(f"Encrypted message: {encrypted_message}")

    # 받은 AES 키와 암호문 복호화
    decrypted_aes_key = decrypt_with_rsa(private_key, encrypted_aes_key)
    decrypted_message = decrypt_with_aes(decrypted_aes_key, iv, encrypted_message)

    # 출력: 복호화된 메시지
    print(f"Original message: {plaintext}")
    print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    main()


