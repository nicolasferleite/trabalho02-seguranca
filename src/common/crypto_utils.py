from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoManager:
    """Classe responsável por todas as operações criptográficas do sistema."""

    @staticmethod
    def generate_ecdhe_keys():
        """
        Gera um par de chaves efêmeras usando a curva elíptica SECP256R1 (P-256).
        Isso garante o Sigilo Perfeito (Forward Secrecy).
        """
        # Gera a chave privada efêmera (existirá apenas durante esta sessão)
        priv_key = ec.generate_private_key(ec.SECP256R1())
        
        # Serializa a chave pública para o formato binário X962 (ponto não compactado)
        # para que possa ser enviada pela rede para o outro par (peer).
        pub_key = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return priv_key, pub_key

    @staticmethod
    def derive_keys(shared_secret, salt):
        """
        Aplica o protocolo HKDF (TLS 1.3) para transformar o segredo compartilhado 
        em chaves simétricas seguras e distintas para cada direção.
        """
        # FASE 1: HKDF-Extract
        # Transforma o segredo compartilhado (que pode ter baixa entropia) em uma 
        # Chave Mestra de Pseudorrandomização (PRK) usando o salt aleatório.
        prk = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=None,
        ).derive(shared_secret)

        # FASE 2: HKDF-Expand (Chave Cliente -> Servidor)
        # Deriva uma chave de 16 bytes (AES-128) específica para o fluxo de subida.
        key_c2s = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b"c2s", # Label que diferencia as chaves
        ).derive(prk)

        # FASE 2: HKDF-Expand (Chave Servidor -> Cliente)
        # Deriva uma chave de 16 bytes (AES-128) específica para o fluxo de descida.
        key_s2c = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b"s2c", # Label que diferencia as chaves
        ).derive(prk)

        return key_c2s, key_s2c

    @staticmethod
    def encrypt_data(key, nonce, aad, plaintext):
        """
        Criptografia AEAD (AES-GCM): Garante Confidencialidade e Integridade.
        """
        aesgcm = AESGCM(key)
        # Cifra o texto plano e gera a Tag de Autenticação baseada no Nonce e AAD.
        return aesgcm.encrypt(nonce, plaintext.encode(), aad)

    @staticmethod
    def decrypt_data(key, nonce, aad, ciphertext):
        """
        Descriptografia AEAD: Valida a Tag antes de entregar o texto.
        """
        aesgcm = AESGCM(key)
        # O método decrypt verifica automaticamente se a Tag de Autenticação é válida.
        # Se os dados (ciphertext ou AAD) foram alterados, ele lança uma exceção.
        return aesgcm.decrypt(nonce, ciphertext, aad).decode()