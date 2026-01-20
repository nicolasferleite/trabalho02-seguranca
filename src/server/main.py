import asyncio
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from common.crypto_utils import CryptoManager
from common.protocol import pack_frame, unpack_frame

# Configuração de caminhos para localizar a chave privada RSA do servidor
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
KEY_PATH = os.path.join(BASE_DIR, "certs", "server.key")

# Tabela hash (dicionário) que armazena o estado de cada cliente conectado
sessions = {}

async def handle_client(reader, writer):
    """Gerencia o ciclo de vida de um cliente: Handshake e Troca de Mensagens"""
    client_id = "Desconhecido"

    try:
        # 1. RECEBIMENTO DO HANDSHAKE INICIAL
        # O servidor lê o ID do cliente e sua chave pública efêmera (ECDHE)
        data = await reader.read(200)
        if not data:
            return

        client_id = data[:16].decode("utf-8", errors="ignore").strip()
        pk_c_raw = data[16:]

        # 2. GERAÇÃO DE CHAVES EFÊMERAS DO SERVIDOR
        # Cria o par de chaves ECDHE do servidor para garantir Forward Secrecy
        server_priv_ec, pk_s = CryptoManager.generate_ecdhe_keys()
        salt = os.urandom(16) # Salt aleatório para a derivação de chaves HKDF

        # 3. AUTENTICAÇÃO VIA ASSINATURA RSA
        # O servidor assina sua própria chave pública ECDHE para provar sua identidade
        with open(KEY_PATH, "rb") as key_file:
            server_rsa_private = serialization.load_pem_private_key(
                key_file.read(), password=None
            )

        # Assina: Chave_Pública_S + ID_Cliente + Salt
        signature = server_rsa_private.sign(
            pk_s + client_id.encode().ljust(16)[:16] + salt,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # Envia os dados para o cliente validar o servidor
        writer.write(pk_s + salt + signature)
        await writer.drain()

        # 4. DERIVAÇÃO DE CHAVES DE SESSÃO (DIFFIE-HELLMAN)
        # Calcula o segredo compartilhado Z
        pk_c_obj = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), pk_c_raw
        )
        shared_secret = server_priv_ec.exchange(ec.ECDH(), pk_c_obj)
        
        # Deriva chaves distintas para C -> S e S -> C (Segurança TLS 1.3)
        k_c2s, k_s2c = CryptoManager.derive_keys(shared_secret, salt)

        # Armazena a sessão com contadores de sequência para evitar Replay Attacks
        sessions[client_id] = {
            "writer": writer,
            "k_c2s": k_c2s, # Chave para decifrar o que vem do cliente
            "k_s2c": k_s2c, # Chave para cifrar o que vai para o cliente
            "seq_recv": -1, # Proteção contra repetição de mensagens antigas
            "seq_send": 0,  # Garante nonces únicos no envio
        }

        print(f"✅ {client_id} conectado")

        # 5. LOOP DE ROTEAMENTO DE MENSAGENS
        while True:
            msg_data = await reader.read(4096)
            if not msg_data:
                break

            # Desempacota o frame (Nonce, AAD, IDs, Seq, Ciphertext)
            nonce, aad, s_id, r_id, seq_rec, ciphertext = unpack_frame(msg_data)

            # VALIDAÇÃO ANTI-REPLAY: O número de sequência deve sempre crescer
            if seq_rec <= sessions[client_id]["seq_recv"]:
                continue
            sessions[client_id]["seq_recv"] = seq_rec

            # DECIFRAGEM E VALIDAÇÃO DE INTEGRIDADE (AES-GCM)
            plaintext = CryptoManager.decrypt_data(
                k_c2s, nonce, aad, ciphertext
            )

            # ENCAMINHAMENTO PARA O DESTINATÁRIO
            if r_id in sessions:
                dest = sessions[r_id]
                new_nonce = os.urandom(12)
                new_seq = dest["seq_send"]

                # Novo AAD para o novo trecho da comunicação
                new_aad = (
                    s_id.encode().ljust(16)[:16]
                    + r_id.encode().ljust(16)[:16]
                    + new_seq.to_bytes(8, "big")
                )

                # RE-CIFRAGEM: O servidor cifra com a chave específica do destinatário
                new_ct = CryptoManager.encrypt_data(
                    dest["k_s2c"], new_nonce, new_aad, plaintext
                )

                dest["writer"].write(
                    pack_frame(new_nonce, s_id, r_id, new_seq, new_ct)
                )
                await dest["writer"].drain()
                dest["seq_send"] += 1

    except Exception as e:
        print(f"❌ Erro na sessão {client_id}: {e}")

    finally:
        # Limpeza: remove o cliente da tabela ao desconectar
        if client_id in sessions:
            del sessions[client_id]
        writer.close()

async def main():
    # Inicia o servidor na porta 8888
    server = await asyncio.start_server(handle_client, "127.0.0.1", 8888)
    print("🚀 SERVIDOR ATIVO em 127.0.0.1:8888")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())