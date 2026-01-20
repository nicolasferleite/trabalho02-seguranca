import asyncio
import sys
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography import x509

from common.crypto_utils import CryptoManager
from common.protocol import pack_frame, unpack_frame


# ==========================================================
# Configuração de Caminhos e Constantes
# ==========================================================
# Localiza o certificado público do servidor para validar a autenticidade
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CERT_PATH = os.path.join(BASE_DIR, "certs", "server.crt")

# Tamanhos esperados na mensagem de Handshake do Servidor
PK_SIZE = 65        # Chave pública ECDH (ponto não compactado)
SALT_SIZE = 16      # Salt para derivação HKDF
SIG_SIZE = 256      # Assinatura RSA (2048 bits)
HANDSHAKE_SIZE = PK_SIZE + SALT_SIZE + SIG_SIZE


# ==========================================================
# Interface de Entrada Assíncrona
# ==========================================================
async def async_input(prompt):
    """
    Resolve o problema do input() travar o loop de eventos do asyncio.
    Executa a leitura em uma thread separada (executor).
    """
    print(prompt, end="", flush=True)
    return await asyncio.get_event_loop().run_in_executor(
        None, sys.stdin.readline
    )


# ==========================================================
# Fluxo de Saída: Envio de Mensagens
# ==========================================================
async def enviar_mensagens(writer, key_c2s, my_id):
    seq_send = 0  # Contador de sequência para evitar Replay Attacks
    await asyncio.sleep(1)  # Pequeno delay para garantir que a interface esteja pronta

    while True:
        try:
            line = await async_input("\nMensagem: ")
            msg = line.strip()
            if not msg: continue

            line_target = await async_input("Para (ID): ")
            target = line_target.strip()
            if not target: continue

            # CRIPTOGRAFIA DE DADOS (AES-GCM)
            nonce = os.urandom(12) # IV aleatório obrigatório por mensagem
            # AAD: Dados que o AES-GCM protege mas não cifra (Remetente | Destinatário | Seq)
            aad = (
                my_id.encode().ljust(16)[:16]
                + target.encode().ljust(16)[:16]
                + seq_send.to_bytes(8, "big")
            )

            ciphertext = CryptoManager.encrypt_data(
                key_c2s, nonce, aad, msg
            )

            # Empacota no formato binário do protocolo e envia via Socket
            writer.write(
                pack_frame(nonce, my_id, target, seq_send, ciphertext)
            )
            await writer.drain()

            print("✅ Enviada!")
            seq_send += 1 # Incrementa para garantir que a próxima mensagem seja única

        except Exception as e:
            print(f"❌ Erro ao enviar: {e}")


# ==========================================================
# Fluxo de Entrada: Recebimento de Mensagens
# ==========================================================
async def receber_mensagens(reader, key_s2c):
    while True:
        try:
            dados = await reader.read(4096)
            if not dados: break

            # Desempacota o frame recebido do servidor
            nonce, aad, sender, recipient, seq, ciphertext = unpack_frame(dados)
            
            # DECIFRAGEM: AES-GCM valida a Tag de Autenticidade aqui
            msg_clara = CryptoManager.decrypt_data(
                key_s2c, nonce, aad, ciphertext
            )

            # Exibe a mensagem de forma formatada (usando \r para não quebrar o prompt)
            print(
                f"\r[{sender}]: {msg_clara}\nMensagem: ",
                end="",
                flush=True,
            )

        except Exception:
            # Erros de decifração (ataque ou dados corrompidos) são ignorados silenciosamente
            pass


# ==========================================================
# Core do Cliente: Handshake e Autenticação
# ==========================================================
async def start_client(my_id):
    writer = None

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", 8888)
        print("🔌 Conectado ao servidor")

        # PASSO 1: Envio da chave pública ECDH efêmera do Cliente
        my_priv_ec, my_pk = CryptoManager.generate_ecdhe_keys()
        writer.write(my_id.encode().ljust(16)[:16] + my_pk)
        await writer.drain()

        # PASSO 2: Recebimento do Handshake assinado pelo Servidor
        data = b""
        while len(data) < HANDSHAKE_SIZE:
            chunk = await reader.read(HANDSHAKE_SIZE - len(data))
            if not chunk: break
            data += chunk

        if len(data) < HANDSHAKE_SIZE:
            raise Exception("Handshake incompleto do servidor")

        pk_s_raw = data[:PK_SIZE]
        salt = data[PK_SIZE : PK_SIZE + SALT_SIZE]
        assinatura = data[PK_SIZE + SALT_SIZE :]

        # PASSO 3: Validação da Autenticidade do Servidor (RSA)
        # O cliente usa o certificado local (server.crt) para checar a assinatura do servidor
        with open(CERT_PATH, "rb") as cert_file:
            server_cert = x509.load_pem_x509_certificate(cert_file.read())
            server_rsa_public = server_cert.public_key()

        # Verifica se a assinatura cobre (Chave_Pública_S | ID_Cliente | Salt)
        server_rsa_public.verify(
            assinatura,
            pk_s_raw + my_id.encode().ljust(16)[:16] + salt,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        print("✅ Servidor autenticado!")

        # PASSO 4: Troca de Chaves ECDH e Derivação HKDF
        pk_s_obj = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), pk_s_raw
        )
        shared_secret = my_priv_ec.exchange(ec.ECDH(), pk_s_obj)
        key_c2s, key_s2c = CryptoManager.derive_keys(shared_secret, salt)

        # PASSO 5: Início simultâneo de Envio e Recebimento
        await asyncio.gather(
            enviar_mensagens(writer, key_c2s, my_id),
            receber_mensagens(reader, key_s2c),
        )

    except Exception as e:
        print(f"❌ Erro no cliente: {e}")
    finally:
        if writer:
            writer.close()


if __name__ == "__main__":
    # Permite passar o ID por argumento: 'python main.py Alice'
    cid = sys.argv[1] if len(sys.argv) > 1 else input("Seu ID: ")
    asyncio.run(start_client(cid))