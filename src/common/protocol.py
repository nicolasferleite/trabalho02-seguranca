import struct

# Definição dos tamanhos fixos em bytes para garantir um protocolo rígido
NONCE_SIZE = 12   # Tamanho do IV/Nonce para o AES-GCM
ID_SIZE = 16      # Tamanho fixo para IDs de usuários (Alice, Bob, etc.)
SEQ_SIZE = 8      # Tamanho de um inteiro de 64 bits (Sequence Number)

# O AAD (Additional Authenticated Data) são dados que não são cifrados,
# mas que o AES-GCM protege contra qualquer tipo de alteração.
# Estrutura: Sender_ID (16) + Recipient_ID (16) + Seq_No (8) = 40 bytes
AAD_SIZE = ID_SIZE + ID_SIZE + SEQ_SIZE


def pack_frame(nonce, sender_id, recipient_id, seq_no, ciphertext):
    """
    Transforma os dados em um pacote binário pronto para envio.
    Estrutura final: [NONCE][SENDER][RECIPIENT][SEQ][CIPHERTEXT]
    """
    # Garante que os IDs tenham exatamente 16 bytes (preenche com espaços se menor)
    s_id = sender_id.encode().ljust(ID_SIZE)[:ID_SIZE]
    r_id = recipient_id.encode().ljust(ID_SIZE)[:ID_SIZE]
    
    # Converte o número de sequência para binário (unsigned long long - 8 bytes, Big-Endian)
    seq_bytes = struct.pack(">Q", seq_no)
    
    # Concatena tudo em uma única sequência de bytes para o socket
    return nonce + s_id + r_id + seq_bytes + ciphertext


def unpack_frame(data):
    """
    Desconstrói o pacote binário recebido para extrair as informações.
    """
    # Extrai o Nonce (primeiros 12 bytes)
    nonce = data[:NONCE_SIZE]
    
    # Extrai os dados que compõem o AAD (os 40 bytes seguintes)
    aad = data[NONCE_SIZE : NONCE_SIZE + AAD_SIZE]

    # Decodifica os IDs e remove os espaços em branco (strip)
    sender_id = aad[:ID_SIZE].decode("utf-8", errors="ignore").strip()
    recipient_id = aad[ID_SIZE:32].decode("utf-8", errors="ignore").strip()
    
    # Converte os 8 bytes do contador de volta para um número inteiro
    seq_no = struct.unpack(">Q", aad[32:40])[0]

    # O que restar no pacote após o cabeçalho é o texto cifrado + a Tag do GCM
    ciphertext = data[NONCE_SIZE + AAD_SIZE :]
    
    return nonce, aad, sender_id, recipient_id, seq_no, ciphertext