🛡️ Secure Messaging App - Guia de Execução
Este guia descreve os passos necessários para configurar e rodar a aplicação de chat seguro com criptografia de ponta a ponta em ambiente Windows (PowerShell).

📂 Estrutura de Pastas Esperada
Certifique-se de que seus arquivos estão organizados desta forma:

secure-messaging/
├── certs/                 # Certificados e chaves RSA (Gerados localmente)
├── src/
│   ├── client/            # Lógica do usuário final
│   ├── server/            # Gerenciamento de sessões e roteamento
│   └── common/            # Protocolo e utilitários criptográficos
├── gerar_certificados.py   # Script de inicialização de credenciais
└── requirements.txt        # Dependências do Python

🛠️ 1. Instalação das Dependências
O projeto utiliza a biblioteca cryptography. Instale-a via terminal:

PowerShell
pip install cryptography
🔑 2. Geração de Certificados (RSA)
O servidor precisa de um par de chaves RSA para assinar o handshake. Rode o script de geração na raiz do projeto:

PowerShell
python gerar_certificados.py
Isso criará a pasta certs/ com os arquivos server.key e server.crt. O cliente usará o .crt para validar a identidade do servidor.

🚀 3. Como Rodar a Aplicação
Siga a ordem abaixo rigorosamente. Abra um novo terminal para cada comando e certifique-se de estar na pasta raiz (secure-messaging).

Passo 1: Iniciar o Servidor
No primeiro terminal, configure o ambiente e inicie o servidor:

PowerShell
$env:PYTHONPATH = "src"
python src/server/main.py
Resultado esperado: O terminal exibirá: 🚀 SERVIDOR ATIVO em 127.0.0.1:8888.

Passo 2: Iniciar Cliente Alice
No segundo terminal, abra a conexão para a Alice:

PowerShell
$env:PYTHONPATH = "src"
python src/client/main.py Alice
Resultado esperado: O terminal exibirá: 🔌 Conectado ao servidor e ✅ Servidor autenticado!.

Passo 3: Iniciar Cliente Bob
No terceiro terminal, abra a conexão para o Bob:

PowerShell
$env:PYTHONPATH = "src"
python src/client/main.py Bob
💬 4. Como Trocar Mensagens
Com todos os terminais abertos:

No terminal da Alice:

No campo Mensagem:, digite o texto e aperte Enter.

No campo Para (ID):, digite Bob (exatamente como o ID do outro cliente) e aperte Enter.

No terminal do Bob:

A mensagem aparecerá como: [Alice]: <conteúdo da mensagem>.

O Bob pode responder digitando a mensagem e definindo o destino como Alice.
