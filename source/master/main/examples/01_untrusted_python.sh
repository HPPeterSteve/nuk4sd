#!/bin/bash
# ======================================================================
# Caso de Uso 1: Execução de Código Não Confiável (Serverless / CI/CD)
# ======================================================================
# Este script simula o que o GitHub Actions ou AWS Lambda fazem:
# Executar código Python enviado por um usuário sem permitir que ele:
# 1. Roube dados do servidor (sem acesso a /home ou /etc sensíveis)
# 2. Faça requisições maliciosas para fora (sem acesso à rede)
# 3. Injete arquivos persistentes no disco (tudo é rodado em tmpfs efêmero)

echo -e "\e[1;34m[+] Gerando payload malicioso em Python...\e[0m"
cat << 'EOF' > /tmp/malicious_payload.py
import urllib.request
import os

print("\n--- INICIANDO PAYLOAD MALICIOSO ---")

# Teste 1: Roubo de rede (Ex: exfiltrar dados ou minerar cripto)
print("1. Tentando conectar na rede externa (google.com)...")
try:
    urllib.request.urlopen("http://google.com", timeout=2)
    print("   [CRÍTICO] Conseguiu acessar a rede externa! (ESCAPE)")
except Exception as e:
    print(f"   [SEGURO] Rede bloqueada: {e}")

# Teste 2: Roubo de credenciais do host
print("\n2. Tentando ler chaves SSH ou arquivos do host...")
try:
    # Tenta listar o diretório home real do host
    # Como não usamos --rw-home, o /home do sandbox deve estar vazio
    home_dir = os.listdir("/home")
    if len(home_dir) > 0:
         print(f"   [CRÍTICO] Acesso ao /home real: {home_dir} (ESCAPE)")
    else:
         print("   [SEGURO] O diretório /home está vazio.")
except Exception as e:
    print(f"   [SEGURO] Acesso negado ao host: {e}")

# Teste 3: Alteração do sistema
print("\n3. Tentando criar arquivo na raiz do sistema...")
try:
    with open("/hacked.txt", "w") as f:
        f.write("hacked")
    print("   [CRÍTICO] Conseguiu escrever na raiz! (ESCAPE)")
except Exception as e:
    print(f"   [SEGURO] Sistema de arquivos é Read-Only: {e}")

print("-----------------------------------\n")
EOF

echo -e "\e[1;33m[!] Executando Payload com NUK4SD (Sem privilégios, Sem Rede)...\e[0m"

# Nós usamos:
# --no-fuse: Roda diretório em /tmp efêmero sem precisar montar vault
# --no-net: Remove interface de rede (isla a rede totalmente)
# --ro /tmp/malicious_payload.py: Injeta o script apenas como leitura
# --run: Executa o interpretador python
./target/release/Nuk4sd --no-fuse --no-net --ro /tmp/malicious_payload.py --run /usr/bin/python3 -- /tmp/malicious_payload.py

echo -e "\e[1;32m[+] Fim da demonstração.\e[0m"
