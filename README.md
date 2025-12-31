# Log Analyzer - Detecção de Força Bruta

Projeto em Python que analisa arquivos de log de autenticação e identifica possíveis ataques de força bruta com base em tentativas de login falhas por IP.

## 📌 Funcionalidades
- Leitura de logs de autenticação
- Contagem de tentativas de login falhas
- Identificação de IPs suspeitos
- Geração de relatório no terminal

## 🛠️ Tecnologias
- Python 3
- Regex
- Collections (defaultdict)

## ▶️ Como executar
1. Clone o repositório
2. Certifique-se de que o arquivo `auth.log` está na mesma pasta do script
3. Execute:
```bash
python analyzer.py
