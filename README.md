# 🔒 GitHub Security Scanner (GSS)

Uma ferramenta completa e profissional para análise de segurança automatizada de repositórios GitHub, com **Dashboard Web**, **API REST**, **Sistema de Autenticação** e arquitetura pronta para produção.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![React](https://img.shields.io/badge/react-18+-61DAFB.svg)
![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg)

## ✨ Funcionalidades

### 🔍 Análise de Segurança
- **Detecção de Secrets**: API keys, tokens, senhas, chaves privadas
- **Scanner de Vulnerabilidades**: CVEs em dependências
- **Análise SAST**: SQL Injection, XSS, Command Injection
- **Scanner de IaC**: Terraform, Kubernetes, Docker misconfigurations
- **Análise de Histórico Git**: Secrets removidos mas ainda no histórico

### 🌐 Interface Web
- **Dashboard**: Visão geral com gráficos e estatísticas
- **Findings**: Lista filtrada de vulnerabilidades encontradas
- **Scans**: Histórico e execução de novos scans
- **Repositories**: Visão por repositório
- **Trends**: Gráficos de evolução temporal
- **History**: Timeline de atividades
- **Export CSV**: Exportação de dados

### 🔐 Segurança & Autenticação
- **Login com JWT**: Tokens de acesso e refresh
- **Gestão de Usuários**: Criar, editar, desativar usuários
- **Roles**: Admin, Analyst, Viewer
- **Proteção de Rotas**: Acesso baseado em permissões

### ⚙️ Arquitetura
- **Microserviços**: API, Worker, Scheduler, Frontend
- **PostgreSQL**: Banco de dados persistente
- **Redis**: Cache e filas de tarefas
- **Docker Compose**: Ambiente completo local
- **Kubernetes Ready**: Manifests inclusos
- **AWS Ready**: Terraform para deploy

## 🚀 Quick Start

### Pré-requisitos
- Docker e Docker Compose
- Git

### Instalação

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/sec_scan_git.git
cd sec_scan_git

# Copie o arquivo de exemplo e configure
cp .env.example .env
# Edite .env com suas configurações (opcional para desenvolvimento)

# Inicie todos os serviços
docker compose up -d

# Acesse o dashboard
open http://localhost
```

### Credenciais Padrão
- **Usuário**: `admin`
- **Senha**: `admin`

> ⚠️ **Importante**: Altere a senha do admin em produção!

## 📖 Uso

### Via Dashboard Web

1. Acesse http://localhost
2. Faça login com `admin` / `admin`
3. Vá para **Scans** → **New Scan**
4. Insira sua organização GitHub e token
5. Escolha o modo de scan:
   - **API Only**: Mais rápido, sem clone (recomendado)
   - **Shallow**: Clone superficial
   - **Full**: Clone completo com histórico
6. Clique em **Start Scan**

### Via API REST

```bash
# Login
curl -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'

# Iniciar scan (use o token retornado)
curl -X POST http://localhost/api/scans \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "organization": "sua-org",
    "token": "ghp_seu_token_github",
    "scan_mode": "api_only"
  }'

# Listar findings
curl http://localhost/api/findings \
  -H "Authorization: Bearer <TOKEN>"
```

### Via CLI

```bash
# Instalar o pacote
pip install -e .

# Scan de organização
github-security-scanner scan --org minha-org --token $GITHUB_TOKEN

# Scan de repositório específico
github-security-scanner scan-repo --repo owner/repo --token $GITHUB_TOKEN
```

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend                              │
│                   (React + TypeScript)                       │
│                      Port: 80                                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         Nginx                                │
│                   (Reverse Proxy)                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      API Service                             │
│                (FastAPI + Uvicorn)                           │
│                    Port: 8000                                │
└─────────────────────────────────────────────────────────────┘
                    │                   │
          ┌─────────┘                   └─────────┐
          ▼                                       ▼
┌─────────────────────┐             ┌─────────────────────────┐
│     PostgreSQL      │             │         Redis           │
│   (Data Storage)    │             │   (Cache & Queues)      │
│     Port: 5432      │             │      Port: 6379         │
└─────────────────────┘             └─────────────────────────┘
```

## 📁 Estrutura do Projeto

```
sec_scan_git/
├── frontend/                    # Dashboard React
│   ├── src/
│   │   ├── components/         # Componentes reutilizáveis
│   │   ├── contexts/           # Context API (Auth)
│   │   ├── pages/              # Páginas da aplicação
│   │   ├── services/           # API client
│   │   ├── stores/             # Zustand stores
│   │   └── types/              # TypeScript types
│   └── package.json
├── src/github_security_scanner/ # Backend Python
│   ├── api/                    # FastAPI endpoints
│   │   ├── app.py             # Aplicação principal
│   │   ├── auth.py            # Autenticação JWT
│   │   └── security.py        # Segurança da API
│   ├── analyzers/              # Analisadores de segurança
│   │   ├── secrets.py         # Detecção de secrets
│   │   ├── api_scanner.py     # Scanner via API GitHub
│   │   ├── sast.py            # Análise estática
│   │   ├── iac.py             # Infrastructure as Code
│   │   └── vulnerabilities.py # CVE scanner
│   ├── core/                   # Core do scanner
│   │   ├── scanner.py         # Orquestrador principal
│   │   ├── config.py          # Configurações
│   │   └── models.py          # Modelos de dados
│   ├── storage/                # Persistência
│   │   ├── database.py        # SQLite (dev)
│   │   └── postgres_database.py # PostgreSQL (prod)
│   └── github/                 # Cliente GitHub
├── infrastructure/
│   ├── docker/                 # Dockerfiles
│   ├── kubernetes/             # K8s manifests
│   └── terraform/              # IaC para AWS
├── patterns/                   # Regras de detecção
│   ├── secrets.yaml           # Padrões de secrets
│   ├── sast_rules.yaml        # Regras SAST
│   └── iac_checks.yaml        # Checks de IaC
├── docker-compose.yml          # Ambiente local
├── .env.example                # Template de configuração
└── pyproject.toml              # Dependências Python
```

## 🔌 API Endpoints

### Autenticação
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/auth/login` | Login (retorna JWT) |
| POST | `/api/auth/refresh` | Refresh token |
| GET | `/api/auth/me` | Usuário atual |
| POST | `/api/auth/change-password` | Alterar senha |

### Usuários (Admin)
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/users` | Listar usuários |
| POST | `/api/users` | Criar usuário |
| PATCH | `/api/users/{id}` | Atualizar usuário |
| DELETE | `/api/users/{id}` | Desativar usuário |
| POST | `/api/users/{id}/reset-password` | Resetar senha |

### Scans
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/scans` | Listar scans |
| POST | `/api/scans` | Iniciar scan de org |
| POST | `/api/scans/repo` | Scan de repositório |
| GET | `/api/scans/{id}` | Detalhes do scan |
| GET | `/api/scans/{id}/status` | Status em tempo real |

### Findings
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/findings` | Listar findings |
| GET | `/api/findings/{id}` | Detalhes do finding |
| PATCH | `/api/findings/{id}/status` | Atualizar status |
| GET | `/api/findings/export/csv` | Exportar CSV |

### Dashboard
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/dashboard` | Estatísticas gerais |
| GET | `/api/trends` | Dados de tendência |
| GET | `/api/history` | Histórico de atividades |
| GET | `/api/repositories` | Lista de repositórios |

## 🔍 Tipos de Findings

### Secrets Detectados
- AWS Access Keys / Secret Keys
- GitHub Tokens (PAT, Fine-grained, OAuth)
- Google API Keys / Service Accounts
- Azure / GCP credentials
- Private Keys (RSA, EC, OpenSSH)
- Database URLs com credenciais
- JWT Secrets
- Slack, Stripe, SendGrid, Twilio tokens
- Chaves PIX, tokens de pagamento BR

### Severidades
| Nível | Descrição | Cor |
|-------|-----------|-----|
| **Critical** | Exposição imediata de acesso | 🔴 Vermelho |
| **High** | Risco significativo | 🟠 Laranja |
| **Medium** | Risco moderado | 🟡 Amarelo |
| **Low** | Risco baixo | 🟢 Verde |
| **Info** | Informacional | ⚪ Cinza |

## ⚙️ Configuração

### Variáveis de Ambiente

```bash
# Database
POSTGRES_USER=gss
POSTGRES_PASSWORD=sua_senha_segura
POSTGRES_DB=gss_db

# Security
GSS_SECRET_KEY=sua_chave_secreta_32_chars
GSS_AUTH_ENABLED=true

# GitHub
GITHUB_TOKEN=ghp_seu_token
# Ou GitHub App
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY=/path/to/key.pem
```

### Arquivo config.yaml

```yaml
github:
  token: ${GITHUB_TOKEN}
  api_url: https://api.github.com

scan:
  parallel_repos: 4
  clone_strategy: shallow
  analyze_history: false
  exclude_repos:
    - "*-deprecated"
    - "archive-*"

analyzers:
  secrets_enabled: true
  vulnerabilities_enabled: true
  sast_enabled: true
  iac_enabled: true

output:
  formats: [json, html]
  redact_secrets: true
```

## 🐳 Docker Commands

```bash
# Iniciar todos os serviços
docker compose up -d

# Ver logs
docker compose logs -f api

# Reiniciar serviço específico
docker compose restart api

# Parar tudo
docker compose down

# Limpar volumes (⚠️ apaga dados!)
docker compose down -v
```

## 🧪 Desenvolvimento

```bash
# Backend
pip install -e ".[dev]"
pytest
ruff check src/

# Frontend
cd frontend
npm install
npm run dev
npm run build
```

## 🔐 Segurança

- ✅ Tokens nunca são logados em plaintext
- ✅ Secrets são mascarados nos logs
- ✅ JWT com expiração configurável
- ✅ Bcrypt para hash de senhas
- ✅ Rate limiting na API
- ✅ CORS configurável
- ✅ Sanitização de inputs

## 📊 Modos de Scan

| Modo | Velocidade | Profundidade | Uso |
|------|------------|--------------|-----|
| **API Only** | ⚡ Rápido | Superficial | Organizações grandes |
| **Shallow** | 🔄 Médio | Moderada | Uso geral |
| **Full** | 🐢 Lento | Completa | Análise detalhada |

## 🚀 Deploy em Produção

### AWS (ECS + Aurora)
```bash
cd infrastructure/terraform
terraform init
terraform plan
terraform apply
```

### Kubernetes
```bash
kubectl apply -f infrastructure/kubernetes/
```

## 📄 Licença

MIT License - veja [LICENSE](LICENSE) para detalhes.

## 🤝 Contribuindo

1. Fork o projeto
2. Crie sua feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add: AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

---

**Desenvolvido com ❤️ para a segurança de código**
