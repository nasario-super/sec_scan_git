# 🔒 GitHub Organization Security Scanner

Uma ferramenta completa para análise de segurança automatizada de todos os repositórios de uma organização GitHub, com **API REST** e **Dashboard Web** profissional.

## ✨ Funcionalidades

- **Detecção de Secrets**: Encontra API keys, tokens, senhas e outras informações sensíveis
- **Scanner de Vulnerabilidades**: Analisa dependências em busca de CVEs conhecidas
- **Análise SAST**: Detecta bugs de segurança como SQL Injection, XSS, Command Injection
- **Scanner de IaC**: Verifica misconfigurations em Terraform, Kubernetes, Docker
- **Análise de Histórico**: Encontra secrets que foram removidas mas ainda estão no git history
- **Classificação de Estado**: ACTIVE, HISTORICAL, HARDCODED
- **🌐 Dashboard Web**: Interface React moderna com gráficos e visualizações
- **🔌 API REST**: FastAPI para integração com outros sistemas
- **📊 Gerenciamento de Remediação**: Track de status e histórico de correções

## 📦 Instalação

```bash
# Clone o repositório
git clone https://github.com/your-org/github-security-scanner.git
cd github-security-scanner

# Instale com pip
pip install -e .

# Ou com dependências de desenvolvimento
pip install -e ".[dev]"
```

## 🚀 Uso Rápido

```bash
# Scan completo de uma organização
github-security-scanner scan --org sua-org --token $GITHUB_TOKEN

# Scan de um repositório específico
github-security-scanner scan-repo --repo owner/repo --token $GITHUB_TOKEN

# Iniciar console interativo
github-security-scanner console

# Ver dashboard
github-security-scanner dashboard

# Listar repositórios
github-security-scanner list-repos --org sua-org --token $GITHUB_TOKEN

# Gerar configuração padrão
github-security-scanner config --init
```

## 🖥️ Console Interativo

O scanner inclui uma console interativa para gerenciar scans e findings:

```bash
github-security-scanner console
```

### Comandos da Console

| Comando | Descrição |
|---------|-----------|
| `help` | Mostrar comandos disponíveis |
| `dashboard` | Mostrar dashboard principal |
| `scan <org>` | Executar novo scan |
| `scans` | Listar histórico de scans |
| `show <id>` | Mostrar detalhes do scan |
| `findings` | Listar findings |
| `finding <id>` | Detalhes do finding |
| `status <id> <status>` | Atualizar status do finding |
| `compare <id1> <id2>` | Comparar dois scans |
| `trends <org>` | Mostrar tendências |
| `retest <org>` | Retest para verificar correções |
| `export <id>` | Exportar relatório |

### Gerenciamento de Remediação

```bash
# Listar findings abertos
github-security-scanner findings --status open

# Listar apenas críticos
github-security-scanner findings --severity critical

# Atualizar status de um finding
github-security-scanner update-status abc123 fixed --comment "Fixed in PR #456"

# Comparar dois scans para ver o que foi corrigido
github-security-scanner diff scan1 scan2

# Ver tendências ao longo do tempo
github-security-scanner trends minha-org --days 30
```

### Status de Remediação

| Status | Descrição |
|--------|-----------|
| `open` | Finding não resolvido |
| `in_progress` | Em processo de correção |
| `fixed` | Corrigido |
| `wont_fix` | Não será corrigido |
| `false_positive` | Falso positivo |
| `accepted_risk` | Risco aceito |

## 📋 Comandos

### `scan` - Escanear Organização

```bash
github-security-scanner scan \
  --org minha-org \
  --token $GITHUB_TOKEN \
  --include-historical \        # Incluir análise de histórico git
  --languages python,javascript \
  --exclude-repos "test-*,deprecated-*" \
  --severity-threshold medium \
  --output-format json,html,sarif \
  --output-dir ./reports \
  --parallel 8
```

### `scan-repo` - Escanear Repositório

```bash
github-security-scanner scan-repo \
  --repo owner/repo-name \
  --token $GITHUB_TOKEN \
  --branch main \
  --full-history
```

### `config` - Gerenciar Configuração

```bash
# Criar arquivo de configuração padrão
github-security-scanner config --init

# Validar configuração
github-security-scanner config --validate

# Mostrar configuração atual
github-security-scanner config --show
```

## ⚙️ Configuração

Crie um arquivo `config.yaml`:

```yaml
github:
  token: ${GITHUB_TOKEN}
  api_url: https://api.github.com
  timeout: 30

scan:
  parallel_repos: 4
  clone_strategy: shallow  # full, shallow, sparse
  analyze_history: true
  history_depth: 1000
  exclude_repos:
    - "*-deprecated"
    - "archive-*"
  exclude_paths:
    - "node_modules/"
    - "vendor/"
    - ".git/"

analyzers:
  secrets_enabled: true
  vulnerabilities_enabled: true
  sast_enabled: true
  iac_enabled: true

output:
  formats:
    - json
    - html
  directory: ./reports
  redact_secrets: true
```

## 📊 Formatos de Saída

- **JSON**: Resultado completo em formato JSON
- **HTML**: Relatório visual interativo
- **SARIF**: Compatível com GitHub Security tab
- **CSV**: Para análise em planilhas

## 🔍 Tipos de Findings

### Secrets Detectados
- AWS Access Keys / Secret Keys
- GitHub Tokens (PAT, Fine-grained)
- Private Keys (RSA, EC, OpenSSH)
- API Keys genéricos
- Database URLs com credenciais
- Slack/Stripe/SendGrid tokens
- E muito mais...

### Vulnerabilidades
- Dependências Python (pip-audit, safety)
- Dependências JavaScript (npm audit)
- Dependências Go (govulncheck)
- Análise genérica com Trivy

### Bugs SAST
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Insecure Deserialization
- Weak Cryptography

### Misconfigurations IaC
- S3 Buckets sem encryption
- Security Groups abertos
- Containers privilegiados
- Kubernetes sem security context
- Docker rodando como root

## 🏷️ Estados dos Findings

| Estado | Descrição |
|--------|-----------|
| **ACTIVE** | Presente no código atual, risco imediato |
| **HISTORICAL** | Removido mas ainda no git history |
| **HARDCODED** | Valor literal no código (vs env var) |

Um finding pode ter múltiplos estados (ex: ACTIVE + HARDCODED).

## 🔐 Segurança

A ferramenta segue boas práticas de segurança:
- Nunca loga tokens ou secrets em plaintext
- Sanitiza outputs antes de salvar
- Limpa clones após análise
- Respeita rate limits do GitHub
- Suporte a proxy corporativo

## 🧪 Desenvolvimento

```bash
# Instalar dependências de desenvolvimento
pip install -e ".[dev]"

# Rodar testes
pytest

# Verificar código
ruff check src/
mypy src/

# Formatar código
ruff format src/
```

## 📁 Estrutura do Projeto

```
github-security-scanner/
├── src/github_security_scanner/
│   ├── cli.py              # Interface de linha de comando
│   ├── core/
│   │   ├── scanner.py      # Orquestrador principal
│   │   ├── config.py       # Gestão de configuração
│   │   └── models.py       # Modelos de dados
│   ├── github/
│   │   ├── client.py       # Cliente GitHub API
│   │   └── repository.py   # Operações com repos
│   ├── analyzers/
│   │   ├── secrets.py      # Detector de secrets
│   │   ├── vulnerabilities.py
│   │   ├── sast.py
│   │   ├── iac.py
│   │   └── history.py
│   ├── classifiers/
│   │   ├── state.py        # Classificador de estado
│   │   └── severity.py
│   ├── reporters/
│   │   ├── json_reporter.py
│   │   ├── html_reporter.py
│   │   ├── sarif_reporter.py
│   │   └── csv_reporter.py
│   ├── storage/
│   │   ├── database.py     # Banco SQLite para persistência
│   │   └── models.py       # Modelos de dados do banco
│   └── api/
│       ├── app.py          # FastAPI REST API
│       └── __init__.py
├── web/                     # Dashboard React
│   ├── src/
│   │   ├── components/     # Componentes reutilizáveis
│   │   ├── pages/          # Páginas da aplicação
│   │   ├── hooks/          # React hooks customizados
│   │   ├── lib/            # Utilitários e API client
│   │   └── types/          # TypeScript types
│   ├── package.json
│   └── Dockerfile
├── patterns/
│   ├── secrets.yaml
│   ├── sast_rules.yaml
│   └── iac_checks.yaml
├── docker-compose.yml       # Deploy com Docker
├── Dockerfile
└── tests/
```

## 🐳 Deploy com Docker

```bash
# Build e iniciar todos os serviços
docker-compose up -d

# Acessar o dashboard
open http://localhost:3000

# Ver logs
docker-compose logs -f
```

## 📄 Licença

MIT License - veja [LICENSE](LICENSE) para detalhes.

## 🌐 Dashboard Web

O scanner inclui um **Dashboard Web** profissional construído com React, TypeScript e Tailwind CSS.

### Iniciando a API

```bash
# Instalar dependências
pip install -e .

# Iniciar o servidor API (porta 8000)
gss-api

# Ou manualmente
uvicorn github_security_scanner.api.app:app --reload --port 8000
```

### Iniciando o Frontend

```bash
# Entrar na pasta web
cd web

# Instalar dependências
npm install

# Iniciar o servidor de desenvolvimento (porta 3000)
npm run dev
```

### Acessando o Dashboard

Abra [http://localhost:3000](http://localhost:3000) no seu navegador.

### Funcionalidades do Dashboard

| Página | Descrição |
|--------|-----------|
| **Dashboard** | Visão geral com stats, gráficos de tendência, findings críticos |
| **Scans** | Histórico de scans, detalhes por scan, filtros por organização |
| **Findings** | Lista completa de findings com filtros por severidade, tipo, status |
| **Repositórios** | Visão por repositório com contagem de findings |
| **Novo Scan** | Interface para iniciar novos scans |
| **Comparar** | Comparação entre dois scans para ver novos/corrigidos |

### Screenshots

#### Dashboard Principal
- Cards com estatísticas (Total Scans, Findings Abertos, Corrigidos, Em Progresso)
- Gráfico de tendência de findings ao longo do tempo
- Distribuição por severidade (pizza)
- Lista de scans recentes
- Top repositórios mais afetados

#### Gestão de Findings
- Tabela com filtros avançados
- Busca por categoria, repositório, arquivo
- Atualização de status diretamente na interface
- Detalhes completos com código fonte e remediação

### Tema Visual

O dashboard usa um tema cyberpunk/hacker moderno:
- **Cores**: Verde neon (#00ff9f), Cyan (#00d9ff), fundo escuro
- **Tipografia**: JetBrains Mono (código), Space Grotesk (títulos)
- **Badges de severidade**: Crítico (vermelho), Alto (laranja), Médio (amarelo), Baixo (verde)
- **Animações**: Transições suaves com Framer Motion

## 🔌 API REST

A API REST permite integração com outros sistemas e automação.

### Endpoints Principais

```
GET  /api/dashboard         - Estatísticas do dashboard
GET  /api/trends            - Dados de tendência
GET  /api/scans             - Listar scans
POST /api/scans             - Iniciar novo scan de organização
POST /api/scans/repo        - Iniciar scan de repositório
GET  /api/scans/{id}        - Detalhes do scan
GET  /api/scans/{id}/status - Status de scan em execução
GET  /api/scans/compare     - Comparar dois scans
GET  /api/findings          - Listar findings
GET  /api/findings/{id}     - Detalhes do finding
PATCH /api/findings/{id}/status - Atualizar status
GET  /api/organizations     - Listar organizações escaneadas
GET  /api/health            - Health check
```

### Exemplos de Uso

```bash
# Listar scans
curl http://localhost:8000/api/scans

# Iniciar novo scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"organization": "minha-org", "token": "ghp_xxx"}'

# Atualizar status de finding
curl -X PATCH http://localhost:8000/api/findings/abc123/status \
  -H "Content-Type: application/json" \
  -d '{"status": "fixed", "comment": "Corrigido no PR #456"}'

# Comparar dois scans
curl "http://localhost:8000/api/scans/compare?baseline=scan1&current=scan2"
```

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor, leia [CONTRIBUTING.md](docs/contributing.md) para guidelines.

