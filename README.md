Aqui está o README simples e direto para sua tool:

markdown
# 🔒 Security Headers Scanner

Ferramenta para análise de headers de segurança em aplicações web.

## 🚀 Como Usar


python3 scanner.py


Digite a URL quando solicitado e veja o relatório completo.

## 📊 O que a Ferramenta Verifica

### 🔴 Alta Prioridade
- **X-Frame-Options** - Proteção contra Clickjacking
- **Content-Security-Policy** - Proteção contra XSS
- **Strict-Transport-Security** - Força HTTPS
- **X-Content-Type-Options** - Previne MIME Sniffing
- **Cookies Secure/HttpOnly** - Segurança de sessão

### 🟡 Média Prioridade
- **Referrer-Policy** - Controle de informação de referência
- **X-XSS-Protection** - Proteção XSS do navegador
- **Feature-Policy** - Controle de features do browser

### 🔵 Information Disclosure
- **Server** - Vazamento de versão do servidor
- **X-Powered-By** - Vazamento de tecnologia
- **X-AspNet-Version** - Vazamento do .NET

## 🎯 Para Bug Bounty

Foque nas vulnerabilidades marcadas em **VERMELHO** - são as mais críticas e fáceis de explorar!

## 📝 Exemplo de Uso


Digite o target URL (ex: https://alvo.com): https://exemplo.com

✅ Protegido     ❌ Vulnerável     ⚠️ Warning


## 🛠 Requisitos

pip install requests


## 👨💻 Desenvolvido por

**Miguel Vasco** - Hacker Ético



*Use com responsabilidade e apenas em targets autorizados!*


Quer que eu adicione mais alguma seção ou explique algo específico?