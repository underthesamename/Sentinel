# Prompt 01 — Fundação da API

## Prompt

Trabalhe no projeto Sentinel localizado na raiz deste repositório. Leia integralmente `PRODUCT.md`, `README.md`, `docs/architecture.md`, `docs/openapi.yaml`, a especificação técnica `.docx` em `docs/` e os arquivos existentes do workspace Rust antes de alterar código.

Implemente a fundação de produção da API Rust/Axum, preservando o monólito modular e as dependências entre camadas já documentadas.

### Objetivo

Entregar uma API configurável, conectada ao PostgreSQL, observável e preparada para receber casos de uso de autenticação sem acoplar domínio a Axum ou SQLx.

### Escopo obrigatório

1. Criar configuração tipada carregada por variáveis de ambiente, com validação antecipada e mensagens que não revelem segredos.
2. Criar o estado compartilhado da aplicação contendo apenas dependências necessárias, como pool PostgreSQL, relógio e configuração pública.
3. Conectar ao PostgreSQL usando SQLx, com limites e timeouts explícitos.
4. Executar migrações versionadas de forma segura no ambiente local e definir a estratégia para CI/produção.
5. Separar `live` de `ready`: liveness verifica o processo; readiness verifica dependências necessárias para aceitar tráfego.
6. Implementar erros públicos `application/problem+json` conforme RFC 9457, com códigos estáveis e `correlation_id`.
7. Propagar request/correlation ID por handlers, serviços, logs e respostas de erro.
8. Configurar logs JSON estruturados com allowlist de campos e sem corpos ou cabeçalhos sensíveis.
9. Implementar encerramento gracioso e comportamento correto durante indisponibilidade do banco.
10. Atualizar `.env.example`, README, OpenAPI e documentação arquitetural afetada.

### Restrições

- `crates/domain` não pode depender de Axum, SQLx ou transporte.
- `crates/application` depende apenas de domínio e portas abstratas.
- Não registrar `DATABASE_URL`, cookies, tokens, senhas ou cabeçalhos de autorização.
- Não adicionar Redis, microsserviços, filas ou abstrações sem consumidor real.
- Não implementar ainda cadastro ou login.

### Testes e validação

- Testes unitários de parsing e validação de configuração.
- Testes de health checks com banco disponível e indisponível.
- `cargo fmt --all --check`.
- `cargo clippy --workspace --all-targets -- -D warnings`.
- `cargo test --workspace`.
- Migração aplicada em PostgreSQL descartável.
- Verificação automatizada de que erros e logs não contêm segredos conhecidos usados no teste.

### Critérios de conclusão

- A API inicia com configuração válida e falha cedo com configuração inválida.
- `/health/live` e `/health/ready` possuem semânticas distintas.
- Erros seguem o contrato RFC 9457 e incluem correlação.
- PostgreSQL está integrado sem violar as fronteiras de arquitetura.
- Documentação e comportamento são compatíveis.
- Relatar arquivos alterados, decisões tomadas, comandos executados e pendências reais.

