# Prompt 03 — Autenticação por senha e sessões

## Prompt

Implemente a Fase 1 de autenticação do Sentinel sobre as fundações concluídas nos Prompts 01 e 02. Leia os requisitos RF-001 a RF-003, RNFs relacionados, schema, OpenAPI, threat model e regras de cookies antes de codificar.

### Objetivo

Entregar cadastro, login, consulta da sessão atual, obtenção de CSRF e logout com sessões revogáveis no servidor.

### Endpoints

- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `GET /v1/auth/me`
- `GET /v1/auth/csrf`
- `POST /v1/auth/logout`

### Escopo obrigatório

1. Normalização consistente de e-mail e unicidade no banco.
2. Política de senha conforme especificação: mínimo adequado para fator único, suporte a senhas longas, blocklist e permissão para colar.
3. Argon2id com parâmetros configurados após benchmark documentado.
4. Respostas externas equivalentes para conta inexistente e senha incorreta.
5. Trabalho criptográfico caro somente após controles baratos aplicáveis.
6. Criação de sessão com token novo, fingerprint persistido, timeout ocioso e absoluto.
7. Cookie `__Host-session` criado somente após autenticação bem-sucedida.
8. Rotação de sessão após autenticação e invalidação de identificadores anteriores aplicáveis.
9. CSRF emitido/renovado para a sessão e exigido no logout.
10. Logout revoga a sessão no servidor antes de remover o cookie.
11. Eventos de auditoria definidos na especificação, sem e-mail ou segredos brutos.
12. Contratos, OpenAPI, migrações e documentação atualizados.

### Concorrência e idempotência

- Cadastro simultâneo do mesmo e-mail deve produzir uma conta.
- Logout repetido não pode restaurar ou prolongar sessão.
- Sessão expirada ou revogada falha fechada.
- `last_seen_at` não deve causar escrita excessiva; documentar a estratégia adotada.

### Testes obrigatórios

- Cadastro válido, e-mail duplicado e senha bloqueada.
- Login correto, senha incorreta e conta inexistente com resposta externa equivalente.
- Rate limit de cadastro e login.
- Cookie com todos os atributos exigidos.
- CSRF em logout.
- Expiração ociosa, absoluta e revogação.
- Rotação/fixação de sessão.
- Concorrência no cadastro.
- Ausência de senha, token, cookie e e-mail bruto em logs.

### Critérios de conclusão

- O usuário consegue cadastrar, autenticar, consultar sua identidade e encerrar a sessão.
- O servidor, não o navegador, decide se uma sessão permanece válida.
- OpenAPI e testes descrevem o comportamento real.
- Não iniciar o login por QR nesta etapa.

