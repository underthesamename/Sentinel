# Arquitetura

O Sentinel começa como monólito modular. Axum adapta HTTP/WebSocket; a camada de aplicação orquestra casos de uso; o domínio protege invariantes; a infraestrutura implementa banco e serviços externos.

```text
Desktop Web ─┐
             ├─ HTTPS/WSS ─ Proxy TLS ─ API Rust/Axum ─ PostgreSQL
Mobile/PWA ──┘                         ├─ Jobs internos
                                     └─ Redis (evolução)
```

## Dependências permitidas

```text
apps/api → api-contract, application, infrastructure
infrastructure → application, domain
application → domain
domain → nenhuma camada interna
```

O banco é a fonte de verdade. WebSocket entrega notificações e snapshots; polling conclui o fluxo quando o canal estiver indisponível.

## Composição da API

O binário em `apps/api/src/main.rs` é o composition root. Ele carrega e valida a configuração, cria o pool, aplica migrações conforme a política do ambiente, monta `AppState` e inicia o servidor. O roteador e seus adapters HTTP ficam na biblioteca `sentinel-api`, o que permite testar contratos sem abrir uma porta real.

`AppState` contém somente dependências atualmente consumidas: `PgPool`, configuração pública sem segredos e uma sonda de readiness. `DATABASE_URL` permanece privada no tipo de configuração e seu `Debug` é explicitamente redigido.

## Controles reutilizáveis de segurança

- `application::RateLimiter` é a porta estável para políticas por operação e chave composta.
- `infrastructure::security` fornece geração CSPRNG, keyring HMAC rotacionável, CSRF vinculado à sessão e o limiter em memória do MVP.
- `api::security` adapta validação de `Origin`/`Referer`, cookies `__Host-`, cabeçalhos privados e eventos de auditoria tipados.
- `TOKEN_FINGERPRINT_KEYS` ordena a chave ativa e as anteriores. Segredos permanecem fora de `PublicConfig` e têm saída `Debug` redigida.

## Autenticação por senha

`domain::auth` concentra normalização de e-mail e política de senha. `application::auth` define portas para credenciais, sessões e hashing. A infraestrutura implementa transações PostgreSQL e Argon2id; a API apenas adapta HTTP, compõe controles baratos antes do hash e emite contratos de `api-contract`.

Uma sessão é aceita somente quando fingerprint, status da conta, revogação, timeout ocioso e limite absoluto são válidos no servidor. O acesso atualiza `last_seen_at` e o timeout ocioso apenas quando o último toque tem ao menos cinco minutos, sempre limitado pela expiração absoluta. Login com cookie de sessão válido cria um token novo e revoga o identificador anterior após persistir a nova sessão.

## Inicialização e migrações

```text
variáveis → AppConfig validada → conexão com timeout → migrações (local/CI)
          → AppState → router → listener → graceful shutdown
```

- Local/CI: migrações podem rodar no startup para reprodutibilidade.
- Staging/produção: o padrão é não migrar no processo; o release executa uma vez antes do tráfego.
- Falha de configuração, conexão ou migração impede a API de aceitar requisições.

## Saúde e observabilidade

- `/health/live` não consulta dependências.
- `/health/ready` consulta o PostgreSQL com timeout e retorna 503 em falha.
- `X-Request-ID` é validado ou gerado e propagado na resposta.
- Logs são JSON e registram método, caminho, status, latência e correlação; corpos e cabeçalhos não são registrados.
- Erros públicos usam `application/problem+json` e códigos estáveis.

## Invariantes

- Um challenge cria no máximo uma sessão.
- Estados terminais não possuem transições de saída.
- Apenas a sessão móvel scanner exata consulta, aprova ou rejeita.
- Revogação da sessão scanner cancela autorizações pendentes.
- Expiração é validada na operação, não delegada ao job de limpeza.
