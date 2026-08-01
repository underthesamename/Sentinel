# Sentinel

Autenticação entre dispositivos por QR Code, com aprovação explícita, uso único e conclusão resiliente por WebSocket ou polling.

## Estado

O Sentinel implementa cadastro e login por senha, sessões revogáveis e autenticação entre
dispositivos por QR. O fluxo QR exige comparação de código e aprovação explícita no celular;
o desktop conclui a troca por WebSocket ou polling usando o estado persistido no PostgreSQL.

## Estrutura

- `apps/api`: composição HTTP/WebSocket em Axum.
- `apps/web`: SPA/PWA React para desktop e celular.
- `crates/domain`: entidades, estados e invariantes sem dependências de infraestrutura.
- `crates/application`: casos de uso e portas.
- `crates/infrastructure`: PostgreSQL, hashing, relógio, rate limiting e eventos.
- `crates/api-contract`: DTOs e erros públicos RFC 9457.
- `migrations`: schema PostgreSQL versionado.
- `docs`: especificação, ADRs, arquitetura, ameaças, privacidade, incidentes e OpenAPI.
- `deploy`: ambiente local e proxy TLS.

## Desenvolvimento local

1. Copie `.env.example` para `.env`, substitua os segredos e exporte suas variáveis no shell.
2. Suba o banco: `docker compose -f deploy/compose/docker-compose.yml up -d db`.
3. Execute a API: `cargo run -p sentinel-api`.
4. Em outro terminal, instale e execute o frontend: `npm install --prefix apps/web && npm run dev --prefix apps/web`.

Health checks:

- `GET /health/live`: confirma apenas que o processo HTTP está ativo.
- `GET /health/ready`: executa uma consulta curta ao PostgreSQL; retorna RFC 9457 com HTTP 503 quando o banco não está pronto.

Toda resposta propaga `X-Request-ID`. Um UUID válido enviado pelo cliente é preservado; valores ausentes ou inválidos são substituídos.

O baseline de segurança inclui validação normalizada de origem, CSRF vinculado à sessão, cookies `__Host-`, tokens de 256 bits, fingerprints HMAC rotacionáveis, rate limiting substituível, auditoria em allowlist e cabeçalhos privados. Os endpoints de autenticação compõem esses controles antes do trabalho Argon2id.

Endpoints disponíveis:

- `POST /v1/auth/register`: cria uma conta após normalização do e-mail e política de senha.
- `POST /v1/auth/login`: verifica Argon2id e cria/rotaciona a sessão.
- `GET /v1/auth/me`: retorna identidade e prazos da sessão ativa.
- `GET /v1/auth/csrf`: emite ou renova CSRF vinculado à sessão.
- `POST /v1/auth/logout`: exige origem e CSRF, revoga no servidor e limpa o cookie.
- `POST /v1/qr-login/challenges`: cria um challenge temporário no desktop.
- `POST /v1/qr-login/scan/bootstrap`: inicia a continuação segura no celular.
- `POST /v1/qr-login/challenges/{id}/scan`: vincula o challenge à sessão do celular.
- `POST /v1/qr-login/challenges/{id}/verify`: compara o código exibido no desktop.
- `POST /v1/qr-login/challenges/{id}/decision`: aprova ou recusa a nova sessão.
- `POST /v1/qr-login/challenges/{id}/exchange`: troca uma aprovação por uma sessão de uso único.
- `GET /v1/qr-login/challenges/{id}` e `/ws`: consultam o estado persistido por polling ou WebSocket.

Senhas usam Argon2id com 19 MiB, duas iterações e paralelismo 1. Em 2026-08-01, o benchmark manual (`cargo test -p sentinel-infrastructure benchmark_argon2id_hash -- --ignored --nocapture`) mediu mediana de 406 ms em cinco hashes, build de desenvolvimento, num AMD Ryzen 5 5500. Esse número não representa produção e deve ser repetido no binário/hardware de deploy. `last_seen_at` é atualizado no máximo a cada `SESSION_TOUCH_INTERVAL` (5 minutos por padrão), reduzindo write amplification sem estender uma sessão após seu limite absoluto.

`TOKEN_FINGERPRINT_KEYS` usa a forma `id:chave,id-anterior:chave-anterior`: o primeiro item assina novos fingerprints e os demais verificam dados durante rotação. Cada chave deve possuir no mínimo 32 bytes. Staging e produção falham no startup se a chave estiver ausente/fraca ou se `COOKIE_SECURE=false`.

## Migrações

`RUN_MIGRATIONS` é `true` por padrão somente em `local` e `ci`. Em staging e produção o padrão é `false`: o pipeline de release deve executar as migrações uma única vez antes de liberar tráfego. A aplicação nunca usa o job de migração como substituto para validações de segurança em runtime.

## Configuração do PostgreSQL

- `DATABASE_URL`: obrigatória e sempre tratada como segredo.
- `DB_MAX_CONNECTIONS`: máximo do pool, maior que zero.
- `DB_ACQUIRE_TIMEOUT_SECS`: espera máxima por uma conexão do pool.
- `DB_CONNECT_TIMEOUT_SECS`: tempo máximo para estabelecer o pool no startup.

## Testes

As suítes Rust cobrem regras de domínio, contrato HTTP, migrações, concorrência, sessões e
QR contra PostgreSQL real:

```bash
TEST_DATABASE_URL=postgres://sentinel:sentinel@127.0.0.1:5432/sentinel \
  cargo test --workspace --no-fail-fast
```

No frontend, Vitest cobre componentes e clientes HTTP. Playwright inicia API e Vite e executa os
fluxos completos em projetos desktop e mobile:

```bash
npm test --prefix apps/web
TEST_DATABASE_URL=postgres://sentinel:sentinel@127.0.0.1:5432/sentinel \
  npm run test:e2e --prefix apps/web
```

O CI também exige `rustfmt`, Clippy sem warnings, build do frontend, auditoria de dependências e
varredura de segredos.

## Princípios obrigatórios

- PostgreSQL é a fonte de verdade; WebSocket apenas acelera a UX.
- Segredos brutos nunca são persistidos ou registrados.
- Toda mutação autenticada por cookie exige CSRF.
- Cada challenge cria no máximo uma sessão.
- Estados terminais são irreversíveis.
- Controles de segurança entram no mesmo marco da funcionalidade protegida.
