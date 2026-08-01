# Sentinel

Autenticação entre dispositivos por QR Code, com aprovação explícita, uso único e conclusão resiliente por WebSocket ou polling.

## Estado

Este repositório contém a fundação inicial baseada na especificação técnica v0.2.0. A API possui configuração tipada, PostgreSQL, migrações controladas, health checks distintos, erros RFC 9457, correlação e logs estruturados. Autenticação e QR login serão adicionados por fases.

## Estrutura

- `apps/api`: composição HTTP/WebSocket em Axum.
- `apps/web`: SPA/PWA React para desktop e celular.
- `crates/domain`: entidades, estados e invariantes sem dependências de infraestrutura.
- `crates/application`: casos de uso e portas.
- `crates/infrastructure`: PostgreSQL, hashing, relógio, rate limiting e eventos.
- `crates/api-contract`: DTOs e erros públicos RFC 9457.
- `migrations`: schema PostgreSQL versionado.
- `docs`: especificação, ADRs, arquitetura, ameaças, privacidade, incidentes e OpenAPI.
- `tests`: integração, concorrência, segurança e E2E.
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

O baseline de segurança reutilizável já inclui validação normalizada de origem, CSRF vinculado à sessão, cookies `__Host-`, tokens de 256 bits, fingerprints HMAC rotacionáveis, rate limiting substituível, auditoria em allowlist e cabeçalhos privados. Os endpoints de autenticação serão responsáveis por compor esses controles na próxima etapa.

`TOKEN_FINGERPRINT_KEYS` usa a forma `id:chave,id-anterior:chave-anterior`: o primeiro item assina novos fingerprints e os demais verificam dados durante rotação. Cada chave deve possuir no mínimo 32 bytes. Staging e produção falham no startup se a chave estiver ausente/fraca ou se `COOKIE_SECURE=false`.

## Migrações

`RUN_MIGRATIONS` é `true` por padrão somente em `local` e `ci`. Em staging e produção o padrão é `false`: o pipeline de release deve executar as migrações uma única vez antes de liberar tráfego. A aplicação nunca usa o job de migração como substituto para validações de segurança em runtime.

## Configuração do PostgreSQL

- `DATABASE_URL`: obrigatória e sempre tratada como segredo.
- `DB_MAX_CONNECTIONS`: máximo do pool, maior que zero.
- `DB_ACQUIRE_TIMEOUT_SECS`: espera máxima por uma conexão do pool.
- `DB_CONNECT_TIMEOUT_SECS`: tempo máximo para estabelecer o pool no startup.

## Princípios obrigatórios

- PostgreSQL é a fonte de verdade; WebSocket apenas acelera a UX.
- Segredos brutos nunca são persistidos ou registrados.
- Toda mutação autenticada por cookie exige CSRF.
- Cada challenge cria no máximo uma sessão.
- Estados terminais são irreversíveis.
- Controles de segurança entram no mesmo marco da funcionalidade protegida.
