# Relatório de testes da Fase 1

Data da revisão: 2026-08-01.

## Gate executável

| Gate | Comando ou job | Evidência esperada |
|---|---|---|
| Rust estático | `cargo fmt --all --check` e `cargo clippy --workspace --all-targets -- -D warnings` | Formatação e lints sem avisos |
| Rust unitário e PostgreSQL | `TEST_DATABASE_URL=... cargo test --workspace --no-fail-fast` | Testes de todas as crates e migrações em schemas vazios |
| Frontend | `npm test` e `npm run build` em `apps/web` | Vitest e build TypeScript/Vite aprovados |
| E2E | `TEST_DATABASE_URL=... npm run test:e2e` em `apps/web` | Fluxos aprovados em Desktop Chrome e Pixel 5 |
| Dependências | jobs `rust-audit` e `npm audit --audit-level=high` | Nenhum achado alto ou crítico |
| Segredos | job `secret-scan` | Gitleaks sem achados |
| Contrato | `openapi_paths_match_the_real_phase1_routes` | Conjunto de paths OpenAPI igual ao router da Fase 1 |

O job Rust do CI fornece PostgreSQL 16 real e define `TEST_DATABASE_URL`. Os testes criam schemas
isolados com UUID, aplicam `0001_initial.sql` e `0002_password_sessions.sql` do zero e removem o
schema ao final. Não há dependência de ordem entre casos.

## Rastreabilidade de requisitos e ameaças

| Requisito / ameaça | Evidência principal | Nível |
|---|---|---|
| Domínio e validação de e-mail | `domain::auth::tests::*` | Unitário |
| Política de senha e blocklist | `password_policy_accepts_long_passphrases_and_rejects_blocklist` e testes HTTP de cadastro | Unitário + HTTP |
| Tempo ocioso e absoluto | `idle_and_absolute_expiration_fail_closed` e `concurrent_session_touch_and_logout_converge_to_revoked` | Serviço + PostgreSQL |
| Tokens e fingerprints | `tokens_are_distinct_and_exactly_256_bits_before_encoding`, rotação e separação de contexto | Unitário |
| Migrações em banco vazio | `TestDatabase::create` em cada teste PostgreSQL | PostgreSQL 16 |
| Cookie `__Host-` | `migrations_apply_from_zero_and_http_contract_survives_abuse` e testes de `HostCookieBuilder` | HTTP + unitário |
| CSRF vinculado à sessão | `csrf_is_bound_to_session_and_expiration` e fluxo HTTP até logout | Unitário + PostgreSQL |
| RFC 9457 e correlation ID | teste HTTP de payload hostil e testes do middleware de correlação | HTTP |
| Cadastro duplicado concorrente | `postgres_enforces_duplicate_registration_under_concurrency` | PostgreSQL concorrente |
| Logout duplicado e atualização concorrentes | `concurrent_session_touch_and_logout_converge_to_revoked` | PostgreSQL concorrente |
| Enumeração de conta | `wrong_password_and_unknown_account_have_equivalent_external_response` | HTTP |
| Credential stuffing | testes de limite no sexto login, isolamento e recuperação da janela | Serviço + unitário |
| Fixação de sessão | `login_rotates_existing_session_and_invalidates_old_cookie` | HTTP |
| SQL injection | payload hostil no teste PostgreSQL e contagem final de usuários | HTTP + PostgreSQL |
| Vazamento em logs | `captured_audit_log_only_contains_allowlisted_fields_and_no_secrets`, tipos secretos e config redigidos | Unitário + secret scan |
| Indisponibilidade e recuperação | `readiness_reports_database_outage_and_recovers_with_a_healthy_pool` | HTTP + PostgreSQL |
| Rotas reais versus OpenAPI | `openapi_paths_match_the_real_phase1_routes` | Contrato estático |
| Cadastro/login/logout desktop e mobile | `apps/web/e2e/auth.spec.ts` | Playwright + backend real |

## Limites residuais

- O limiter em memória não compartilha estado entre réplicas e perde contadores em reinícios. Isso
  impede escala horizontal segura e permanece registrado no modelo de ameaças.
- O RustSec sinaliza `RUSTSEC-2023-0071` (CVSS 5.9, médio) em `rsa`, sem versão corrigida. A crate
  não integra o grafo ativo do workspace e o Sentinel não usa RSA. O limiar alto do gate está em
  `.cargo/audit.toml`; o achado deve ser reavaliado se features ou backends SQLx mudarem.
- A blocklist de senhas é pequena e precisa de corpus versionado antes de uso público.
- O teste de recuperação usa primeiro um pool realmente inacessível e depois um pool saudável; ele
  não derruba o serviço PostgreSQL compartilhado durante a suíte, evitando interferência entre
  jobs e testes.
- WebSocket, CSWSH, replay e concorrência do login QR pertencem ao Prompt 06 e não fazem parte da
  superfície implementada na Fase 1.
