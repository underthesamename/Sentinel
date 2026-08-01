# ADR-003 — Senhas e sessões revogáveis

## Status

Aceito em 2026-08-01.

## Decisão

- E-mails do MVP são ASCII, recebem trim e case folding antes da constraint única. Internacionalização exige uma decisão explícita sobre Unicode/IDNA.
- Senhas têm mínimo de 15 caracteres, aceitam ao menos 64 e usam uma blocklist inicial. Não há regras artificiais de composição.
- Hashes usam Argon2id v1.3 com 19 MiB, duas iterações e paralelismo 1. Benchmark manual em 2026-08-01: mediana de 406 ms em cinco hashes, build de desenvolvimento, AMD Ryzen 5 5500. O custo deve ser medido novamente no binário e hardware de produção.
- Login inexistente verifica um hash dummy com os mesmos parâmetros e retorna o mesmo erro público de senha incorreta.
- O cookie contém somente token CSPRNG; PostgreSQL armazena fingerprint HMAC e decide validade, revogação e expiração.
- `last_seen_at` é tocado no máximo a cada cinco minutos e nunca estende a sessão além do limite absoluto.
- Login com uma sessão válida rotaciona o token e revoga a sessão anterior. Logout revoga antes de limpar o cookie e cancela challenges móveis pendentes na mesma transação.

## Consequências e riscos

A blocklist embarcada cobre apenas casos óbvios e não é suficiente para produção pública. O limiter em memória continua restrito a uma instância. Auditoria estruturada está protegida por allowlist, mas retenção e armazenamento operacional ainda precisam de aprovação.
