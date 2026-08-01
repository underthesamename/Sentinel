# ADR-002 — Controles de segurança reutilizáveis

## Status

Aceito em 2026-08-01.

## Contexto

As primeiras rotas de autenticação precisarão aplicar as mesmas regras de origem, CSRF, cookies, tokens, rate limiting, auditoria e cache. Implementações isoladas por handler aumentariam a chance de divergência e de defaults inseguros.

## Decisão

- Tokens possuem 256 bits obtidos do CSPRNG do sistema e são expostos somente por método explícito.
- Persistência e verificação usam HMAC-SHA-256 com separação de contexto. O fingerprint carrega um `key_id`; o primeiro item do keyring é ativo e itens antigos verificam dados durante rotação.
- CSRF usa token aleatório, fingerprint vinculado ao identificador da sessão e expiração armazenada. SameSite não substitui essa validação.
- A camada de aplicação define a porta `RateLimiter`; a infraestrutura inicial usa janela fixa em memória por operação e chave composta.
- A API normaliza origens completas. Mutações HTTP podem usar `Referer` apenas quando `Origin` estiver ausente; WebSocket exige `Origin`.
- Cookies `__Host-` são sempre `Secure`, `HttpOnly`, `Path=/`, sem `Domain`; sessão usa `SameSite=Lax` e continuação QR usa `SameSite=Strict`.
- Auditoria aceita apenas campos tipados e metadata em allowlist. Respostas recebem políticas centrais de segurança e cache privado.
- Produção falha no startup sem keyring forte e recusa `COOKIE_SECURE=false`.

## Consequências

Handlers posteriores compõem controles existentes em vez de reconstruí-los. A versão em memória do rate limiter limita o MVP a uma instância e deve ser substituída antes de escala horizontal. A rotação exige manter a chave anterior até expirar todo fingerprint que dependa dela.
