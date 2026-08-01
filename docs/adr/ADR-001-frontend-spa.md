# ADR-001 — React SPA para o primeiro marco

- Status: aceito provisoriamente
- Data: 2026-07-31

## Contexto

O Sentinel precisa da mesma base web responsiva no desktop e no celular. A autenticação é orientada a APIs, câmera, WebSocket e polling; SSR não é requisito do núcleo.

## Decisão

Usar React, TypeScript e Vite como SPA/PWA no MVP. Manter a API independente para permitir troca futura de frontend.

## Consequências

- Menor complexidade operacional inicial.
- Navegação e estados de autenticação ficam no cliente.
- SEO e renderização pública não são prioridades do MVP.
- A decisão deve ser revisada se surgir uma superfície pública dependente de SSR.

