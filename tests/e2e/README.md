# Testes E2E

`apps/web/e2e/auth.spec.ts` executa cadastro, login, restauração da sessão, mensagem genérica de
credenciais e logout contra API e PostgreSQL reais. A mesma suíte roda nos projetos Playwright
desktop e mobile.

```bash
TEST_DATABASE_URL=postgres://sentinel:sentinel@127.0.0.1:5432/sentinel \
  npm run test:e2e --prefix apps/web
```

O fluxo entre dispositivos por QR pertence ao Prompt 06.
