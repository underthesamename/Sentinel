# Validação da interface de autenticação

## Pré-requisitos

- PostgreSQL do `compose.yaml` ativo e migrações aplicadas.
- API em `http://127.0.0.1:8080` com `APP_ORIGIN=http://127.0.0.1:5173`.
- Dependências do frontend instaladas com `npm install` em `apps/web`.

## Execução

Em `apps/web`, execute `npm test` para os contratos de UI/cliente e `npm run test:e2e` para o fluxo real no navegador. O Playwright inicia o Vite; a API e o PostgreSQL devem estar ativos separadamente.

O E2E cria uma conta sintética única, entra, recarrega a página para comprovar a restauração por cookie, encerra a sessão com CSRF e confirma a linguagem genérica para credenciais inválidas. Os projetos `desktop` e `mobile` repetem o fluxo nos dois viewports.
