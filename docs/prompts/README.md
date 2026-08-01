# Prompts de implementação do Sentinel

Estes documentos dividem a evolução do Sentinel em etapas verificáveis. Execute-os na ordem abaixo, sempre em uma nova conversa ou contexto limpo quando possível.

| Ordem | Documento | Resultado esperado |
|---|---|---|
| 1 | [01-fundacao-api.md](01-fundacao-api.md) | API conectada ao PostgreSQL, configurada e observável |
| 2 | [02-controles-seguranca.md](02-controles-seguranca.md) | CSRF, origem, cookies, tokens e rate limiting preparados |
| 3 | [03-autenticacao-senha.md](03-autenticacao-senha.md) | Cadastro, login, sessão, identidade e logout funcionais |
| 4 | [04-interface-autenticacao.md](04-interface-autenticacao.md) | Frontend conectado aos endpoints reais de autenticação |
| 5 | [05-testes-fase-1.md](05-testes-fase-1.md) | Cobertura de integração e segurança da Fase 1 |
| 6 | [06-login-qr-resiliente.md](06-login-qr-resiliente.md) | Fluxo QR completo com WebSocket, polling e exchange atômico |

## Regras de execução

- A especificação em `docs/Sentinel_Especificacao_Tecnica_v0.2.0.docx` é a fonte principal.
- `PRODUCT.md`, `DESIGN.md`, ADRs, OpenAPI e migrações também são fontes normativas.
- Cada etapa deve terminar com build, testes, documentação e uma descrição objetiva do que permanece pendente.
- Não antecipar funcionalidades de etapas posteriores sem necessidade técnica comprovada.
- Não substituir controles obrigatórios por comentários, mocks ou tarefas futuras.

