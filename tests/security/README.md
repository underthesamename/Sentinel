# Testes de segurança

O gate da Fase 1 combina testes unitários e PostgreSQL real para CSRF, enumeração, credential
stuffing, fixação de sessão, SQL injection e vazamento de segredos em logs. A rastreabilidade
completa está em `docs/phase1-test-report.md`.

XSS é reduzido pela renderização do React e pelos cabeçalhos privados já testados. CSWSH e replay
do fluxo QR só se tornam exercitáveis quando as rotas WebSocket/QR forem implementadas no Prompt
06.
