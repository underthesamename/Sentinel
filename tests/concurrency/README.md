# Testes de concorrência

O escopo da Fase 1 cobre cadastro duplicado e corrida entre atualização e revogação de sessão no
PostgreSQL real. Os casos estão em `apps/api/tests/phase1_postgres.rs` e verificam o estado final no
banco, não apenas as respostas das tarefas concorrentes.

Concorrência de aprovação, exchange e expiração pertence ao login por QR (Prompt 06) e não é
antecipada neste gate.
