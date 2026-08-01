# Testes de integração

Os testes executáveis ficam em `apps/api/tests/phase1_postgres.rs`. Cada caso cria um schema
PostgreSQL exclusivo, aplica todas as migrações a partir do zero e remove os dados sintéticos ao
terminar.

```bash
TEST_DATABASE_URL=postgres://sentinel:sentinel@127.0.0.1:5432/sentinel \
  cargo test -p sentinel-api --test phase1_postgres
```

O gate cobre o contrato HTTP, cookies, CSRF, RFC 9457, correlation ID, indisponibilidade e
recuperação do banco. `TEST_DATABASE_URL` é obrigatório para impedir que uma ausência acidental do
banco seja tratada como teste aprovado.
