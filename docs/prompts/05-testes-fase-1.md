# Prompt 05 — Testes e gate da Fase 1

## Prompt

Faça uma revisão orientada por evidências da Fase 1 do Sentinel. O objetivo não é adicionar funcionalidades, mas provar que cadastro, login, sessão, CSRF e logout satisfazem a especificação sob falhas, abuso e concorrência.

### Objetivo

Construir a suíte de testes e o gate de CI necessários para considerar a autenticação por senha concluída.

### Escopo obrigatório

1. Testes unitários de domínio, validação, tempo, fingerprints e política de senha.
2. Testes de integração com PostgreSQL real e migrações do zero.
3. Testes HTTP de cookies, CSRF, erros RFC 9457 e correlation ID.
4. Testes concorrentes para cadastro duplicado, logout e atualização de sessão.
5. Testes de segurança para enumeração, credential stuffing, session fixation, SQL injection e vazamento em logs.
6. Testes E2E da interface nos viewports desktop e mobile.
7. Teste de indisponibilidade e recuperação do banco.
8. Auditoria de dependências Rust e npm.
9. Verificação de documentação e OpenAPI contra as rotas reais.
10. Integração de todos os gates no CI.

### Regras

- Não enfraquecer uma asserção para fazer o teste passar.
- Corrigir bugs encontrados somente quando a correção estiver claramente dentro da Fase 1; documentar expansões de escopo.
- Usar relógio controlável e dados sintéticos.
- Não depender da ordem dos testes.
- Limpar dados de teste e não registrar segredos.

### Gate de saída

- `cargo fmt`, `clippy` e todos os testes Rust aprovados.
- Build e testes do frontend aprovados.
- Migrações aplicam em banco vazio.
- Nenhum segredo detectado nos logs.
- Nenhum achado crítico ou alto aberto.
- Cookies, CSRF, rate limits, mensagens genéricas e revogação comprovados.
- Relatório final mapeando cada teste aos requisitos e ameaças correspondentes.

