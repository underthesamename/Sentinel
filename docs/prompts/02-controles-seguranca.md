# Prompt 02 — Controles básicos de segurança

## Prompt

Continue o projeto Sentinel após a conclusão comprovada do Prompt 01. Leia a especificação, o threat model, o mapa de privacidade, os ADRs, a configuração e os testes existentes. Não assuma que controles mencionados em documentação já estão implementados: confirme no código.

### Objetivo

Criar os componentes reutilizáveis de segurança exigidos pelas primeiras rotas de autenticação, com APIs difíceis de usar incorretamente.

### Escopo obrigatório

1. Validar `Origin` e, quando aplicável, `Referer` usando origens normalizadas e allowlist configurada.
2. Implementar proteção CSRF vinculada à sessão, adequada a mutações autenticadas por cookie.
3. Definir construtor central de cookies `__Host-session` e `__Host-qr-cont` com atributos seguros por ambiente.
4. Criar geração de tokens de 256 bits usando CSPRNG do sistema.
5. Persistir/verificar apenas fingerprints de tokens usando HMAC-SHA-256 com chave configurada e rotacionável.
6. Usar comparação em tempo constante quando aplicável.
7. Implementar rate limiting em memória por operação e chave composta, atrás de uma porta substituível.
8. Criar categorias de auditoria e redaction/allowlist de campos.
9. Definir cabeçalhos de segurança e políticas de cache para respostas privadas.
10. Atualizar threat model, `.env.example` e documentação das decisões.

### Restrições

- SameSite não substitui CSRF.
- Rate limit não pode depender somente de um IP por longos períodos.
- Tokens brutos nunca entram em banco, logs, tracing, métricas ou erros.
- Não armazenar segredos em `localStorage`.
- Defaults locais inseguros devem ser impossíveis em ambiente de produção.
- Não implementar ainda endpoints completos de login.

### Testes obrigatórios

- Origem válida, inválida, ausente e malformada.
- CSRF ausente, inválido, de outra sessão, expirado e válido.
- Atributos exatos dos cookies em local e produção.
- Tokens distintos, tamanho correto e fingerprints determinísticos somente sob a mesma chave.
- Rate limit, janela, recuperação e isolamento entre operações.
- Pesquisa automática por valores secretos nos logs capturados.
- Testes de propriedades ou vetores fixos para funções criptográficas quando apropriado.

### Critérios de conclusão

- Os próximos handlers conseguem aplicar CSRF, cookies, fingerprints e rate limit por composição explícita.
- Nenhuma mutação autenticada futura precisa reinventar esses controles.
- Testes e análise estática passam sem exceções silenciosas.
- Relatar ameaças mitigadas, riscos residuais e decisões ainda abertas.

