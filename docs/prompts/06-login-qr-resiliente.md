# Prompt 06 — Login por QR Code resiliente

## Prompt

Implemente a Fase 2 do Sentinel somente após o gate do Prompt 05 estar aprovado. Leia integralmente as seções de domínio, fluxos, REST/WebSocket, segurança e testes da especificação v0.2.0. Os casos CT-001 a CT-016 são critérios normativos.

### Objetivo

Entregar o fluxo completo desktop → QR → celular → aprovação → exchange, mantendo PostgreSQL como fonte de verdade e permitindo conclusão sem WebSocket.

### Escopo obrigatório

1. Criação de challenge com `qr_token`, `subscription_token`, código de confirmação e TTL usando CSPRNG.
2. Persistência somente de hashes/fingerprints.
3. `qr_token` no fragmento da URL.
4. Bootstrap que remove o fragmento e cria continuação `__Host-qr-cont` HttpOnly.
5. Continuidade segura através do login móvel.
6. Transição atômica `CREATED → SCANNED` vinculada a `scanner_user_id` e `scanner_session_id` exatos.
7. Consulta de detalhes autorizada pela sessão scanner exata, com 404 genérico em falhas.
8. Number matching com limite de tentativas.
9. Aprovação e rejeição com CSRF e concorrência otimista por `lock_version`.
10. WebSocket com Origin allowlist, subscribe autenticado, snapshot e eventos sem segredos.
11. Polling autenticado como fallback integral.
12. Exchange atômico usando `subscription_token`, criando exatamente uma sessão.
13. Cancelamento e propagação após revogação da sessão scanner.
14. Expiração validada em cada operação e jobs apenas para limpeza.
15. Interface desktop e mobile integrada aos endpoints reais.
16. OpenAPI, protocolo WS, ADRs, threat model e documentação atualizados.

### Invariantes obrigatórios

- Um challenge gera no máximo uma sessão.
- Estados terminais são irreversíveis.
- A aprovação não cria cookie no desktop.
- O WebSocket nunca é a fonte de verdade.
- Perder um evento não impede polling e exchange.
- Revogar a sessão scanner invalida autorizações pendentes.
- Nenhum token ou código bruto aparece no banco, logs, URLs do servidor ou telemetry.

### Testes obrigatórios

Implementar e aprovar CT-001 a CT-016, incluindo:

- QR e continuação expirados.
- Sessão móvel diferente e usuário diferente.
- Código incorreto e limite de tentativas.
- Aprovação e exchange simultâneos.
- Queda do WebSocket antes e depois de `APPROVED`.
- Reconexão com snapshot.
- Revogação simultânea.
- Cookies e CSRF.
- Retenção e limpeza.
- Ausência de segredos em logs e erros.

### Critérios de conclusão

- O E2E passa com WebSocket ativo, ausente e interrompido.
- Vinte exchanges paralelos produzem exatamente uma sessão.
- Todos os estados e erros são estáveis e documentados.
- O frontend não resolve corridas; apenas reflete a decisão do servidor.
- Relatar riscos residuais, especialmente relay/phishing em tempo real.

