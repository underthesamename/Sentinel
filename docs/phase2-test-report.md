# Relatório de aceitação da Fase 2

Data: 2026-08-01.

| Caso | Evidência |
|---|---|
| CT-001 | Bootstrap de QR expirado retorna 410; polling materializa `EXPIRED` sem scan |
| CT-002 | Continuação expirada retorna 410 e não é reconstruída |
| CT-003/004 | Detalhes exigem usuário e sessão scanner exatos; demais retornam 404 |
| CT-005 | Cinco erros de código cancelam o challenge sem revelar o valor correto |
| CT-006 | Duas aprovações simultâneas resultam em um `APPROVED` e um conflito |
| CT-007 | Vinte exchanges paralelos criam exatamente uma sessão de origem |
| CT-008 | Playwright fecha o WebSocket; polling observa aprovação e conclui exchange |
| CT-009 | Todo subscribe/reconnect recebe `qr.snapshot` lido novamente do PostgreSQL |
| CT-010/011 | Logout cancela challenges `SCANNED`/`APPROVED` da sessão revogada |
| CT-012 | Testes de cookie verificam `__Host-`, Secure, HttpOnly, SameSite=Lax e Path=/ |
| CT-013 | Rotas móveis mutáveis exigem Origin e CSRF vinculado à sessão |
| CT-014 | Gate da Fase 1 mantém limite de login e contrato externo genérico |
| CT-015 | Banco, snapshots, erros e auditoria não contêm tokens ou código brutos |
| CT-016 | `cleanup_retained` remove continuações e challenges terminais elegíveis |

O E2E executa o mesmo fluxo com WebSocket ativo e completamente ausente em desktop e mobile. O
exchange nunca depende do evento: ambos os caminhos terminam pelo snapshot persistido.

## Riscos residuais

- Number matching não impede phishing/relay em tempo real.
- Rate limit e sinalização WebSocket são locais à instância; Redis/PubSub são necessários antes de
  escala horizontal.
- `BarcodeDetector` não existe em todos os navegadores; nesses casos a interface orienta usar a
  câmera do sistema, que preserva o fragmento da URL.
