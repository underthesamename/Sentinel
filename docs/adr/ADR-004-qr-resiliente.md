# ADR-004 — Login QR resiliente

## Decisão

O PostgreSQL é a única fonte de verdade do login QR. O desktop recebe, na criação, um
`subscription_token` de alta entropia que autoriza snapshot, polling e exchange. O WebSocket só
transporta snapshots autenticados e pode desaparecer em qualquer ponto do fluxo.

O `qr_token` existe apenas no fragmento da URL. O frontend o remove imediatamente e o backend o
converte em `__Host-qr-cont` HttpOnly antes de qualquer login. Scan, código e decisão ficam
vinculados ao par exato `scanner_user_id` + `scanner_session_id`.

Todas as transições usam estado esperado, `lock_version`, identidade e validade na mesma operação.
O exchange bloqueia a linha do challenge, insere a sessão com `source_challenge_id` único e muda o
estado para `EXCHANGED` na mesma transação.

## Consequências

- Perder mensagens ou reconectar não impede conclusão por polling.
- Aprovação móvel nunca cria cookie no desktop; somente `/exchange` o faz.
- Number matching reduz erro e fadiga, mas não impede relay/phishing em tempo real.
- Sinalização WebSocket entre múltiplas instâncias exigirá Pub/Sub; cada instância continuará
  confirmando o snapshot no PostgreSQL.
