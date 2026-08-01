# Protocolo WebSocket do login QR

Endpoint: `GET /v1/qr-login/ws`. O handshake exige `Origin` presente na allowlist. Tokens nunca
aparecem na URL.

Em até cinco segundos, o cliente envia uma mensagem `subscribe` de no máximo 4 KiB:

```json
{"type":"subscribe","challenge_id":"019...","subscription_token":"opaco","last_seen_version":2}
```

Após validar o fingerprint, o servidor envia imediatamente o estado persistido:

```json
{"type":"qr.snapshot","challenge_id":"019...","status":"APPROVED","version":4,"qr_expires_at":"...","approval_expires_at":"..."}
```

Mudanças posteriores produzem outro snapshot. O servidor encerra após estado terminal. O cliente
deve iniciar polling autenticado quando o socket falhar; eventos não são replayados e nunca são
necessários ao exchange.
