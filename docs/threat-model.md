# Modelo de ameaças

## Controles disponíveis após o Prompt 02

| Ameaça | Controle implementado | Limite residual |
|---|---|---|
| CSRF em mutações autenticadas por cookie | Token aleatório de 256 bits vinculado ao identificador da sessão por HMAC, expiração explícita, validação de `Origin` e fallback restrito para `Referer` | Cada handler futuro ainda precisa compor os validadores; SameSite é apenas defesa adicional |
| CSWSH | Allowlist normalizada e `Origin` obrigatório, sem fallback para `Referer` | O handshake WebSocket será implementado na fase de QR e deverá chamar a política |
| Roubo/fixação de sessão | Construtores únicos para `__Host-session` e `__Host-qr-cont`, sempre `Secure`, `HttpOnly`, `Path=/`, sem `Domain`, com SameSite e TTL explícitos | Rotação, revogação e persistência de sessão entram com os endpoints de autenticação |
| Replay ou vazamento de tokens persistidos | CSPRNG do sistema, tokens de 256 bits e fingerprints HMAC-SHA-256 com separação de contexto, comparação constante e keyring rotacionável | Segredos em memória ainda dependem da segurança do processo e host |
| Credential stuffing e abuso de fluxo | Porta de rate limiting por operação e chave composta, com implementação de janela em memória | Estado se perde no restart e não é compartilhado entre instâncias; Redis é obrigatório antes de escala horizontal |
| Vazamento em logs/auditoria | Evento de auditoria tipado, metadata em allowlist, tipos secretos com `Debug` redigido e testes de ausência de valores secretos | Revisar novas categorias/campos e o pipeline externo de observabilidade |
| Clickjacking, MIME sniffing e cache privado | CSP com `frame-ancestors`, `nosniff`, política de referrer e `no-store, private` centralizados | CSP do frontend deverá ser específica quando conteúdo web for servido pelo mesmo componente |
| QR fotografado ou encaminhado | Planejado: TTL, sessão móvel, number matching e uso único | Não mitigado nesta etapa; posse do QR não pode ser tratada como aprovação |
| Queda do WebSocket | Planejado: snapshot, polling e estado persistido | Não implementado nesta etapa |

## Decisões abertas

- Medir limites e janelas por ambiente antes de liberar tráfego real.
- Definir armazenamento e rotação operacional das chaves fora do processo.
- Substituir o limiter em memória antes de executar múltiplas instâncias.
- Revisar CSP final quando API e SPA tiverem topologia de deploy definitiva.
- Aprovar retenção e acesso à auditoria com o controlador de dados.

Nenhum uso público deve ocorrer sem revisão independente.
