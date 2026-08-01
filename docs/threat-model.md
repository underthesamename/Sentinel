# Modelo de ameaças

## Controles disponíveis após o Prompt 03

| Ameaça | Controle implementado | Limite residual |
|---|---|---|
| CSRF em mutações autenticadas por cookie | Logout exige token aleatório de 256 bits vinculado à sessão por HMAC, expiração explícita e validação de origem | Novas mutações autenticadas ainda precisam compor os mesmos validadores; SameSite é apenas defesa adicional |
| CSWSH | Allowlist normalizada e `Origin` obrigatório, sem fallback para `Referer` | O handshake WebSocket será implementado na fase de QR e deverá chamar a política |
| Roubo/fixação de sessão | Sessão opaca persistida apenas por fingerprint; `__Host-session` seguro; rotação invalida a sessão apresentada no login; timeout ocioso/absoluto e revogação no servidor | XSS ou comprometimento do host ainda podem agir enquanto a sessão estiver válida; gestão de todas as sessões é fase posterior |
| Enumeração e credential stuffing | Conta inexistente e senha incorreta produzem contrato equivalente e executam Argon2id; rate limit usa conta normalizada + rede | Tempos podem variar por carga e banco; limiter em memória perde estado no restart |
| Senhas fracas ou vazadas | Mínimo de 15 caracteres, suporte a senhas longas, blocklist inicial e Argon2id 19 MiB/t=2/p=1 | A blocklist embarcada é deliberadamente pequena; antes de produção deve ser substituída por corpus versionado e processo de atualização |
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
