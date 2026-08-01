# Mapa inicial de dados pessoais

| Dado | Finalidade | Minimização | Retenção proposta |
|---|---|---|---|
| E-mail normalizado | Identidade e login | Nunca registrar em texto em logs | Enquanto a conta for necessária |
| IP | Segurança e rate limit | Prefixo/pseudônimo em logs duradouros | IP completo por até 30 dias |
| User-Agent resumido | Contexto de dispositivo | Não usar como sinal de confiança | Junto da sessão/challenge |
| Tokens e códigos | Autenticação transitória | Apenas hash/fingerprint | Inutilizar no estado terminal |
| Auditoria pseudonimizada | Segurança e prestação de contas | Campos em allowlist | 90–180 dias, sujeito a aprovação |

As bases legais, operadores, compartilhamentos e prazos finais dependem do controlador real e de análise jurídica.

