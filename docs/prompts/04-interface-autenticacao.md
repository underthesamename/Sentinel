# Prompt 04 — Interface funcional de autenticação

## Prompt

Conecte o frontend do Sentinel aos endpoints reais entregues pelo Prompt 03. Antes de alterar a interface, leia `PRODUCT.md`, `DESIGN.md`, o sidecar `.impeccable/design.json`, a surface brief existente e os contratos OpenAPI. Preserve a identidade visual de serigrafia em três tintas e a honestidade sobre o estágio do projeto.

### Objetivo

Transformar a apresentação existente em uma entrada funcional para cadastro, login, sessão autenticada e logout, sem perder a página pública e sem simular sucesso.

### Escopo obrigatório

1. Definir navegação pública para apresentação, cadastro e login.
2. Criar formulários acessíveis com labels persistentes, autocomplete correto e mensagens de recuperação claras.
3. Integrar cadastro e login aos endpoints reais, usando cookies HTTP e sem persistir tokens no JavaScript.
4. Obter e enviar CSRF conforme o contrato do backend.
5. Criar estado autenticado com identidade mínima e ação de logout.
6. Implementar estados de carregamento, erro, sucesso, sessão expirada e serviço indisponível.
7. Evitar enumeração de contas também na linguagem da interface.
8. Preservar foco, navegação por teclado, contraste e redução de movimento.
9. Adaptar cuidadosamente desktop e celular.
10. Atualizar testes E2E e documentação de execução.

### Direção visual

- Reutilizar papel claro, cyan, âmbar, scarlet, sobreposição e marcas de registro.
- Tratar estados do formulário como alinhamento/desalinhamento dos passes, sem depender somente de cor.
- Não usar modais para cadastro ou login.
- Não criar cards genéricos ou uma identidade paralela.
- Campos e botões devem continuar familiares e operáveis.

### Testes obrigatórios

- Fluxo de cadastro e login com backend real.
- Erros genéricos de credenciais.
- Sessão restaurada após recarregar a página.
- Logout e sessão expirada.
- Teclado, foco e labels.
- Viewports desktop e mobile.
- Build de produção e detector visual.

### Critérios de conclusão

- Nenhuma ação principal é apenas decorativa.
- A interface nunca afirma sucesso antes da confirmação do servidor.
- O design público e as telas operacionais pertencem ao mesmo sistema.
- O backend continua sendo a autoridade de autenticação.

