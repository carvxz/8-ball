# Cpioa — painel de jogos

Administração exclusiva do proprietário em [carvxz.github.io/8-ball](https://carvxz.github.io/8-ball/), com API e banco D1 na Cloudflare.

| Painel | Prefixo da key | `product` na API |
| --- | --- | --- |
| Scripts | `CPIOA` | `scripts` |
| 8Ball Pool | `CPIOA8` | `8ball` |
| Free Fire | `CPIOAff` | `freefire` |

Cada painel tem geração, pesquisa, contadores e lista próprios. Validade em minutos ou horas inteiras, de 1 minuto a 1 ano, ou sem expiração; o prazo começa na geração. A lista permite copiar a key completa, pausar/reativar e excluir. A exclusão bloqueia a key e a move para **Excluídas**, onde pode ser restaurada sem alterar vencimento ou revogação. A pausa geral afeta os três painéis. Não há geração pública.

## Publicação

Os arquivos estáticos ficam na raiz: GitHub Pages, branch `main`, pasta `/ (root)`. `config.js` contém apenas a URL pública da API. `worker/worker.mjs` é o código ESM para o Worker existente `cpioa-keys-api`, mantendo o binding D1 `DB`, `ADMIN_PASSWORD_HASH` e `ALLOWED_ORIGINS` já configurados. O segredo da senha administrativa fica exclusivamente na Cloudflare.

Na primeira execução sobre o banco anterior, o Worker acrescenta as colunas de produto, cópia criptografada e exclusão, e arquiva as keys antigas em **Scripts → Excluídas**. Essa migração é atômica, executada uma vez, e preserva os registros e seus hashes. Essas keys antigas só tinham hash e código mascarado; seu código completo não pode ser copiado. Gere novas keys para os aplicativos atualizados.

Novas keys têm hash de validação e uma cópia criptografada por AES-GCM. Somente o administrador autenticado pode recuperar a cópia. A criptografia deriva de `KEY_STORAGE_SECRET`, quando configurado, ou do segredo `ADMIN_PASSWORD_HASH` existente. Trocar o segredo usado na derivação exige recriptografar as cópias; os hashes continuam validando as keys. Não publique segredos no repositório.

## Integração dos aplicativos

`POST /v1/verify`, JSON:

```json
{"product":"8ball","key":"CPIOA8-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX"}
```

O aplicativo deve enviar seu `product` fixo. O servidor verifica o prefixo e o produto armazenado, além de validade, exclusão, pausa e revogação. Uma key de outro painel retorna `KEY_WRONG_APP`; aplicativos sem `product` recebem `APP_REQUIRED`. Os APKs anteriores precisam dessa atualização antes de usar o novo sistema. A autenticação administrativa e as sessões existentes continuam iguais.

Rotas administrativas exigem `Authorization: Bearer <sessão>`:

- `POST /v1/admin/keys`: `{"product":"8ball","label":"Teste","duration":{"value":30,"unit":"minutes"}}`; use `duration: null` para ilimitada.
- `GET /v1/admin/keys?product=8ball&status=all`; `status=deleted` consulta Excluídas.
- `POST /v1/admin/keys/<id>/copy`, `/delete`, `/restore`, `/pause` ou `/resume`, com `{"product":"8ball"}`.

## Testes

Node.js 24, sem dependências externas:

```sh
node --check app.js
node --check worker/worker.mjs
node --test worker/worker.test.mjs
```

A suíte executa o Worker real com WebCrypto e SQLite em memória, incluindo migração, matriz entre os três jogos, autenticação, duração, cópia criptografada e exclusão/restauração. A senha da suíte é fictícia e não tem relação com produção.
