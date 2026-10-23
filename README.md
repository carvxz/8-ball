# Cpioa Access

Site: https://carvxz.github.io/8-ball/
API: https://cpioa-keys-api.saiasporu.workers.dev

Somente o administrador autenticado gera keys e as entrega aos usuários. A página pública permite verificar uma key recebida e mostra como entrar no app Cpioa. A administração permite definir validade, pausar, reativar e revogar keys, além de pausar o acesso geral.

O app Android valida a key por HTTPS em POST /v1/verify e renova a autorização usando checkAfterSeconds. Uma key salva no aparelho precisa de nova validação após reiniciar o processo.

Na Cloudflare, PUBLIC_GENERATION=false mantém a geração anônima desativada na API. As keys continuam sendo emitidas em POST /v1/admin/keys, com sessão administrativa. A senha fica em um Secret da Cloudflare e não é incluída no site nem no APK.

Os arquivos da página são publicados por GitHub Pages a partir da branch main, pasta raiz. config.js contém apenas a URL pública da API. API e banco ficam na Cloudflare.
