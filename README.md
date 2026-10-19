# Cpioa Access

Site de geração e verificação de keys do Cpioa.

- Site: https://carvxz.github.io/8-ball/
- API: https://cpioa-keys-api.saiasporu.workers.dev

Keys públicas sem expiração, painel administrativo com pausa individual, reativação, pausa geral, controle de geração e revogação. Interface responsiva para PC e celular.

Os arquivos da página ficam na raiz para publicação pelo GitHub Pages: branch `main`, pasta `/ (root)`. O arquivo `config.js` contém a URL pública da API. A API e o banco de dados ficam na Cloudflare.

A senha administrativa é definida pelo proprietário como Secret na Cloudflare. Nenhuma senha administrativa está neste repositório. A integração do script Lua será feita em uma etapa separada.