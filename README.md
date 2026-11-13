# Keycloak LNURL-auth

Provedor de identidade Keycloak para login e cadastro com uma carteira Lightning que suporte LNURL-auth. O identificador externo é a chave pública comprimida que a carteira deriva para o domínio. Na primeira entrada, o fluxo **First Broker Login** do realm coleta os dados obrigatórios e cria ou vincula a conta após a confirmação do usuário.

## Instalação

Requisitos de build: Java 21 e Maven. Use o Keycloak **26.8.2** ou uma versão com as correções de segurança posteriores. A distribuição do Keycloak fornece o Bouncy Castle.

```sh
mvn verify
```

Copie `target/keycloak-lnurl-auth-0.2.1.jar` para `/opt/keycloak/providers/` e execute `kc.sh build` antes de iniciar a imagem otimizada. Em **Identity providers**, adicione o provedor do tipo `lnurl-auth` e escolha um nome como `Lightning wallet`. Mantenha **Trust Email** e **Store Tokens** desativados. O Keycloak exibe o provedor na tela de login do tema padrão. O JAR inclui os recursos necessários para essa tela e para o fluxo de autenticação.

Configure o hostname público do Keycloak com HTTPS para que a carteira possa alcançar `/realms/<realm>/broker/<alias>/endpoint/wallet`. Use o mesmo domínio ao atualizar a implantação, pois a carteira usa o domínio para derivar a identidade. O fluxo gera um `k1` de 32 bytes por tentativa e deixa o parâmetro opcional `action` em aberto. O Keycloak decide entre cadastro, login e vinculação. O desafio expira em três minutos, aceita uma única assinatura DER ECDSA válida e só conclui no navegador que iniciou a tentativa.

O provedor permite até cinco verificações por desafio e vinte por IP em cada janela de dez segundos, por realm e alias. Ao esgotar as tentativas do desafio, volte à tela de login para gerar outro QR Code. Se houver um proxy reverso, configure os cabeçalhos encaminhados e restrinja os proxies confiáveis para que o Keycloak identifique o IP correto.

## Testes

`mvn verify` confere o vetor Bech32 da LUD‑01, a leitura do QR Code, a validação de assinatura sobre o `k1` bruto e o limite de tentativas. Para validar a instalação, habilite o provedor em um realm com o tema padrão e conclua o login no navegador.

## Referências e licença

- [Keycloak Server Developer Guide](https://www.keycloak.org/docs/26.8.2/server_development/)
- [LUD‑01 — Codificação do LNURL](https://github.com/lnurl/luds/blob/luds/01.md)
- [LUD‑04 — LNURL-auth](https://github.com/lnurl/luds/blob/luds/04.md)
- [LUD‑05 — Derivação BIP32 na carteira](https://github.com/lnurl/luds/blob/luds/05.md) e [LUD‑13 — Derivação com signMessage na carteira](https://github.com/lnurl/luds/blob/luds/13.md)

Código do projeto sob [licença MIT](LICENSE). O gerador de QR Code usa ZXing, distribuído sob a licença Apache 2.0.


## Publicar uma versão

Atualize a versão em `pom.xml`. Depois que a alteração entrar em `main`, crie e envie uma tag anotada `vX.Y.Z` no commit da versão. O GitHub Actions valida a origem da tag, roda os testes e publica o JAR e seu `SHA256SUMS` em Releases.
