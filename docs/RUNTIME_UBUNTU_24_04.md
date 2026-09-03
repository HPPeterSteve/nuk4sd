# Runtime Ubuntu 24.04 obrigatório

Este runtime é uma raiz de userspace Ubuntu 24.04 AMD64 mínima e obrigatória para toda execução isolada pelo Nuk4sd portátil. Ele é incorporado ao instalador em `runtime/`; o núcleo não aceita outra raiz e não inicia uma sandbox se esse arquivo estiver ausente ou alterado. Ele não é uma máquina virtual e não inclui um kernel próprio: o kernel, os drivers e a disponibilidade de namespaces, FUSE e recursos gráficos continuam sendo os do Linux hospedeiro.

## Artefato

| Campo | Valor |
|---|---|
| Arquivo no pacote | `runtime/nuk4sd-runtime-ubuntu-24.04-amd64.tar.gz` |
| Formato | `tar.gz`, caminhos relativos, sem artefatos de build |
| Base | Ubuntu 24.04 (`noble`) AMD64, instalação mínima |
| SHA-256 | `6a71bb27bf32b04723697a8f68a090dec2697ece9286f38513e415a764e68c55` |

O pacote contém a hierarquia completa do rootfs, incluindo `etc/os-release`, `bin`, `lib`, `usr` e os metadados de pacote mínimos. Ele **não inclui Firefox**, Chromium, drivers gráficos ou um servidor gráfico. Esses componentes devem ser incorporados e testados como uma extensão separada do runtime, para que a base permaneça pequena e auditável.

## Uso

Instale ou execute o arquivo portátil normalmente. Não é necessário passar `--image` ou `--no-fuse`: para todo `--run`, o núcleo seleciona a raiz Ubuntu incluída e deixa de depender do vault/FUSE.

```bash
/caminho/para/Nuk4sd \
  --run /bin/true --
```

O Nuk4sd verifica o SHA-256 incorporado no binário, extrai o arquivo para um diretório temporário, monta essa raiz como `/` da sandbox e executa o programa indicado dentro dela. Se o arquivo não existir, não corresponder à soma esperada ou não puder ser importado, o lançamento falha com código diferente de zero; não há fallback para o filesystem hospedeiro, vault ou uma imagem indicada pelo usuário.

## Verificação manual

Antes de usar, compare a soma do arquivo:

```bash
sha256sum runtime/nuk4sd-runtime-ubuntu-24.04-amd64.tar.gz
```

O valor exibido deve ser exatamente o SHA-256 da tabela. O teste de integração desta entrega executou `/bin/true` dentro dessa raiz obrigatória e confirmou o retorno `0` após `pivot_root`. Também foram testadas as recusas de runtime ausente e de runtime alterado.

## Limites atuais

Esta primeira imagem comprova o caminho de runtime local e fornece uma base Ubuntu repetível; ela não comprova a execução do Firefox. Uma edição futura para navegadores precisa conter o navegador e suas dependências, além de ter uma matriz própria de testes para X11/Wayland, áudio, GPU e sandbox aninhado.
