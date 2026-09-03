# Nuk4sd — pacote completo com runtime Ubuntu

Este pacote reúne o projeto de fontes, o instalador portátil e o runtime Ubuntu 24.04 AMD64 em formatos direto e compactado. Os arquivos foram organizados para que o runtime fique explícito e auditável, além de permanecer incorporado no instalador portátil.

| Caminho | Conteúdo |
|---|---|
| `source/nuk4sd/` | Árvore completa de fontes exportada, incluindo núcleo C/Rust, componentes de sandbox, assets e GUI Qt/Plasma presentes na versão empacotada. |
| `installer/Nuk4sd-portable-linux-x86_64.run` | Instalador portátil para Linux x86_64; contém o runtime obrigatório. |
| `runtime/nuk4sd-runtime-ubuntu-24.04-amd64.squashfs` | Runtime Ubuntu 24.04 AMD64 no formato montável utilizado pelo projeto. |
| `runtime/nuk4sd-runtime-ubuntu-24.04-amd64.tar.gz` | A mesma imagem de runtime, distribuída em formato compactado. |
| `docs/RUNTIME_UBUNTU_24_04.md` | Documento de referência do runtime. |
| `SHA256SUMS` | Checksums SHA-256 do instalador e dos dois formatos de runtime. |

## Conferência de integridade

No diretório raiz deste pacote, execute:

```bash
sha256sum -c SHA256SUMS
```

O resultado esperado é `OK` para os três arquivos listados. O instalador deve ser executado apenas após conferir a integridade e ler a documentação de runtime incluída.

> O projeto permanece em desenvolvimento. A compatibilidade com aplicações gráficas continua em validação; o pacote não deve ser apresentado como garantia de compatibilidade universal.
