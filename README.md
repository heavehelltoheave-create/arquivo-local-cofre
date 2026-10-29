# Arquivo Local — cofre de senhas para Windows

Aplicativo local com três abas: **Criar e proteger**, **Recuperar**, **Disfarçar arquivo**.

## Como instalar e abrir

1. No Windows 10/11, instale o **Python 3.11 ou superior** com a opção *Add Python to PATH* em https://www.python.org/downloads/windows/ (se ainda não tiver).
2. Extraia este ZIP em uma pasta privada.
3. Execute `Instalar_e_Abrir.bat`. A primeira instalação requer internet apenas para baixar as bibliotecas do Python.
4. Nas próximas vezes, execute `Abrir.bat`. Depois da instalação, **o aplicativo funciona sem internet**.
5. Opcional: execute `Criar_EXE.bat` no próprio Windows para produzir `dist\ArquivoLocal.exe`, sem exigir Python no computador onde será executado. O EXE não está incluído porque a compilação Windows não foi executada neste ambiente.

Não execute o programa como administrador: use sua conta normal do Windows.

## Proteção real (e limites)

- A senha a proteger é misturada com caracteres aleatórios e embaralhada; a ordem de recuperação também é criptografada. **Essa transformação não aumenta a segurança de AES**; apenas atende ao formato solicitado.
- A proteção criptográfica é **AES-256-GCM** com autenticação de integridade e **Argon2id** para derivar a chave da senha mestra (256 MiB de memória, 3 iterações e paralelismo 2, para novos registros). Sal aleatório de 16 bytes, nonce aleatório de 12 bytes, diferentes para cada arquivo.
- **Compatibilidade:** arquivos criados na edição anterior, com Argon2id de 128 MiB, continuam abrindo nesta edição. Arquivos novos (256 MiB) podem não abrir na edição antiga; **não remova seu backup da versão anterior sem testar a nova edição**.
- A criação de novos registros recusa algumas senhas mestras óbvias e repetitivas; isso **não é um medidor de entropia certificado**. O aplicativo ainda aceita senhas mestras antigas para abrir backups.
- A senha mestra **não é gravada em arquivo**. É necessário lembrar dela para recuperar o conteúdo.
- No cofre Windows, o arquivo já criptografado é protegido **novamente** pelo DPAPI da conta Windows. Os dados ficam em `%LOCALAPPDATA%\LocalVault\records` com nomes aleatórios. Os dados podem ficar inacessíveis após troca de computador ou redefinição administrativa da senha da conta.
- A cópia externa `.txt` é criptografada de verdade e pode ser aberta em outro Windows com este programa e a senha mestra. Ela **não** depende do DPAPI.
- O ZIP da aba 03 é **um ZIP verdadeiro**, mas o conteúdo interno está cifrado. Ele *não* adiciona criptografia nova nem disfarça completamente sua existência para especialistas.
- Ao recuperar, a senha é mascarada. Você pode revelá-la por 15 segundos e copiá-la; o programa tenta limpar a área de transferência após 20 segundos, se ainda for a mesma. **O histórico da área de transferência e outros programas podem manter cópias**.
- A interface limpa os campos sensíveis após 60 segundos de inatividade; **Ctrl+L** bloqueia manualmente; **Python/Windows não garantem apagamento de todas as cópias em RAM**.
- A exportação direta de um registro DPAPI e a exclusão pelo aplicativo pedem **novamente a senha mestra**. Isso protege a interface contra uso casual, mas não impede um programa malicioso de copiar/apagar arquivos com os privilégios da sua conta.
- O bloqueio de tentativas vale apenas na interface. Como arquivos exportados permitem ataques offline, **uma senha mestra longa, única e aleatória é indispensável**.
- Malware executado na **mesma conta Windows**, um administrador comprometido, keyloggers ou acesso à sessão desbloqueada ainda podem obter suas senhas. Nenhum cofre local consegue prometer que “só você” terá acesso sob essas condições.
- **Este aplicativo é um projeto novo, sem auditoria independente de segurança.** Para senhas críticas, recomendamos um gerenciador de senhas estabelecido e auditado, como KeePassXC ou Bitwarden.

## Fluxos

### Aba 01 — criar e proteger

Digite uma senha existente ou gere uma aleatória de 32 caracteres. Coloque a senha mestra **diferente da senha armazenada** e confirme. Guarde no cofre Windows e/ou exporte uma cópia `.txt`. Faça pelo menos um backup externo criptografado para não depender exclusivamente do DPAPI do Windows. Quando instalar uma versão atualizada do aplicativo, execute novamente `Instalar_e_Abrir.bat` para atualizar as dependências no ambiente virtual.

### Aba 02 — recuperar

Selecione um registro do cofre Windows (identificado por código e data) ou abra um arquivo `.txt` ou `.zip` produzido pelo aplicativo. Informe a senha mestra, desbloqueie e depois use Mostrar ou Copiar. Para **exportar um backup cifrado do cofre** ou **excluir um registro**, confirme a senha mestra novamente. O backup só contém ciphertext e não requer exportar a senha em claro.

### Aba 03 — disfarçar

Selecione um `.txt` exportado, crie um ZIP e escolha um nome genérico. Ele pode ser aberto diretamente na aba Recuperar, ou convertido de volta em `.txt` pela opção Restaurar. O aplicativo nunca exporta uma senha em texto simples.

## Boas práticas

- Use senha mestra **única**, longa, que não use em outros sites, idealmente uma frase aleatória de muitas palavras ou senha aleatória guardada em local seguro.
- Salve pelo menos duas cópias cifradas em mídias diferentes e **teste** a recuperação com sua senha mestra.
- Proteja sua sessão do Windows, habilite BitLocker se disponível e mantenha Defender e atualizações ativos.
- Desative o histórico da área de transferência (Windows + V), caso queira reduzir retenção de senhas copiadas.
- Nunca salve sua senha mestra no mesmo arquivo que está protegendo.

## Arquivos do projeto

`app.py` contém a interface Tkinter, `securebox_core.py` os algoritmos de criptografia, `windows_vault.py` o DPAPI, `test_securebox.py` testes automatizados e `requirements.txt` as dependências. Sem nuvem, contas, publicidade ou telemetria.

## Preparar e publicar no GitHub

Este ZIP **não inclui** senhas, registros DPAPI, exemplos contendo segredos, tokens ou backups. O arquivo `.gitignore` também bloqueia padrões comuns de dados confidenciais. **Antes de cada push, inspecione os arquivos preparados** com `git diff --cached --name-only` e `git diff --cached`. Nunca publique seu `.txt` criptografado real nem os arquivos de `%LOCALAPPDATA%\LocalVault\records`, mesmo em repositórios privados.

1. Crie um repositório **Private** em https://github.com/new com o nome `arquivo-local-cofre`, **sem** inicializar com README ou `.gitignore` (já estão no projeto).
2. Abra o PowerShell na pasta extraída e execute os comandos a seguir. O exemplo usa o login da conta GitHub conectada; ajuste se desejar outra conta; **não cole senhas nem tokens em comandos**.

```powershell
git init -b main
git add README.md SECURITY.md .gitignore .github/workflows/tests.yml .github/dependabot.yml requirements.txt app.py securebox_core.py windows_vault.py test_securebox.py Abrir.bat Instalar_e_Abrir.bat Criar_EXE.bat
git diff --cached --name-only
git diff --cached --check
git commit -m "Initial secure local vault"
git remote add origin https://github.com/senhordochaos3-gif/arquivo-local-cofre.git
git push -u origin main
```

Se o Git solicitar autenticação, conclua no navegador ou pelo gerenciador de credenciais do Git, sem compartilhar suas credenciais. Alternativamente, use **GitHub Desktop → Add existing repository → Publish repository → Keep this code private**.

## Segurança do projeto

Leia `SECURITY.md` antes de guardar credenciais críticas. Este aplicativo é protótipo funcional, não é substituto auditado de um gerenciador consolidado de senhas. Pull requests devem passar pelos testes e análise de segurança. A configuração do Dependabot solicita atualizações periódicas das dependências e do GitHub Actions.
