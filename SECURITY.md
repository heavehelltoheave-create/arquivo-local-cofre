# Política de segurança — Arquivo Local

## Aviso sobre o nível de segurança

Projeto funcional e local para fins de aprendizado e uso consciente. **Não há auditoria criptográfica independente** nem garantia de proteção contra um Windows já comprometido. O uso para senhas de alto impacto exige avaliação prévia. A criptografia depende de uma senha mestra de alta entropia e de bibliotecas atualizadas.

## Resumo técnico

- AES-256-GCM fornece confidencialidade e integridade dos registros.
- Argon2id deriva a chave da senha mestra com salt único de 128 bits; perfil atual: m=256 MiB, t=3, p=2. O perfil antigo (128 MiB, t=3, p=2) é aceito **apenas para decifrar** backups antigos. Há uma lista restrita de parâmetros permitidos, para evitar exaustão de memória via cabeçalhos maliciosos.
- Salt e nonce (96 bits) são gerados com aleatoriedade criptograficamente segura em cada operação. O cabeçalho é autenticado como AAD.
- O DPAPI do usuário Windows envolve *novamente* o registro criptografado armazenado no cofre local, mas malware com acesso à conta pode solicitar o desbloqueio ao Windows.
- Arquivos `.txt` e `.zip` exportados NÃO exigem a conta Windows; para quebrar esses arquivos, o atacante pode tentar adivinhar a senha mestra offline. Não publique esses arquivos.
- Embaralhamento, nomes discretos e embalagem ZIP **não acrescentam segurança criptográfica** e não escondem o formato de um analista.
- Reautenticação da senha mestra é exigida na interface para exportação DPAPI e exclusão de registros; não é uma defesa contra malware com acesso ao disco.

## Limitações conhecidas

1. Strings Python/Tkinter podem persistir temporariamente na memória e não oferecem limpeza de RAM verificável.
2. Mostrar/copiar senhas pode expô-las a keyloggers, área de transferência, gravação de tela ou programas maliciosos. A limpeza programada da área de transferência não remove necessariamente cópias do histórico.
3. Não há autenticação por Windows Hello implementada. Não anuncie suporte a biometria ou MFA.
4. Não existe proteção contra ataques offline além da força da senha mestra e do custo de Argon2id; o atraso por tentativas da UI não é defesa para arquivos copiados.
5. A exclusão padrão não apaga setores e snapshots de forma forense.
6. A perda da senha mestra implica perda de acesso aos backups. Reinstalar o Windows pode impedir o uso do DPAPI antigo; mantenha backups criptografados fora da máquina e teste a restauração.
7. Dependências são limitadas por faixas de versão, não por hashes imutáveis; as instalações devem usar fontes confiáveis e passar por revisões de dependências.

## Recomendação de operação

- Use senha mestra única (frase de várias palavras geradas aleatoriamente ou senha aleatória longa), diferente das credenciais armazenadas.
- Salve dois backups criptografados em mídias distintas. Não armazene senha mestra junto ao backup.
- Habilite proteção de disco completa, Windows Defender e atualizações. Revise ameaças permitidas no Defender antes de confiar neste aplicativo para credenciais importantes.
- Verifique `git status`, `git diff --cached` e faça revisão manual antes de publicar; não inclua arquivos do cofre nem registros reais, mesmo que cifrados.
- Prefira um gerenciador de senhas com auditoria pública (por exemplo, KeePassXC) para credenciais críticas.

## Reportar falhas

**Não coloque vulnerabilidades exploráveis ou senhas reais em issues públicas.** Contate o mantenedor por um canal privado; quando habilitado, use o sistema de *Private vulnerability reporting* do GitHub. Remova dados pessoais de logs e exemplos.
