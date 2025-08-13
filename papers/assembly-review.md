---
title: "Review sobre assembly"
author: "slayer"
---

## O que é ****assembly****?

****Assembly**** é uma linguagem de programação de baixo nivel, ela é escrita para se comunicar diretamente com o hardware do **processador**. Ao contrário das linguagens de alto nivel, como o famoso python, o ****assembly**** opera próximo ao código de máquina, o famoso binário! Cada instrução em ****assembly**** geralmente representa uma única operação da **CPU**, como mover dados entre **registradores**, realizar operações aritméticas ou controlar o fluxo de execução.

****Assembly**** não é universal!! Ele depende diretamente da arquitetura do **processador**. Por exemplo, um código em ****assembly**** feito para processadores **x86** não funcionará em uma arquitetura ARM, isso significa que aprender ****assembly**** é também aprender sobre a estrutura interna e o funcionamento da **cpu** em questão. Então, se você quer aprender ****assembly****, papers como o do nosso membro voiiid podem te ajudar bastante nessa jornada! https://pwnbuffer.org/en/posts/void/**x86**/

Aqui está uma tabela dos **registradores** **x86** e **x86_64**, mostrando EAX, EBX... e seus equivalentes, RAX, RBX...

<div style="text-align: center;">
  <img src="/images/slayer/review-asm/register-table.png" alt="2">
</div>

****Assembly**** é uma linguagem bem antiga, surgindo em meados dos anos 50, mas mesmo assim, ela é muito relevante, mas, por que ainda é relevante?

Simplesmente porque ela é uma ferramenta essencial em várias áreas da computação, como na engenharia reversa, para analisar binários e entender softwares sem acesso ao código fonte.

****Assembly**** NÃO é uma linguagem genérica! Ela reflete a arquitetura do **processador** que está sendo usado. Isso significa que os **registradores**, instruçõees e modos de endereçamento variam entre arquiteturas como **x86**, **x86_64**, ARM & MIPS. Aprender ****assembly**** é aprender a linguagem interna do **processador**. Essa ligação direta torna ****assembly**** indnispensável para compreender como um código em C se transforma em instruções binárias e como o sistema realmente executa cada linha do código. Ele revela o que está "por baixo do tapete".

![2](../img//images/slayer/review-asm/architecture_block.svg)

***

## Arquitetura **x86**/**x86_64**

A principal diferença entre as arquiteturas de 32 bits e de 64 bits está na largura dos **registradores**, ou seja, na quantidade de dados que o **processador** pode manipular de uma vez:

- 32 bits --> os **registradores** e os endereços são limitados a 4GB
- 64 bits --> os **registradores** e os endereços podem acessar até 16 exabytes, teoricamente (2⁶⁴) embora o limite na pratica seja muito menor

Além do aumento da capacidade, a arquitetura **x86_64** traz mais **registradores**, o que melhora o desempenho e reduz a necessidade de acessar a memória constantemente.

***

### **Registradores** principais

#### **x86**

- EAX, EBX, ECX, EDX --> **registradores** gerais
- ESP --> **stack pointer**
- EBP --> **base pointer**
- ESI/EDI --> cópia & manipulação de memória

Cada registrador tem 32 bits (ou seja, 4 bytes) eles também podem ser acessados parcialmente como AX, AH, AL (16 e 8 bits)

***

#### **x86_64**

- todos os **registradores** de 32 bits foram expandidos: EAX --> RAX, EBX --> RBX e etc..
- adição de novos **registradores** R8 até R15
- **stack pointer** e **base pointer** também mudaram: ESP --> RSP & EBP --> RBP

Cada registrador agora armazena 64 bits (8 bytes) e também pode ser acessado em porções, por exemplo: RAX (64 bits), EAX (32 bits), AX (16 bits), AL (8 bits)

***

## Estrutura de um Programa em ****Assembly****

Um programa em ****assembly**** geralmente é dividido em seções que organizam os dados e o código, por exemplo:

- `.data` --> onde ficam os dados inicializados (como as strings e variáveis com valor definido)
- `.bss` --> para dados não inicializados (variáveis reservadas, mas sem valor inicial)
- `.text` --> contém o código executável do programa




```assembly
section .data
    msg db "Olá, Mundo!", 0Ah

section .text
    global _start
_start:
    ;sys write
    mov eax, 4
    mov ebx, 1
    mov ecx, msg
    mov edx, 13
    int 0x80

    ;sys exit
    mov eax, 1
    xor ebx, ebx
    int 0x80
```




Esse exemplo usa chamadas de sistema do **linux** com `int 0x80`, válidas em sistemas de 32 bits. Ele simplesmente imprime `"Olá, Mundo!"` no terminal e depois finaliza o programa.

***

## Conceitos Chave

- Intruções comuns:

 - `MOV` --> move dados entre **registradores** e memória
  - `ADD`, `SUB` --> soma e subtração
  - `CMP` --> compara valores (usado antes de `JMP`)
  - `JMP`, `JE`, `JNE`, etc. --> saltos (condicionais ou não)

- Flags:
  - `ZF` (Zero Flag) --> setada se o resultado for zero
  - `CF` (Carry Flag) --> indica overflow em operações sem sinal
  - `SF` (Sign Flag) --> indica se o resultado é negativo
  - `OF` (Overflow Flag) --> indica overflow em operações com sinal

- Stack:
  - `PUSH` --> coloca um valor na stack
  - `POP` --> remove o topo da stack
  - `CALL` --> empilha o endereço de retorno e salta para a função
  - `RET` --> retorna da função para o endereço salvo




```asm
section .data
    msg db "exec func!", 0Ah
    len equ $ - msg

section .text
    global _start

_start:
    call message

    mov eax, 1
    xor ebx, ebx
    int 0x80

message:
    push eax
    push ebx

    mov eax, 4
    mov ebx, 1
    mov ecx, msg
    mov edx, len
    int 0x80

    pop ebx
    pop eax
    ret
```




Nesse exemplo, o programa chama a função `message` usando `CALL`, que automaticamente faz um `PUSH` do endereço de retorno. 

Dentro da função: 

- Os **registradores** `eax` & `ebx` são salvos com `PUSH`
- A **syscall** `write` imprime `"exec func!"`
- Depois, `POP` restaura os **registradores** originais
- E o `RET` volta para depois do `CALL`, onde o programa continua

***

## Calling Conventions

As calling conventions definem como funções recebem argumentos, retornam valores e manipulam a stack, são essas as regras que garantem compatibilidade entre codigos ****assembly**** e outras linguagens como C!

### Main Conventions

- `cdecl` --> C declaration, comum no **linux** 32 bits
    - argumentos: passados na stack, da direita pra esquerda
    - responsável por limpar a stack: quem chama a função `caller`
    - retorno: via `EAX`
    - muito usada com: GCC, linguagens C/C++

- `stdcall` --> Comum no **windows** 32 bits
    - argumentos: passados na stack, da direita pra esquerda
    - responsável por limpar a stack: a função chamada `callee`
    - retorno: via `EAX`
    - muito usada com: APIs do **windows**

- `sycv` --> System V AMD64 ABI, padrão no **linux** 64 bits
    - argumentos: via **registradores**, nesta ordem:
        - `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`
        - extras vão para a stack
    - retorno: via `RAX`
    - responsável por salvar **registradores** temporários: `caller`

### Resumão visual:

| Convenção | Plataforma  | Argumentos via       | Retorno | Quem limpa a pilha |
|-----------|-------------|---------------------|---------|--------------------|
| `cdecl`   | **Linux** 32bit | Pilha (dir → esq)   | EAX     | Quem chama         |
| `stdcall` | **Windows** 32b | Pilha (dir → esq)   | EAX     | Função chamada     |
| `sysv`    | **Linux** 64bit | **Registradores** + pilha| RAX     | Quem chama         |


Bom, chegamos ao final de mais um paper, muito obrigado por ler até aqui! Espero ter te ajudado em algo, e segue as fontes que utilizei para criar este artigo! ;)

***
Fontes usadas para a construção deste artigo:

- [**Assembly** Language - Wikipedia](https://en.wikipedia.org/wiki/Assembly_language)
- [**Processador** 64 bits vs 32 bits - Tecnoblog](https://tecnoblog.net/responde/**processador**-64-bits-vs-32-bits-diferencas/)
- [**x86** overview - cs.lmu.edu](https://cs.lmu.edu/~ray/notes/x86overview/)
- [**Assembly** quick guide - tutorialspoint](https://www.tutorialspoint.com/assembly_programming/assembly_quick_guide.htm)
- [Intel® 64 and IA-32 Architectures Developer Manuals (PDFs oficiais)](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [Calling Conventions - Wikipedia](https://en.wikipedia.org/wiki/Calling_convention)  
- [NASM Documentation](https://www.nasm.us/doc/)
