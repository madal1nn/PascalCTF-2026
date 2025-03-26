#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *flag = "\x56\x4c\x75\x5c\x38\x6d\x39\x58\x6c\x28\x3e\x57\x7b\x5f\x3f\x54\x44\x5b\x71\x20\x82\x1b\x8b\x50\x80\x46\x7e\x15\x8a\x57\x7d\x5a\x50\x54\x81\x51\x8c\x0c\x94\x44";
char *code;
char *mem;

enum VM_OP {
    VM_OP_RET = 0,
    VM_OP_ADD = 1,
    VM_OP_SUB = 2,
    VM_OP_MOD = 3,
    VM_OP_MOV = 4,
    VM_OP_READ = 5,
    VM_OP_CMP_JMP = 6,
};

void initVM() {
    FILE *bytecode = fopen("code.pascal", "r");
    if (!bytecode) {
        perror("Failed to open bytecode file");
        return;
    }
    code = malloc(4096);
    mem = malloc(1024);

    if (!mem || !code) {
        perror("Failed to initialize memory");
        fclose(bytecode);
        free(code);
        free(mem);
        return;
    }

    memset(mem, 0, 1024); 
    size_t bytesRead = fread(code, sizeof(char), 4096, bytecode);
    
    if (bytesRead == 0) {
        perror("Failed to read bytecode file");
        free(code);
        free(mem);
        fclose(bytecode);
        return;
    }

    fclose(bytecode);
}

char readByte(char *ptr) {
    return *ptr;
}

int readInt(char *ptr) {
    return readByte(ptr) | (readByte(ptr + 1) << 8) |
        (readByte(ptr + 2) << 16) | (readByte(ptr + 3) << 24);
}

void executeVM() {
    int ip = 0;
    while (code[ip] != 0) {
        int addr;
        char value;
        
        switch (code[ip++])
        {
        case VM_OP_ADD:
            addr = readInt(code + ip);
            value = readByte(code + ip + 4);
            mem[addr] += value;
            ip += 5;
            break;

        case VM_OP_SUB:
            addr = readInt(code + ip);
            value = readByte(code + ip + 4);
            mem[addr] -= value;
            ip += 5;
            break;

        case VM_OP_MOD:
            addr = readInt(code + ip);
            value = readByte(code + ip + 4);
            if (value == 0) {
                fprintf(stderr, "Division by zero error\n");
                exit(EXIT_FAILURE);
            }
            mem[addr] %= value;
            ip += 5;
            break;

        case VM_OP_MOV:
            addr = readInt(code + ip);
            value = readByte(code + ip + 4);
            mem[addr] = value;
            ip += 5;
            break;

        case VM_OP_READ:
            addr = readInt(code + ip);
            scanf("%c", mem + addr);
            ip += 4;
            break;

        case VM_OP_CMP_JMP:
            addr = readInt(code + ip);
            char value = readByte(code + ip + 4);
            if (!mem[addr]) {
                ip += value;
            }
            ip += 5;
            break;

        default:
            fprintf(stderr, "Unknown operation code: %d\n", code[ip]);
            exit(EXIT_FAILURE);
        }
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    initVM();
    executeVM();

    if (strcmp(mem, flag) == 0) {
        puts("Congratulations! You have successfully executed the code.");
    } else {
        puts("Execution failed. The code did not match the expected flag.");
    }
    free(code);
    free(mem);
    return 0;
}