#include "coder.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

void init(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

const char expected[] = {65, 49, 49, 68, 54, 49, 50, 76, 80, 83, 67, 66, 76, 83, 51, 55, 0};
bool check(char *output){
    if (strlen(output) != 16)
        return false;
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 16; j++) {
            output[j] ^= 0x5E;
        }
        for (int j = 0; j < 16; j++) {
            char c = output[j+1];
            output[j+1] = output[j];
            output[j] = c;
        }
    }
    if (strcmp(output, expected) != 0)
        return false;
    return true;
}

int main() {
    char output[20], flag[40], user_input[100];
    
    init();
    
    puts("Welcome into the latest version of");
    puts("      Albo delle Eccellenze       ");
    puts("   (PascalCTF Beginners 2026)     ");
    puts("");
    
    Data userdata;

    memset(&userdata, 0, sizeof(userdata));

    printf("Enter your name: ");
    fgets(userdata.name, sizeof(userdata.name), stdin);
    printf("Enter your surname: ");
    fgets(userdata.surname, sizeof(userdata.surname), stdin);
    printf("Enter your date of birth (DD/MM/YYYY): ");
    fgets(user_input, sizeof(user_input), stdin);
    sscanf(user_input, "%2d/%2d/%4d", &userdata.day, &userdata.month, &userdata.year);
    printf("Enter your sex (M/F): ");
    fgets(user_input, sizeof(user_input), stdin);
    sscanf(user_input, "%c", &userdata.sex);
    printf("Enter your place of birth: ");
    fgets(userdata.city, sizeof(userdata.city), stdin);
    userdata.city[strcspn(userdata.city, "\n")] = 0;

    calculateCode(userdata, output);

    if (check(output) == 0) {
        readFlag(flag);
        printf("Code matched!\n");
        printf("Here is the flag: %s\n", flag);
    }
    else {
        printf("Code did not match. Your code is: %s\n", output);
    }

    return 0;
}