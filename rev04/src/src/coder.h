#ifndef CODER_H
#define CODER_H

typedef struct {
    char name[100], surname[100], city[100];
    int day, month, year;
    char sex;
} Data;

typedef struct {
    char name[50];
    char code[5];
} City;

void calculateCode(Data userdata, char *output);
void readFlag(char *output);
#endif
