#include "coder.h"
#include "cities.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

const char *vowels = "AEIOUaeiou";

static const int tab_odd[256] = {
    ['0'] = 1,  ['1'] = 0,  ['2'] = 5,  ['3'] = 7,  ['4'] = 9,
    ['5'] = 13, ['6'] = 15, ['7'] = 17, ['8'] = 19, ['9'] = 21,
    ['A'] = 1,  ['B'] = 0,  ['C'] = 5,  ['D'] = 7,  ['E'] = 9,
    ['F'] = 13, ['G'] = 15, ['H'] = 17, ['I'] = 19, ['J'] = 21,
    ['K'] = 2,  ['L'] = 4,  ['M'] = 18, ['N'] = 20, ['O'] = 11,
    ['P'] = 3,  ['Q'] = 6,  ['R'] = 8,  ['S'] = 12, ['T'] = 14,
    ['U'] = 16, ['V'] = 10, ['W'] = 22, ['X'] = 25, ['Y'] = 24,
    ['Z'] = 23
};

static const int tab_even[256] = {
    ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,  ['4'] = 4,
    ['5'] = 5,  ['6'] = 6,  ['7'] = 7,  ['8'] = 8,  ['9'] = 9,
    ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,
    ['F'] = 5,  ['G'] = 6,  ['H'] = 7,  ['I'] = 8,  ['J'] = 9,
    ['K'] = 10, ['L'] = 11, ['M'] = 12, ['N'] = 13, ['O'] = 14,
    ['P'] = 15, ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19,
    ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23, ['Y'] = 24,
    ['Z'] = 25
};

char getCINCode(const char *cf15) {
    int sum = 0;
    for (int i = 0; i < 15; ++i) {
        char c = toupper((unsigned char)cf15[i]);
        if (i % 2 == 0) {
            sum += tab_odd[(unsigned char)c];
        } else {
            sum += tab_even[(unsigned char)c];
        }
    }
    int r = sum % 26;
    return 'A' + r;
}


void scanName(char *input, char *consonants, char *vowels_out)
{
    int c_idx = 0, v_idx = 0;
    for (int i = 0; i < strlen(input); i++)
    {
        if (isalpha(input[i])) {
            if (strchr(vowels, input[i]))
                vowels_out[v_idx++] = toupper(input[i]);
            else
                consonants[c_idx++] = toupper(input[i]);
        }
    }
    consonants[c_idx] = '\0';
    vowels_out[v_idx] = '\0';
}

char getMonthChar(int month)
{
    switch (month)
    {
    case 1:
        return 'A';
    case 2:
        return 'B';
    case 3:
        return 'C';
    case 4:
        return 'D';
    case 5:
        return 'E';
    case 6:
        return 'H';
    case 7:
        return 'L';
    case 8:
        return 'M';
    case 9:
        return 'P';
    case 10:
        return 'R';
    case 11:
        return 'S';
    case 12:
        return 'T';
    default:
        return ' ';
    }
}

void calculateCode(Data userdata, char *output)
{
    char nCons[100], nVowels[100];
    char sCons[100], sVowels[100];

    scanName(userdata.name, nCons, nVowels);
    scanName(userdata.surname, sCons, sVowels);

    int lCons = strlen(sCons), lVowels = strlen(sVowels);
    int out_idx = 0;
    for (int i = 0; i < 3; i++)
    {
        if (i < lCons)
            output[out_idx++] = sCons[i];
    }
    for (int i = 0; out_idx < 3 && i < lVowels; i++)
    {
        output[out_idx++] = sVowels[i];
    }
    while (out_idx < 3)
    {
        output[out_idx++] = 'X';
    }

    lCons = strlen(nCons);
    lVowels = strlen(nVowels);
    if (lCons > 3) {
        output[out_idx++] = nCons[0];
        output[out_idx++] = nCons[2];
        output[out_idx++] = nCons[3];
    } else {
        for (int i = 0; i < 3; i++)
        {
            if (i < lCons)
                output[out_idx++] = nCons[i];
        }
        for (int i = 0; out_idx < 6 && i < lVowels; i++)
        {
            output[out_idx++] = nVowels[i];
        }
        while (out_idx < 6)
        {
            output[out_idx++] = 'X';
        }
    }

    sprintf(output + 6, "%02d", userdata.year % 100);
    output[8] = getMonthChar(userdata.month);
    sprintf(output + 9, "%02d", userdata.day + (userdata.sex == 'F' ? 40 : 0));

    for (int i = 0; i < sizeof(cities) / sizeof(City); i++) {
        if (strcmp(cities[i].name, userdata.city) == 0) {
            strcpy(output + 11, cities[i].code);
            break;
        }
    }
    output[15] = getCINCode(output);
    output[16] = '\0';
}

void readFlag(char *output)
{
    FILE *file = fopen("flag", "r");
    if (file == NULL)
    {
        perror("Could not open flag file");
        exit(EXIT_FAILURE);
    }
    
    fgets(output, 50, file);
    output[strcspn(output, "\n")] = '\0';
    fclose(file);
}
