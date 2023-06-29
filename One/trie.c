#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "difinition.h"


Node* createNode() {
    Node* newNode = (Node*)malloc(sizeof(Node));

    newNode->count = -1;
    for(int i = 0; i<ALPHABET_SIZE; i++){
        newNode->children[i] = NULL;
    }
    return newNode;
}

void insert(Node* root, const char* key, int count) {
    int length = strlen(key);
    Node* currentNode = root;
    for (int i = 0; i < length; i++) {
        int index;
        char ch = key[i];
        if (ch >= 'a' && ch <= 'z') {
            index = ch - 'a';
        }
        else if(ch>= '0' && ch <= '9'){
            index = ch - 22;
        }
        else if (ch == '.') {
            index = 36;
        }
        else if (ch == '-') {
            index = 37;
        }
        else {
            continue;
        }
        if (NULL == currentNode->children[index]) {
            currentNode->children[index] = createNode();
        }
        currentNode = currentNode->children[index];
    }
    currentNode->count = count;
}

int search(Node* root, const char* key) {
    int length = strlen(key);
    Node* currentNode = root;
    for (int i = 0; i < length; i++) {
        int index;
        char ch = key[i];
        if (ch >= 'a' && ch <= 'z') {
            index = ch - 'a';
        }
        else if(ch>= '0' && ch <= '9'){
            index = ch - 22;
        }
        else if (ch == '.') {
            index = 36;
        }
        else if (ch == '-') {
            index = 37;
        }
        else {
            continue;
        }

        if (currentNode->children[index] == NULL) {
            return -1;
        }
        currentNode = currentNode->children[index];
    }
    return currentNode->count;
}

void destroyTrie(Node* root) {
    if (root) {
        for (int i = 0; i < ALPHABET_SIZE; i++) {
            destroyTrie(root->children[i]);
        }
        free(root);
    }
}
