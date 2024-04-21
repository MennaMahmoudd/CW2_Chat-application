#include <iostream>
#include <thread>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

bool initialize() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    return true;
}

void InteractWithClient(int clientSocket, int* clients, int& clientCount, unsigned char *key, unsigned char *iv) {
    cout << "Client connected." << endl;

    unsigned char buffer[4096];

    while (true) {
        int bytesrecvd = recv(clientSocket, buffer, sizeof(buffer), 0);

        if (bytesrecvd <= 0) {
            cout << "Client disconnected." << endl;
            break;
        }

        int plaintext_len;
        unsigned char plaintext[4096];
        plaintext_len = decrypt(buffer, bytesrecvd, key, iv, plaintext);
        plaintext[plaintext_len] = '\0';

        cout << "Encrypted message from client: " << buffer << endl;
        cout << "Decrypted message from client: " << plaintext << endl;

        for (int i = 0; i < clientCount; ++i) {
            if (clients[i] != clientSocket) {
                int ciphertext_len;
                unsigned char ciphertext[4096];
                // Encrypt the received message before sending to other clients
                ciphertext_len = encrypt(plaintext, plaintext_len, key, iv, ciphertext);
                send(clients[i], ciphertext, ciphertext_len, 0);
            }
        }
    }

    for (int i = 0; i < clientCount; ++i) {
        if (clients[i] == clientSocket) {
            for (int j = i; j < clientCount - 1; ++j) {
                clients[j] = clients[j + 1];
            }
            clientCount--;
            break;
        }
    }

    close(clientSocket);
}

int main() {
    if (!initialize()) {
        cout << "Initialization failed." << endl;
        return 1;
    }

    cout << "Server program." << endl;

    int listenSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (listenSocket == -1) {
        cout << "Socket creation failed." << endl;
        return 1;
    }

    sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

    int port = 12345;
    int bindResult;
    do {
        serveraddr.sin_port = htons(port);
        bindResult = bind(listenSocket, reinterpret_cast<sockaddr*>(&serveraddr), sizeof(serveraddr));
        if (bindResult == -1) {
            cout << "Bind failed on port " << port << ", trying another port..." << endl;
            port++;
        }
    } while (bindResult == -1);

    if (listen(listenSocket, SOMAXCONN) == -1) {
        cout << "Listen failed." << endl;
        close(listenSocket);
        return 1;
    }

    cout << "Server has started listening on port: " << port << endl;

    const int MAX_CLIENTS = 100;
    int clients[MAX_CLIENTS];
    int clientCount = 0;

    // AES key and IV (Initialization Vector)
    unsigned char key[] = "01234567890123456789012345678901";
    unsigned char iv[] = "0123456789012345";

    while (true) {
        int clientSocket = accept(listenSocket, nullptr, nullptr);
        if (clientSocket == -1) {
            cout << "Invalid client socket." << endl;
            continue;
        }

        if (clientCount >= MAX_CLIENTS) {
            cout << "Maximum clients reached. Connection refused." << endl;
            close(clientSocket);
            continue;
        }

        clients[clientCount++] = clientSocket;
        thread t1(InteractWithClient, clientSocket, clients, ref(clientCount), key, iv);
        t1.detach();
    }

    close(listenSocket);

    return 0;
}
