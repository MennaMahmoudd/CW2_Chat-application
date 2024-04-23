#include <iostream>
#include <thread>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

using namespace std;

void InteractWithClient(int clientSocket, int* clients, int& clientCount) {
    cout << "Client connected." << endl;

    unsigned char buffer[4096];

    while (true) {
        int bytesrecvd = recv(clientSocket, buffer, sizeof(buffer), 0);

        if (bytesrecvd <= 0) {
            cout << "Client disconnected." << endl;
            break;
        }

        cout << "Message from client: " << buffer << endl;

        for (int i = 0; i < clientCount; ++i) {
            if (clients[i] != clientSocket) {
                send(clients[i], buffer, bytesrecvd, 0);
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
        thread t1(InteractWithClient, clientSocket, clients, ref(clientCount));
        t1.detach();
    }

    close(listenSocket);

    return 0;
}
