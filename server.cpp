#include <iostream> // Including the iostream library for input/output operations.
#include <thread> // Including the thread library for concurrent execution.
#include <cstring> // Including the cstring library for string manipulation.
#include <arpa/inet.h> // Including arpa/inet.h for Internet operations.
#include <sys/socket.h> // Including sys/socket.h for socket operations.
#include <netinet/in.h> // Including netinet/in.h for Internet address operations.
#include <unistd.h> // Including unistd.h for POSIX API access.

using namespace std; // Using the standard namespace.

void InteractWithClient(int clientSocket, int* clients, int& clientCount) { // Defining a function to interact with clients.
    cout << "Client connected." << endl; // Printing a message when a client connects.

    unsigned char buffer[4096]; // Buffer for incoming data.

    while (true) { // Continuously listen for messages from the client.
        int bytesrecvd = recv(clientSocket, buffer, sizeof(buffer), 0); // Receiving data from client.

        if (bytesrecvd <= 0) { // If no bytes received, client disconnected.
            cout << "Client disconnected." << endl;
            break;
        }

        cout << "Message from client: " << buffer << endl; // Printing the received message.

        for (int i = 0; i < clientCount; ++i) { // Sending the received message to other clients.
            if (clients[i] != clientSocket) {
                send(clients[i], buffer, bytesrecvd, 0);
            }
        }
    }

    // Removing client from the list and closing the connection.
    for (int i = 0; i < clientCount; ++i) {
        if (clients[i] == clientSocket) {
            for (int j = i; j < clientCount - 1; ++j) {
                clients[j] = clients[j + 1];
            }
            clientCount--;
            break;
        }
    }

    close(clientSocket); // Closing client socket.
}

int main() { // Main function.
    cout << "Server program." << endl; // Printing server program initialization message.

    int listenSocket = socket(AF_INET, SOCK_STREAM, 0); // Creating a socket for listening to client connections.

    if (listenSocket == -1) { // Checking if socket creation failed.
        cout << "Socket creation failed." << endl;
        return 1;
    }

    sockaddr_in serveraddr; // Server address structure.
    serveraddr.sin_family = AF_INET; // Using IPv4.
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY); // Binding to any available local address.

    int port = 12345; // Port to listen on.
    int bindResult;
    do { // Binding the socket to the port.
        serveraddr.sin_port = htons(port); // Setting port.
        bindResult = bind(listenSocket, reinterpret_cast<sockaddr*>(&serveraddr), sizeof(serveraddr)); // Binding socket to address.
        if (bindResult == -1) { // If binding failed, try another port.
            cout << "Bind failed on port " << port << ", trying another port..." << endl;
            port++;
        }
    } while (bindResult == -1);

    if (listen(listenSocket, SOMAXCONN) == -1) { // Listening for incoming connections.
        cout << "Listen failed." << endl;
        close(listenSocket);
        return 1;
    }

    cout << "Server has started listening on port: " << port << endl; // Server started listening.

    const int MAX_CLIENTS = 100; // Maximum number of clients.
    int clients[MAX_CLIENTS]; // Array to store client sockets.
    int clientCount = 0; // Counter for connected clients.

    while (true) { // Continuously accept incoming connections.
        int clientSocket = accept(listenSocket, nullptr, nullptr); // Accepting client connection.
        if (clientSocket == -1) { // If invalid client socket, continue.
            cout << "Invalid client socket." << endl;
            continue;
        }

        if (clientCount >= MAX_CLIENTS) { // If maximum clients reached, refuse connection.
            cout << "Maximum clients reached. Connection refused." << endl;
            close(clientSocket);
            continue;
        }

        clients[clientCount++] = clientSocket; // Add client to the list.
        thread t1(InteractWithClient, clientSocket, clients, ref(clientCount)); // Start a thread to interact with the client.
        t1.detach(); // Detach the thread to run independently.
    }

    close(listenSocket); // Close the listening socket.

    return 0; // Exit the program.
}
