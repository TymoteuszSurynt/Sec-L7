#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include<openssl/rsa.h>
#include <openssl/pem.h>
#include <fstream>
#include <sstream>
#include <iomanip>

using namespace std;

string sha256(const string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int) hash[i];
    }
    return ss.str();
}

int main(int argc, char *argv[]) {
    int server, portNum, bufferSize = 17000;
    string publicK, Nstring;
    ifstream privateKey;
    BIGNUM *N = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *rExp = BN_new();
    char buffer[bufferSize];
    char ip[] = "127.0.0.1";
    struct sockaddr_in server_addr;
    ofstream file;
    server = socket(AF_INET, SOCK_STREAM, 0);
    if (argc < 3) {
        cout << "Error: Something is missing" << endl;
        exit(1);
    } else {
        portNum = atoi(argv[1]);
    }
    if (server < 0) {
        cout << "Error: establishing socket" << endl;
        exit(1);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(portNum);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);
    if (connect(server, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        cout << "Error: No connection" << endl;
    } else {
        recv(server, buffer, bufferSize, 0);
        cout << buffer << endl;
        strcpy(buffer, argv[3]);

        privateKey.open("publicKey");
        if (privateKey.is_open()) {
            getline(privateKey, Nstring);
            getline(privateKey, publicK);
            privateKey.close();
        }
        BN_hex2bn(&N, Nstring.c_str());
        BN_hex2bn(&e, publicK.c_str());
        BN_rand_range(r, N);
        BN_hex2bn(&m, sha256(buffer).c_str());
        BN_mod_exp(rExp, r, e, N, BN_CTX_new());
        BN_mod_mul(x, m, rExp, N, BN_CTX_new());
        send(server, BN_bn2hex(x), bufferSize, 0);
        bzero(buffer, bufferSize);
        cout << "Server: ";
        recv(server, buffer, bufferSize, 0);
        cout << buffer << endl;
        file.open("lastMsg.txt");
        if (file.is_open()) {
            file << buffer << endl;
            strcpy(buffer, argv[3]);
            file << sha256(buffer) << endl;
            file << BN_bn2hex(r);
            file.close();
        }
    }
    BN_free(N);
    BN_free(e);
    BN_free(x);
    BN_free(r);
    close(server);
    return 0;
}