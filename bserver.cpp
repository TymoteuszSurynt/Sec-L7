#include <iostream>
#include <openssl/pem.h>
#include <fstream>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctime>

using namespace std;

void getPassword(int passwordSize, int saltSize) {

    int option;
    ofstream config;
    string password, salt;
    unsigned char *out = static_cast<unsigned char *>(malloc(sizeof(char) * 100));
    cout << "1-Own password 2-Generated Password(default)" << endl;
    cin >> option;
    if (option == 1) {
        cout << "Enter password:" << endl;
        cin >> password;
    } else {
        srand(time(NULL));
        for (int i = 0; i < passwordSize; i++) {
            password += (char) (rand() % 105 + 21);
        }
        cout << "Your password:" << endl;
        cout << password << endl;
        cout << "Do not forget your password" << endl;

    }
    for (int i = 0; i < saltSize; ++i) {
        salt += (char) (rand() % 105 + 21);
    }
    config.open("config");
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), reinterpret_cast<const unsigned char *>(salt.c_str()),
                      salt.length(), 1000, EVP_sha512(), 100, out);
    config << out << endl << salt;
    config.close();
}

int keySize() {
    int option;
    cout << "Choose size: 1-2048(default) 2-4096 3-8192 4-16384" << endl;
    cin >> option;
    if (option == 2) {
        return 4096;
    } else if (option == 3) {
        return 8192;
    } else if (option == 4) {
        return 16384;
    } else {
        return 2048;
    }
}

void generateKey(int size) {
    BIGNUM *bn = BN_new();
    const BIGNUM *N = BN_new();
    const BIGNUM *d = BN_new();
    const BIGNUM *e = BN_new();
    RSA *key = RSA_new();
    ofstream file1, file2;
    if (BN_set_word(bn, RSA_F4) != 1) {
        cout << "Something went wrong!" << endl;
        exit(1);
    }
    clock_t start;
    start = clock();
    if (RSA_generate_key_ex(key, size, bn, nullptr) != 1) {
        cout << "Something went wrong!" << endl;
        exit(1);
    }
    cout << "Generating key: " << (clock() - start) / (double) CLOCKS_PER_SEC << endl;
    RSA_get0_key(key, &N, &e, &d);

    file1.open("publicKey");
    if (file1.is_open()) {
        file1 << BN_bn2hex(N) << endl << BN_bn2hex(e);
        file1.close();
    } else {
        cout << "File problem" << endl;
        exit(1);
    }
    file2.open("privateKey");
    if (file2.is_open()) {
        file2 << BN_bn2hex(N) << endl << BN_bn2hex(d);
        file2.close();
    } else {
        cout << "File problem" << endl;
        exit(1);
    }

    RSA_free(key);
    BN_free(bn);
}

bool verify(const unsigned char *a, string b, unsigned long sizeA, unsigned long sizeB) {
    if (sizeA != sizeB) {
        return false;
    }
    for (int i = 0; i < sizeA; i++) {
        if (a[i] != ((unsigned char) b[i])) {
            return false;
        }
    }
    return true;
}

int main(int argc, const char *argv[]) {
    int option, size, bufferSize = 17000;
    string nienawidzePisacWc = "1";
    cout << "Type: 1-Setup 2-Sign(default)" << endl;
    cin >> option;
    if (option == 1) {
        size = keySize();
        generateKey(size);
        getPassword(12, 4);

    } else {
        string password, salt, password2;
        ifstream config("config");

        if (config.is_open()) {
            unsigned char *out = static_cast<unsigned char *>(malloc(sizeof(char) * 100));
            getline(config, password);
            getline(config, salt);
            cout << "Enter password" << endl;
            cin >> password2;
            PKCS5_PBKDF2_HMAC(password2.c_str(), password2.length(),
                              reinterpret_cast<const unsigned char *>(salt.c_str()), salt.length(), 1000, EVP_sha512(),
                              100, out);
            if (verify(out, password, strlen((char *) out), password.length())) {
                string privateK,publicK, Nstring,dump;
                ifstream privateKey,publicKey;
                BIGNUM *N = BN_new();
                BIGNUM *d = BN_new();
                BIGNUM *e = BN_new();
                BIGNUM *x = BN_new();
                BIGNUM *r = BN_new();
                BIGNUM *gcd = BN_new();
                BIGNUM *resultToSend = BN_new();
                BIGNUM *rToE = BN_new();
                BIGNUM *rToEX = BN_new();
                BIGNUM *y = BN_new();
                BIGNUM *rInverse = BN_new();
                privateKey.open("privateKey");
                if (privateKey.is_open()) {
                    getline(privateKey, Nstring);
                    getline(privateKey, privateK);
                    privateKey.close();
                }
                publicKey.open("publicKey");
                if (publicKey.is_open()) {
                    getline(publicKey, dump);
                    getline(publicKey, publicK);
                    publicKey.close();
                }
                BN_hex2bn(&N, Nstring.c_str());
                BN_hex2bn(&d, privateK.c_str());
                BN_hex2bn(&e, publicK.c_str());

                char buffer[bufferSize];
                int server;
                int client[10];
                int clientNum = 0;
                int portNum;

                struct sockaddr_in server_addr;
                socklen_t size;
                if(argc<2){
                    cout <<"No port added, running on default 4000" << endl;
                    portNum = 4000;
                }else{
                    portNum=atoi(argv[1]);
                }
                server = socket(AF_INET, SOCK_STREAM, 0);
                if (server < 0) {
                    cout << "Error: socket" << endl;
                    exit(1);
                }
                server_addr.sin_family = AF_INET;
                server_addr.sin_addr.s_addr = htons(INADDR_ANY);
                server_addr.sin_port = htons(portNum);
                int yes = 1;
                if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
                    cout<<"Error: setsockopt"<<endl;
                    exit(1);
                }
                if ((bind(server, (struct sockaddr *) &server_addr, sizeof(server_addr))) < 0) {
                    cout<< "Error: bind" << endl;
                    exit(1);
                }
                size = sizeof(server_addr);
                listen(server, 1);
                while (clientNum < 10) {
                    client[clientNum] = accept(server, (struct sockaddr *) &server_addr, &size);
                    if (client < 0) {
                        cout << "Error: accept" << endl;
                    }
                    if (client > 0) {
                        strcpy(buffer, "Connected");
                        send(client[clientNum], buffer, bufferSize, 0);
                        recv(client[clientNum], buffer, bufferSize, 0);
                        clock_t start;
                        start = clock();
                        BN_hex2bn(&x, buffer);
                        BN_gcd(gcd, N, x, BN_CTX_new());
                        if (!nienawidzePisacWc.compare(BN_bn2dec(gcd))) {
                            do {
                                BN_rand_range(r, N);
                                BN_gcd(gcd,r, N, BN_CTX_new());
                            }while(nienawidzePisacWc.compare(BN_bn2dec(gcd)));
                            BN_mod_exp(rToE, r, e, N, BN_CTX_new());
                            BN_mul(rToEX, rToE, x, BN_CTX_new());
                            BN_mod_exp(y, rToEX, d, N, BN_CTX_new());
                            BN_mod_inverse(rInverse, r, N, BN_CTX_new());
                            BN_mod_mul(resultToSend, y, rInverse, N, BN_CTX_new());
                            strcpy(buffer, BN_bn2hex(resultToSend));
                        } else {
                            strcpy(buffer, "Wrong message");
                        }

                        if(argc>1){
                            double time=atof(argv[2]);
                            int pisanieServeraWc=0;
                            while((clock() - start) / (double) CLOCKS_PER_SEC<time){
                                pisanieServeraWc++;
                                pisanieServeraWc--;
                            }
                        }
                        cout << "Signing: " << (clock() - start) / (double) CLOCKS_PER_SEC << endl;
                        send(client[clientNum], buffer, bufferSize, 0);
                        close(client[clientNum]);
                    }
                }
                BN_free(N);
                BN_free(d);
                BN_free(x);
                BN_free(r);
                BN_free(resultToSend);
                BN_free(rToE);
                BN_free(rToEX);
                BN_free(y);
                BN_free(gcd);
                BN_free(rInverse);
                close(server);

            } else {
                cout << "Wrong password!" << endl;
            }
            config.close();
        }
    }
    return 0;
}