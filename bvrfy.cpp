#include <iostream>
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
    ifstream file, publicKey;
    string message, toTest, random, eS, NS;
    BIGNUM *x = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *N = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *minsOne = BN_new();
    BIGNUM *temp = BN_new();
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();
    if (argc < 3) {
        cout << "File destination missing" << endl;
        exit(1);
    }
    file.open(argv[1]);
    if (file.is_open()) {
        getline(file, toTest);
        getline(file, message);
        getline(file, random);
        file.close();
    } else {
        cout << "No last msg" << endl;
        exit(1);
    }
    publicKey.open(argv[2]);
    if (publicKey.is_open()) {
        getline(publicKey, NS);
        getline(publicKey, eS);
        file.close();
    } else {
        cout << "No key" << endl;
        exit(1);
    }
    clock_t start;
    start = clock();
    BN_hex2bn(&N, NS.c_str());
    BN_hex2bn(&e, eS.c_str());
    BN_hex2bn(&x, toTest.c_str());
    BN_hex2bn(&r, random.c_str());
    BN_mod_inverse(temp, r, N, BN_CTX_new());
    BN_mod_mul(temp1, x, temp, N, BN_CTX_new());
    BN_mod_exp(temp2, temp1, e, N, BN_CTX_new());
    BN_hex2bn(&m, message.c_str());
    if (BN_cmp(temp2, m) == 0) {
        cout << "OK" << endl;
    } else {
        cout << "Not OK" << endl;
    }
    cout << "Verifying key: " << (clock() - start) / (double) CLOCKS_PER_SEC << endl;
    BN_free(N);
    BN_free(e);
    BN_free(x);
    BN_free(r);
    BN_free(temp);
    BN_free(temp1);
    BN_free(temp2);

    return 0;
}
