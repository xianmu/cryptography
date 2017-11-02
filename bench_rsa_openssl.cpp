
#include <sys/time.h>
#include <errno.h>

#include <iostream>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#define ENCRYPTION_TIMES 1000

/// Time is measured using gettimeofday() in microseconds
double timestamp() {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) < 0) {
        std::cout << "getimeofday error:" << errno << "(" << strerror(errno) << ")" << std::endl;
        return 0.0;
    }
    return tv.tv_sec * 1e6 + tv.tv_usec;
}

bool GenerateRSAKeyPair(EVP_PKEY** pkey, int key_length) {
    EVP_PKEY_CTX* ctx = NULL;
    bool succ = false;
    if (NULL == (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))) {
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_length) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_keygen(ctx, pkey) <= 0) {
        goto cleanup;
    }
    succ = true;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return succ;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "usage: ./bench_rsa_openssl RSA_KEY_SIZE";
        return 1;
    }
    int key_size = atoi(argv[1]);
    std::cout << "key_size:" << key_size << std::endl;
    EVP_PKEY* pkey = NULL;
    unsigned char* out_buf = NULL;
    size_t out_len;
    EVP_PKEY_CTX* ctx = NULL;

    unsigned char* d_out_buf = NULL;
    size_t d_out_len;
    EVP_PKEY_CTX* d_ctx = NULL;

    std::string plain_text("plain-text");

    if (!GenerateRSAKeyPair(&pkey, key_size)) {
        std::cout << "error generating rsa key pair" << std::endl;
        goto cleanup;
    }

    // encryption
    if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) {
        goto cleanup;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        goto cleanup;
    }

    // determine buffer length
    const unsigned char* in_buf = reinterpret_cast<const unsigned char*>(plain_text.c_str());
    if (EVP_PKEY_encrypt(ctx, NULL, &out_len, in_buf, plain_text.length()) <= 0) {
        goto cleanup;
    }
    if (NULL == (out_buf = reinterpret_cast<unsigned char*>(OPENSSL_malloc(out_len)))) {
        goto cleanup;
    }
    double t_start = timestamp();
    for (int i = 0; i < ENCRYPTION_TIMES; ++i) {
        if (EVP_PKEY_encrypt(ctx, out_buf, &out_len, in_buf, plain_text.length()) <= 0) {
            goto cleanup;
        }
    }
    double t_end = timestamp();
    std::cout << "encryption time:" << (t_end - t_start) / ENCRYPTION_TIMES << std::endl;

    // decryption
    if (NULL == (d_ctx = EVP_PKEY_CTX_new(pkey, NULL))) {
        goto cleanup;
    }
    if (EVP_PKEY_decrypt_init(d_ctx) <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_decrypt(d_ctx, NULL, &d_out_len, out_buf, out_len) <= 0) {
        goto cleanup;
    }
    if (NULL == (d_out_buf = reinterpret_cast<unsigned char*>(OPENSSL_malloc(d_out_len)))) {
        goto cleanup;
    }
    t_start = timestamp();
    for (int i = 0; i < ENCRYPTION_TIMES; ++i) {
        d_out_len = key_size / 8;
        if (EVP_PKEY_decrypt(d_ctx, d_out_buf, &d_out_len, out_buf, out_len) <= 0) {
            goto cleanup;
        }
    }
    t_end = timestamp();
    std::cout << "decryption time:" << (t_end - t_start) / ENCRYPTION_TIMES << std::endl;
    std::cout << "plain-text: " << plain_text << std::endl;
    std::cout << "decipher-text: " << std::string(reinterpret_cast<const char*>(d_out_buf), d_out_len) << std::endl;

cleanup:
    OPENSSL_free(out_buf);
    OPENSSL_free(d_out_buf);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(d_ctx);

}
