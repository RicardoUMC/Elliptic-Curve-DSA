#include "../ecop/EC.h"
#include <stdio.h>
#include <gmp.h>
#include <openssl/rand.h>

void configure_public_params(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G);
void generate_key_pair(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point G, char *filename);

int main(void) {
    mpz_t p, a, b, q;
    ec_point G;

    mpz_inits(p, a, b, q, G.x, G.y, NULL);

    configure_public_params(p, a, b, q, &G);

    char filename[] = "ecdsa_keypair.txt";
    generate_key_pair(p, a, b, q, G, filename);

    mpz_clears(p, a, b, q, G.x, G.y, NULL);

    return 0;
}

void configure_public_params(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G) {
    printf("Enter a prime number p: ");
    mpz_inp_str(p, stdin, 10);

    printf("Enter coefficient a for the elliptic curve: ");
    mpz_inp_str(a, stdin, 10);

    printf("Enter coefficient b for the elliptic curve: ");
    mpz_inp_str(b, stdin, 10);

    printf("Enter the order q of the generator point G: ");
    mpz_inp_str(q, stdin, 10);

    printf("Enter the generator point G coordinates (xG:yG:1):\n");
    printf("xG = ");
    mpz_inp_str(G->x, stdin, 10);
    printf("yG = ");
    mpz_inp_str(G->y, stdin, 10);
    G->z = 1;
}

void generate_key_pair(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point G, char *filename) {
    mpz_t d;
    ec_point B;

    mpz_inits(d, B.x, B.y, NULL);

    unsigned char buffer[32];
    RAND_bytes(buffer, sizeof(buffer));
    mpz_import(d, sizeof(buffer), 1, sizeof(buffer[0]), 0, 0, buffer);
    mpz_mod(d, d, q);

    B = point_multiplication(a, b, p, G, d);

    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    gmp_fprintf(file, "p = %Zd\n", p);
    gmp_fprintf(file, "a = %Zd\n", a);
    gmp_fprintf(file, "b = %Zd\n", b);
    gmp_fprintf(file, "q = %Zd\n", q);
    gmp_fprintf(file, "G = (%Zd:%Zd:%d)\n", G.x, G.y, G.z);
    gmp_fprintf(file, "B = (%Zd:%Zd:%d)\n", B.x, B.y, B.z);

    fclose(file);

    gmp_printf("Private key d: %Zd\n", d);
    gmp_printf("Public key B: (%Zd:%Zd:%d)\n", B.x, B.y, B.z);

    mpz_clears(d, B.x, B.y, NULL);
}

