#include "evp_aes.h"

int main (void) {
	srand (time(NULL));

	/* AES-256 CBC key size 256 bit */
    unsigned char key_256[] = {
    	0x07, 0x9c, 0x42, 0x42, 0x3b, 0x1f, 0x93, 0x8f, 0x6e, 0x5f, 0x73, 0x6d, 0x97, 0x2d, 0xb5, 0x0c,
    	0x53, 0xd2, 0x31, 0x80, 0xe6, 0xd5, 0x1a, 0x4b, 0xb4, 0xe0, 0xdd, 0xe2, 0x38, 0xc9, 0x0d, 0x6b
    };

    /* AES-256 CBC IV size 128 bit */
	int IV_LEN = 16;
	unsigned char random_iv[IV_LEN];
	for (auto i = 0; i < IV_LEN; i++)
		random_iv[i] = (unsigned char)(rand() & 0x00ff);

    /* Message to be encrypted */
    unsigned char *plaintext = (unsigned char *)"test1234";

    printf("Key: \n");
    for (auto i = 0; (unsigned)i < sizeof key_256; i++)
    	printf("%02x ", key_256[i]);
    printf("\n");

    printf("IV: \n");
    for (auto i = 0; (unsigned)i < sizeof random_iv; i++)
    	printf("%02x ", random_iv[i]);
    printf("\n");

    printf("Plaintext: \n%s\n", plaintext);

    int plaintext_length = strlen ((char *)plaintext);
    int decryptedtext_len, ciphertext_len;

    /* Buffer for ciphertext and decryptedtext*/
    unsigned char ciphertext[(plaintext_length+1)*8];
    unsigned char decryptedtext[(plaintext_length)*8];

    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, plaintext_length, key_256, random_iv, ciphertext);

    /*  Print ciphertext here */
    printf("Ciphertext:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key_256, random_iv, decryptedtext);

    /* Add a NULL terminator */
    decryptedtext[decryptedtext_len] = '\0';

    printf("Decrypted text (%zu bits):\n", sizeof decryptedtext);
    printf("%s\n", decryptedtext);

    return 0;
}
