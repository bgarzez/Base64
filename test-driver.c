#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "base64.h"

int main() {
    srand((unsigned int)time(NULL));

    // Test 1: Example from Wikipedia
    char text[] = "Many hands make light work.";
    char* encoded = b64encode((unsigned char*)text, strlen(text) + 1);
    printf("%s\n", encoded);
    char* decoded = (char*)b64decode(encoded);
    printf("%s\n", decoded);
    free(encoded);
    free(decoded);

    // Test 2: Random bytes
    unsigned char* bytes;
    size_t bytes_len = generate_bytes(&bytes);
    char* encoded_bytes = b64encode(bytes, bytes_len);
    printf("%s\n", encoded_bytes);
    unsigned char* decoded_bytes = b64decode(encoded_bytes);
    int equal = 1;
    for (size_t i = 0; i < bytes_len; ++i)
        equal = equal & (bytes[i] == decoded_bytes[i]);
    printf("%d\n", equal);
    free(decoded_bytes);
    free(encoded_bytes);
    free(bytes);

    // Test 3: Image file
    int status = EXIT_FAILURE;
    FILE* image = fopen("image.bmp", "rb");             /* Original image file */
    if (image == NULL) {
        perror("Error opening raw image file for reading");
        goto failOpenRaw;
    }
    FILE* enc_image_w = fopen("image.bmp.enc", "w");    /* Encoded image file (write) */
    if (enc_image_w == NULL) {
        perror("Error opening encoded image file for writing");
        goto failOpenEncW;
    }
    if (encode_file(image, enc_image_w) == 0)
        status = EXIT_SUCCESS;
    fclose(enc_image_w);
    /* Fall-through */
failOpenEncW:
    fclose(image);
    /* Fall-through */
failOpenRaw:
    if (status == EXIT_FAILURE)
        return status;
    
    FILE* enc_image_r = fopen("image.bmp.enc", "r");    /* Encoded image file (read) */
    if (enc_image_r == NULL) {
        perror("Error opening encoded image file for reading");
        goto failOpenEncR;
    }
    FILE* dec_image = fopen("image_dec.bmp", "wb");     /* Decoded image file */
    if (dec_image == NULL) {
        perror("Error opening decoded image file for writing");
        goto failOpenDec;
    }
    if (decode_file(enc_image_r, dec_image) == 0)
        status = EXIT_SUCCESS;
    fclose(dec_image);
    /* Fall-through */
failOpenDec:
    fclose(enc_image_r);
    /* Fall-through */
failOpenEncR:
    return status;
}