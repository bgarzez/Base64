#include "base64.h"
#include <string.h>

char* b64encode(unsigned char* bytes, size_t len) {

    /* STEP 1: Allocate memory for encoded string */

    size_t enc_len = (len + 2) / 3 * 4;
    char* enc = (char*)malloc((enc_len + 1) * sizeof(char));
    if (enc == NULL) {
        puts("There was a problem allocated encoded string.");
        return NULL;
    }

    /* STEP 2: Encode bytes into b64 string */

    size_t n;
    unsigned int bits;
    int i;
    /* Encode 3-byte chunks of raw data at a time */
    for (n = 0; n < len; n += 3) {
        bits = 0;

        /* Copy the 24 bits from 3-byte chunk into a 4-byte integer variable (bit string) */
        for (i = 0; i < 3; ++i) {
            if (n + i == len) {
                bits <<= (3 - i) * 2;                           /* shift bit string left until bit string length is multiple of 6 */
                break;
            }
            bits = bits << 8 | bytes[n + i];                    /* push 8 bits form char into bit string */
        }

        /* Encode 6-bit chunks of the bit string into 2-4 ASCII characters & add to encoded string */
        /* If the raw data's length was not a multiple of 3 bytes, there will be fewer than 24 bits of data */
        for (; i >= 0; --i) {
            enc[n * 4 / 3 + i] = b64e[(char)(bits & 0b111111)]; /* get last 6 bits of bit string */
            bits >>= 6;                                         /* shift bit string 6 bits to the right */
        }
    }

    /* If raw data's length was not multiple of 3, add padding */
    /* (1 character of padding per byte "short"; will be 0-2 (incl.) padding chars) */
    n = 0;
    while ((len + n) % 3 != 0) {
        enc[enc_len - n - 1] = '=';
        ++n;
    }
    enc[enc_len] = '\0';    /* ensure encoded string ends in null terminator */
    return enc;
}

unsigned char* b64decode(char* enc) {

    /* STEP 1: Validate encoded string length (must be multiple of 4) */

    size_t enc_len = strlen(enc);
    if (enc_len % 4 != 0) {
        puts("Encoded string's length must be multiple of 4.");
        return NULL;
    }


    /* STEP 2: Allocate memory for decoded data */

    size_t dec_len = enc_len / 4 * 3;
    unsigned char* dec = (unsigned char*)malloc((dec_len) * sizeof(char));
    if (dec == NULL) {
        puts("There was a problem allocating decoded string.");
        return NULL;
    }

    /* STEP 3: Decode b64 string into bytes */

    size_t n;
    unsigned int bits;
    int i;
    char data;
    /* Decode 4 characters of string at a time */
    for (n = 0; n < enc_len; n += 4) {
        bits = 0;

        /* Copy the 24 bits from 4 [0,63] numbers into a 4-byte integer variable (bit string) */
        for (i = 0; i < 4; ++i) {
            if (enc[n + i] < '+' || enc[n + i] > 'z' || (data = b64d[enc[n + i] - '+']) == 64) {
                printf("Invalid b64 string at index %zu: \'%c\'.\n", n + i, enc[n + i]);
                free(dec);
                return NULL;
            }
            bits = bits << 6 | data;                        /* push 6 bits from data into bit string */
        }

        /* Copy 8-bit chunks of the bit string into allocated memory for raw bytes */
        for (i = 2; i >= 0; --i) {
            dec[n / 4 * 3 + i] = (char)(bits & 0b11111111); /* get last 8 bytes of bit string */
            bits >>= 8;                                     /* shift bit string 8 bits to the right */
        }
    }
    return dec;
}

size_t generate_bytes(unsigned char** dest_ptr) {
    /* Generate random size of byte array */
    size_t len = (size_t)(rand() % max_rand_size) + 1;

    /* Allocate memory for random bytes */
    *dest_ptr = (unsigned char*)malloc(len * sizeof(char));
    if (*dest_ptr == NULL) {
        puts("Error allocating memory for random bytes.");
        return 0;
    }

    /* Generate random data */
    for (size_t i = 0; i < len; ++i)
        (*dest_ptr)[i] = (unsigned char)rand() % 0x100;
    return len;
}

int encode_file(FILE* in_file, FILE* out_file) {
    unsigned char chunk[max_chunk_size];
    const size_t chunk_size = max_chunk_size / 12 * 12; /* chunk size must be multiple of 3 & 4 so no data is padded or truncated */
    char* encoded_chunk;
    size_t bytes_read, bytes_written;
    while ((bytes_read = fread(chunk, sizeof(char), chunk_size, in_file)) > 0) {
        encoded_chunk = b64encode(chunk, bytes_read);
        if (encoded_chunk == NULL) {
            puts("Error encoding chunk.");
            return 1;
        }
        bytes_written = fwrite(encoded_chunk, sizeof(char), (bytes_read + 2) / 3 * 4, out_file);
        free(encoded_chunk);
        if (bytes_written != (bytes_read + 2) / 3 * 4) {
            puts("Error writing to encoded file.");
            return 1;
        }
    }
    if (ferror(in_file)) {
        puts("Error reading file.");
        return 1;
    }
    if (feof(in_file)) {
        puts("Reached EOF.");
        return 0;
    }
    puts("Unexpected outcome of reading file.");
    return 1;
}

int decode_file(FILE* in_file, FILE* out_file) {
    char chunk[max_chunk_size + 1];
    const size_t chunk_size = max_chunk_size / 4 * 4;   /* chunk size must be multiple of 4 so decoding doesn't fail */
    unsigned char* decoded_chunk;
    size_t bytes_read, bytes_written;
    while ((bytes_read = fread(chunk, sizeof(char), chunk_size, in_file)) > 0) {
        chunk[bytes_read] = '\0';
        decoded_chunk = b64decode(chunk);
        if (decoded_chunk == NULL) {
            puts("Error decoding chunk.");
            return 1;
        }
        bytes_written = fwrite(decoded_chunk, sizeof(char), bytes_read / 4 * 3, out_file);
        free(decoded_chunk);
        if (bytes_written != bytes_read / 4 * 3) {
            puts("Error writing to decoded file.");
            return 1;
        }
    }
    if (ferror(in_file)) {
        puts("Error reading file.");
        return 1;
    }
    if (feof(in_file)) {
        puts("Reached EOF.");
        return 0;
    }
    puts("Unexpected outcome of reading file.");
    return 1;
}
