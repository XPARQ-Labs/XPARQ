// SPDX-License-Identifier: Apache-2.0
//
// Test-only bridge for verifying a paqus-sqisign signed message with the
// official SQIsign NIST C API. This file is not linked into Paqus.

#include <api.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_exact(FILE *file, unsigned char *output, size_t length) {
  return fread(output, 1, length, file) == length ? 0 : -1;
}

static uint64_t decode_u64_le(const unsigned char input[8]) {
  uint64_t value = 0;
  for (unsigned int i = 0; i < 8; ++i) {
    value |= ((uint64_t)input[i]) << (8 * i);
  }
  return value;
}

int main(int argc, char **argv) {
  if (argc != 3 || (strcmp(argv[2], "valid") && strcmp(argv[2], "invalid"))) {
    fprintf(stderr, "usage: %s VECTOR.bin <valid|invalid>\n", argv[0]);
    return 64;
  }

  FILE *file = fopen(argv[1], "rb");
  if (!file) {
    perror("fopen");
    return 66;
  }

  unsigned char public_key[CRYPTO_PUBLICKEYBYTES];
  unsigned char length_bytes[8];
  if (read_exact(file, public_key, sizeof(public_key)) ||
      read_exact(file, length_bytes, sizeof(length_bytes))) {
    fprintf(stderr, "truncated vector header\n");
    fclose(file);
    return 65;
  }

  const uint64_t message_length = decode_u64_le(length_bytes);
  if (message_length > (1u << 20)) {
    fprintf(stderr, "message is too large\n");
    fclose(file);
    return 65;
  }

  const size_t signed_length = CRYPTO_BYTES + (size_t)message_length;
  unsigned char *signed_message = malloc(signed_length);
  unsigned char *recovered_message = malloc(message_length ? message_length : 1);
  if (!signed_message || !recovered_message ||
      read_exact(file, signed_message, signed_length) || fgetc(file) != EOF) {
    fprintf(stderr, "invalid vector body\n");
    free(signed_message);
    free(recovered_message);
    fclose(file);
    return 65;
  }
  fclose(file);

  unsigned long long recovered_length = 0;
  const int result =
      crypto_sign_open(recovered_message, &recovered_length, signed_message,
                       (unsigned long long)signed_length, public_key);
  const int accepted =
      result == 0 && recovered_length == message_length &&
      !memcmp(recovered_message, signed_message + CRYPTO_BYTES, message_length);
  const int expected = !strcmp(argv[2], "valid");

  free(signed_message);
  free(recovered_message);

  if (accepted != expected) {
    fprintf(stderr, "%s vector was %s by %s\n", CRYPTO_ALGNAME,
            accepted ? "accepted" : "rejected",
            expected ? "unexpectedly" : "as expected");
    return 1;
  }

  printf("%s: %s vector behaved as expected\n", CRYPTO_ALGNAME, argv[2]);
  return 0;
}
