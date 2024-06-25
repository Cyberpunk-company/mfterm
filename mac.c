/**
 * Copyright (C) 2011 Anders Sundman <anders@4zm.org>
 *
 * This file is part of mfterm.
 *
 * mfterm is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * mfterm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with mfterm.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <openssl/des.h>
#include <openssl/evp.h>
#include <string.h>
#include "util.h"
#include "mac.h"
#include "tag.h"

// The DES MAC key in use
unsigned char current_mac_key[] = { 0, 0, 0, 0, 0, 0, 0, 0 };


/**
 * Compute a DES MAC, use DES in CBC mode. Key and output should be 8
 * bytes. The length specifies the length of the input in bytes. It
 * will be zero padded to 8 byte alignment if required.
 */

 int compute_mac(const unsigned char* input,
                 unsigned char* output,
                 const unsigned char* key,
                 long length) {
     // Context for encryption
     EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
     if (!ctx) return 1; // Error creating context

     // Initialize the encryption operation for DES CBC
     if (EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, (unsigned char*)"\0\0\0\0\0\0\0\0") != 1) {
         EVP_CIPHER_CTX_free(ctx);
         return 1; // Error initializing encryption
     }

     // Calculate the padded length
     int block_size = EVP_CIPHER_CTX_block_size(ctx);
     long padded_length = length + (block_size - (length % block_size));

     // Allocate memory for padded input
     unsigned char* padded_input = (unsigned char*)malloc((size_t)padded_length);
     if (!padded_input) {
         EVP_CIPHER_CTX_free(ctx);
         return 1; // Memory allocation failed
     }
     memcpy(padded_input, input, (size_t)length);

     // Properly handle padding calculation to avoid narrowing conversion
     int padding_needed = block_size - (int)(length % block_size);
     memset(padded_input + length, padding_needed, (size_t)padding_needed);

     // Encrypt the padded input
     int outlen;
     if (EVP_EncryptUpdate(ctx, output, &outlen, padded_input, (int)padded_length) != 1) {
         free(padded_input);
         EVP_CIPHER_CTX_free(ctx);
         return 1; // Error during encryption
     }

     // Finalize the encryption (additional output could be produced)
     int tmplen;
     if (EVP_EncryptFinal_ex(ctx, output + outlen, &tmplen) != 1) {
         free(padded_input);
         EVP_CIPHER_CTX_free(ctx);
         return 1; // Error finalizing encryption
     }
     outlen += tmplen;

     // Move up and truncate (we only want 8 bytes)
     for (int i = 0; i < 8; ++i)
         output[i] = output[outlen - 8 + i];
     for (int i = 8; i < length; ++i)
         output[i] = 0;

     free(padded_input);
     EVP_CIPHER_CTX_free(ctx);
     return 0;
 }



/**
 * Compute the MAC of a given block with the specified 8 byte
 * key. Return a 8 byte MAC value.
 *
 * The input to MAC algo [ 4 serial | 14 data | 6 0-pad ]
 *
 * If update is * nonzero, the mac of the current tag is updated. If
 * not, the MAC is simply printed.
 */
unsigned char* compute_block_mac(unsigned int block,
                                 const unsigned char* key,
                                 int update) {

  static unsigned char output[8];

  // Input to MAC algo [ 4 serial | 14 data | 6 0-pad ]
  unsigned char input[24];
  memcpy(&input, current_tag.amb[0].mbm.abtUID, 4);
  memcpy(&input[4], current_tag.amb[block].mbd.abtData, 14);
  memset(&input[18], 0, 6);

  int res = 0;
  res = compute_mac(input, output, key, 24);

  // Ret null on error
  if (res != 0) return NULL;

  // Should the new MAC be written back?
  if (update) {
    memcpy(&current_tag.amb[block].mbd.abtData[14], output, 2);
  }

  return output;
}
