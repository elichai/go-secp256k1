/**********************************************************************
 * Copyright (c) 2017 Tomas van der Wansem                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MULTISET_TESTS_
#define _SECP256K1_MODULE_MULTISET_TESTS_


#include "include/secp256k1.h"
#include "include/secp256k1_multiset.h"
#include "util.h"
#include "testrand.h"

#define DATALEN   64*3
#define DATACOUNT 100


#define CHECK_EQUAL(a,b) { \
    unsigned char hash1[32]; \
    unsigned char hash2[32]; \
    secp256k1_multiset_finalize(ctx, hash1, (a)); \
    secp256k1_multiset_finalize(ctx, hash2, (b)); \
    CHECK(memcmp(hash1,hash2,sizeof(hash1))==0); \
}

#define CHECK_NOTEQUAL(a,b) { \
    unsigned char hash1[32]; \
    unsigned char hash2[32]; \
    secp256k1_multiset_finalize(ctx, hash1, (a)); \
    secp256k1_multiset_finalize(ctx, hash2, (b)); \
    CHECK(memcmp(hash1,hash2,sizeof(hash1))!=0); \
}

static unsigned char data[DATACOUNT][DATALEN];

/* create random data */
static void initdata(void) {
    secp256k1_rand_bytes_test((unsigned char*)data, DATACOUNT*DATALEN);

}

void test_parse_multiset(void) {
#define SECP256K1_EC_PARSE_TEST_NVALID (12)
  const unsigned char valid[SECP256K1_EC_PARSE_TEST_NVALID][64] = {
      {
          /* Point with leading and trailing zeros in x and y serialization. */
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x52,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x64, 0xef, 0xa1, 0x7b, 0x77, 0x61, 0xe1, 0xe4, 0x27, 0x06, 0x98, 0x9f, 0xb4, 0x83,
          0xb8, 0xd2, 0xd4, 0x9b, 0xf7, 0x8f, 0xae, 0x98, 0x03, 0xf0, 0x99, 0xb8, 0x34, 0xed, 0xeb, 0x00
      },
      {
          /* Point with x equal to a 3rd root of unity.*/
          0x7a, 0xe9, 0x6a, 0x2b, 0x64, 0x7c, 0x07, 0x10, 0x6e, 0x64, 0x47, 0x9e, 0xac, 0x34, 0x34, 0xe9,
          0x9c, 0xf0, 0x49, 0x75, 0x12, 0xf5, 0x89, 0x95, 0xc1, 0x39, 0x6c, 0x28, 0x71, 0x95, 0x01, 0xee,
          0x42, 0x18, 0xf2, 0x0a, 0xe6, 0xc6, 0x46, 0xb3, 0x63, 0xdb, 0x68, 0x60, 0x58, 0x22, 0xfb, 0x14,
          0x26, 0x4c, 0xa8, 0xd2, 0x58, 0x7f, 0xdd, 0x6f, 0xbc, 0x75, 0x0d, 0x58, 0x7e, 0x76, 0xa7, 0xee,
      },
      {
          /* Point with largest x. (1/2) */
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2c,
          0x0e, 0x99, 0x4b, 0x14, 0xea, 0x72, 0xf8, 0xc3, 0xeb, 0x95, 0xc7, 0x1e, 0xf6, 0x92, 0x57, 0x5e,
          0x77, 0x50, 0x58, 0x33, 0x2d, 0x7e, 0x52, 0xd0, 0x99, 0x5c, 0xf8, 0x03, 0x88, 0x71, 0xb6, 0x7d,
      },
      {
          /* Point with largest x. (2/2) */
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2c,
          0xf1, 0x66, 0xb4, 0xeb, 0x15, 0x8d, 0x07, 0x3c, 0x14, 0x6a, 0x38, 0xe1, 0x09, 0x6d, 0xa8, 0xa1,
          0x88, 0xaf, 0xa7, 0xcc, 0xd2, 0x81, 0xad, 0x2f, 0x66, 0xa3, 0x07, 0xfb, 0x77, 0x8e, 0x45, 0xb2,
      },
      {
          /* Point with smallest x. (1/2) */
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
          0x42, 0x18, 0xf2, 0x0a, 0xe6, 0xc6, 0x46, 0xb3, 0x63, 0xdb, 0x68, 0x60, 0x58, 0x22, 0xfb, 0x14,
          0x26, 0x4c, 0xa8, 0xd2, 0x58, 0x7f, 0xdd, 0x6f, 0xbc, 0x75, 0x0d, 0x58, 0x7e, 0x76, 0xa7, 0xee,
      },
      {
          /* Point with smallest x. (2/2) */
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
          0xbd, 0xe7, 0x0d, 0xf5, 0x19, 0x39, 0xb9, 0x4c, 0x9c, 0x24, 0x97, 0x9f, 0xa7, 0xdd, 0x04, 0xeb,
          0xd9, 0xb3, 0x57, 0x2d, 0xa7, 0x80, 0x22, 0x90, 0x43, 0x8a, 0xf2, 0xa6, 0x81, 0x89, 0x54, 0x41,
      },
      {
          /* Point with largest y. (1/3) */
          0x1f, 0xe1, 0xe5, 0xef, 0x3f, 0xce, 0xb5, 0xc1, 0x35, 0xab, 0x77, 0x41, 0x33, 0x3c, 0xe5, 0xa6,
          0xe8, 0x0d, 0x68, 0x16, 0x76, 0x53, 0xf6, 0xb2, 0xb2, 0x4b, 0xcb, 0xcf, 0xaa, 0xaf, 0xf5, 0x07,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
      },
      {
          /* Point with largest y. (2/3) */
          0xcb, 0xb0, 0xde, 0xab, 0x12, 0x57, 0x54, 0xf1, 0xfd, 0xb2, 0x03, 0x8b, 0x04, 0x34, 0xed, 0x9c,
          0xb3, 0xfb, 0x53, 0xab, 0x73, 0x53, 0x91, 0x12, 0x99, 0x94, 0xa5, 0x35, 0xd9, 0x25, 0xf6, 0x73,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
      },
      {
          /* Point with largest y. (3/3) */
          0x14, 0x6d, 0x3b, 0x64, 0xad, 0xd9, 0xf5, 0x4c, 0xcc, 0xa2, 0x85, 0x33, 0xc8, 0x8e, 0x2c, 0xbc,
          0x63, 0xf7, 0x44, 0x3e, 0x16, 0x58, 0x78, 0x3a, 0xb4, 0x1f, 0x8e, 0xf9, 0x7c, 0x2a, 0x10, 0xb5,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
      },
      {
          /* Point with smallest y. (1/3) */
          0x1f, 0xe1, 0xe5, 0xef, 0x3f, 0xce, 0xb5, 0xc1, 0x35, 0xab, 0x77, 0x41, 0x33, 0x3c, 0xe5, 0xa6,
          0xe8, 0x0d, 0x68, 0x16, 0x76, 0x53, 0xf6, 0xb2, 0xb2, 0x4b, 0xcb, 0xcf, 0xaa, 0xaf, 0xf5, 0x07,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      },
      {
          /* Point with smallest y. (2/3) */
          0xcb, 0xb0, 0xde, 0xab, 0x12, 0x57, 0x54, 0xf1, 0xfd, 0xb2, 0x03, 0x8b, 0x04, 0x34, 0xed, 0x9c,
          0xb3, 0xfb, 0x53, 0xab, 0x73, 0x53, 0x91, 0x12, 0x99, 0x94, 0xa5, 0x35, 0xd9, 0x25, 0xf6, 0x73,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      },
      {
          /* Point with smallest y. (3/3) */
          0x14, 0x6d, 0x3b, 0x64, 0xad, 0xd9, 0xf5, 0x4c, 0xcc, 0xa2, 0x85, 0x33, 0xc8, 0x8e, 0x2c, 0xbc,
          0x63, 0xf7, 0x44, 0x3e, 0x16, 0x58, 0x78, 0x3a, 0xb4, 0x1f, 0x8e, 0xf9, 0x7c, 0x2a, 0x10, 0xb5,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
      }
  };
#define SECP256K1_EC_PARSE_TEST_NXVALID (4)
  const unsigned char onlyxvalid[SECP256K1_EC_PARSE_TEST_NXVALID][64] = {
      {
          /* Valid if y overflow ignored (y = 1 mod p). (1/3) */
          0x1f, 0xe1, 0xe5, 0xef, 0x3f, 0xce, 0xb5, 0xc1, 0x35, 0xab, 0x77, 0x41, 0x33, 0x3c, 0xe5, 0xa6,
          0xe8, 0x0d, 0x68, 0x16, 0x76, 0x53, 0xf6, 0xb2, 0xb2, 0x4b, 0xcb, 0xcf, 0xaa, 0xaf, 0xf5, 0x07,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
      },
      {
          /* Valid if y overflow ignored (y = 1 mod p). (2/3) */
          0xcb, 0xb0, 0xde, 0xab, 0x12, 0x57, 0x54, 0xf1, 0xfd, 0xb2, 0x03, 0x8b, 0x04, 0x34, 0xed, 0x9c,
          0xb3, 0xfb, 0x53, 0xab, 0x73, 0x53, 0x91, 0x12, 0x99, 0x94, 0xa5, 0x35, 0xd9, 0x25, 0xf6, 0x73,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
      },
      {
          /* Valid if y overflow ignored (y = 1 mod p). (3/3)*/
          0x14, 0x6d, 0x3b, 0x64, 0xad, 0xd9, 0xf5, 0x4c, 0xcc, 0xa2, 0x85, 0x33, 0xc8, 0x8e, 0x2c, 0xbc,
          0x63, 0xf7, 0x44, 0x3e, 0x16, 0x58, 0x78, 0x3a, 0xb4, 0x1f, 0x8e, 0xf9, 0x7c, 0x2a, 0x10, 0xb5,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
      },
      {
          /* x on curve, y is from y^2 = x^3 + 8. */
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
      }
  };
#define SECP256K1_EC_PARSE_TEST_NINVALID (7)
  const unsigned char invalid[SECP256K1_EC_PARSE_TEST_NINVALID][64] = {
      {
          /* x is third root of -8, y is -1 * (x^3+7); also on the curve for y^2 = x^3 + 9. */
          0x0a, 0x2d, 0x2b, 0xa9, 0x35, 0x07, 0xf1, 0xdf, 0x23, 0x37, 0x70, 0xc2, 0xa7, 0x97, 0x96, 0x2c,
          0xc6, 0x1f, 0x6d, 0x15, 0xda, 0x14, 0xec, 0xd4, 0x7d, 0x8d, 0x27, 0xae, 0x1c, 0xd5, 0xf8, 0x53,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      },
      {
          /* Valid if x overflow ignored (x = 1 mod p). */
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
          0x42, 0x18, 0xf2, 0x0a, 0xe6, 0xc6, 0x46, 0xb3, 0x63, 0xdb, 0x68, 0x60, 0x58, 0x22, 0xfb, 0x14,
          0x26, 0x4c, 0xa8, 0xd2, 0x58, 0x7f, 0xdd, 0x6f, 0xbc, 0x75, 0x0d, 0x58, 0x7e, 0x76, 0xa7, 0xee,
      },
      {
          /* Valid if x overflow ignored (x = 1 mod p). */
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
          0xbd, 0xe7, 0x0d, 0xf5, 0x19, 0x39, 0xb9, 0x4c, 0x9c, 0x24, 0x97, 0x9f, 0xa7, 0xdd, 0x04, 0xeb,
          0xd9, 0xb3, 0x57, 0x2d, 0xa7, 0x80, 0x22, 0x90, 0x43, 0x8a, 0xf2, 0xa6, 0x81, 0x89, 0x54, 0x41,
      },
      {
          /* x is -1, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 5. */
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
          0xf4, 0x84, 0x14, 0x5c, 0xb0, 0x14, 0x9b, 0x82, 0x5d, 0xff, 0x41, 0x2f, 0xa0, 0x52, 0xa8, 0x3f,
          0xcb, 0x72, 0xdb, 0x61, 0xd5, 0x6f, 0x37, 0x70, 0xce, 0x06, 0x6b, 0x73, 0x49, 0xa2, 0xaa, 0x28,
      },
      {
          /* x is -1, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 5. */
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
          0x0b, 0x7b, 0xeb, 0xa3, 0x4f, 0xeb, 0x64, 0x7d, 0xa2, 0x00, 0xbe, 0xd0, 0x5f, 0xad, 0x57, 0xc0,
          0x34, 0x8d, 0x24, 0x9e, 0x2a, 0x90, 0xc8, 0x8f, 0x31, 0xf9, 0x94, 0x8b, 0xb6, 0x5d, 0x52, 0x07,
      },
      {
          /* x is zero, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 7. */
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x8f, 0x53, 0x7e, 0xef, 0xdf, 0xc1, 0x60, 0x6a, 0x07, 0x27, 0xcd, 0x69, 0xb4, 0xa7, 0x33, 0x3d,
          0x38, 0xed, 0x44, 0xe3, 0x93, 0x2a, 0x71, 0x79, 0xee, 0xcb, 0x4b, 0x6f, 0xba, 0x93, 0x60, 0xdc,
      },
      {
          /* x is zero, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 7. */
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x70, 0xac, 0x81, 0x10, 0x20, 0x3e, 0x9f, 0x95, 0xf8, 0xd8, 0x32, 0x96, 0x4b, 0x58, 0xcc, 0xc2,
          0xc7, 0x12, 0xbb, 0x1c, 0x6c, 0xd5, 0x8e, 0x86, 0x11, 0x34, 0xb4, 0x8f, 0x45, 0x6c, 0x9b, 0x53
      }
  };
  const unsigned char pubkeyc[66] = {
      /* Serialization of G. */
      0x04, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
      0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
      0x98, 0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x64, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08,
      0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4,
      0xB8, 0x00
  };
  unsigned char sout[64];
  secp256k1_ge ge;
  secp256k1_gej gej;
  secp256k1_multiset multiset;
  size_t i;
  int32_t ecount;
  int32_t ecount2;
  ecount = 0;
  /* Nothing should be reading this far into pubkeyc. */
  secp256k1_context_set_illegal_callback(ctx, counting_illegal_callback_fn, &ecount);
  memset(&multiset, 0xfe, sizeof(multiset));
  ecount = 0;
  VG_UNDEF(&multiset, sizeof(multiset));
  CHECK(ecount == 0);
  /* NULL multiset, illegal arg error. Pubkey isn't rewritten before this step, since it's NULL into the parser. */
  CHECK(secp256k1_multiset_parse(ctx, NULL, pubkeyc) == 0);
  CHECK(ecount == 1);
  /* NULL input string. Illegal arg and zeroize output. */
  memset(&multiset, 0xfe, sizeof(multiset));
  ecount = 0;
  VG_UNDEF(&multiset, sizeof(multiset));
  CHECK(secp256k1_multiset_parse(ctx, &multiset, NULL) == 0);
  VG_CHECK(&multiset, sizeof(multiset));
  CHECK(ecount == 1);
  /* 64 bytes claimed on input starting with 0x04, fail, zeroize output, no illegal arg error. */
  memset(&multiset, 0xfe, sizeof(multiset));
  ecount = 0;
  VG_UNDEF(&multiset, sizeof(multiset));
  CHECK(secp256k1_multiset_parse(ctx, &multiset, pubkeyc) == 0);
  VG_CHECK(&multiset, sizeof(multiset));
  CHECK(ecount == 0);
  /* Valid parse. */
  memset(&multiset, 0, sizeof(multiset));
  ecount = 0;
  VG_UNDEF(&multiset, sizeof(multiset));
  CHECK(secp256k1_multiset_parse(ctx, &multiset, &pubkeyc[1]) == 1);
  CHECK(secp256k1_multiset_parse(secp256k1_context_no_precomp, &multiset, &pubkeyc[1]) == 1);
  VG_CHECK(&multiset, sizeof(multiset));
  CHECK(ecount == 0);
  VG_UNDEF(&ge, sizeof(ge));
  gej_from_multiset_var(&gej, &multiset);
  secp256k1_ge_set_gej_var(&ge, &gej);
  VG_CHECK(&ge.x, sizeof(ge.x));
  VG_CHECK(&ge.y, sizeof(ge.y));
  VG_CHECK(&ge.infinity, sizeof(ge.infinity));
  ge_equals_ge(&secp256k1_ge_const_g, &ge);
  CHECK(ecount == 0);
  /* secp256k1_multiset_serialize illegal args. */
  ecount = 0;
  CHECK(secp256k1_multiset_serialize(ctx, NULL, &multiset) == 0);
  CHECK(ecount == 1);
  VG_UNDEF(sout, 64);
  CHECK(secp256k1_multiset_serialize(ctx, sout, NULL) == 0);
  VG_CHECK(sout, 64);
  CHECK(ecount == 2);
  VG_UNDEF(sout, 64);
  CHECK(secp256k1_multiset_serialize(ctx, sout, &multiset) == 1);
  VG_CHECK(sout, 64);
  CHECK(ecount == 3);
  /* Multiple illegal args. Should still set arg error only once. */
  ecount = 0;
  ecount2 = 11;
  CHECK(secp256k1_multiset_parse(ctx, NULL, NULL) == 0);
  CHECK(ecount == 1);
  /* Does the illegal arg callback actually change the behavior? */
  secp256k1_context_set_illegal_callback(ctx, uncounting_illegal_callback_fn, &ecount2);
  CHECK(secp256k1_multiset_parse(ctx, NULL, NULL) == 0);
  CHECK(ecount == 1);
  CHECK(ecount2 == 10);
  secp256k1_context_set_illegal_callback(ctx, NULL, NULL);
  /* Try a bunch of prefabbed points with all possible encodings. */
  for (i = 0; i < SECP256K1_EC_PARSE_TEST_NVALID; i++) {
    VG_UNDEF(&multiset, sizeof(multiset));
    CHECK(secp256k1_multiset_parse(ctx, &multiset, valid[i]) == 1);
    VG_CHECK(&multiset, sizeof(multiset));
  }
  for (i = 0; i < SECP256K1_EC_PARSE_TEST_NXVALID; i++) {
    VG_UNDEF(&multiset, sizeof(multiset));
    CHECK(secp256k1_multiset_parse(ctx, &multiset, onlyxvalid[i]) == 0);
    VG_CHECK(&multiset, sizeof(multiset));
    ecount = 0;
    for (i = 0; i < sizeof(multiset); ++i) {
      ecount |= multiset.d[i];
    }
    CHECK(ecount == 0);
  }
  for (i = 0; i < SECP256K1_EC_PARSE_TEST_NINVALID; i++) {
    VG_UNDEF(&multiset, sizeof(multiset));
    CHECK(secp256k1_multiset_parse(ctx, &multiset, invalid[i]) == 0);
    VG_CHECK(&multiset, sizeof(multiset));
    ecount = 0;
    for (i = 0; i < sizeof(multiset); ++i) {
      ecount |= multiset.d[i];
    }
    CHECK(ecount == 0);
  }
}

void test_infinity(void) {
  secp256k1_multiset multiset1, multiset2;
  unsigned char out[64];
  int i;
  secp256k1_multiset_init(ctx, &multiset1);
  secp256k1_multiset_serialize(ctx, out, &multiset1);
  for (i = 0; i < 64; ++i) {
      CHECK(out[i] == 0);
  }
  secp256k1_multiset_parse(ctx, &multiset2, out);
  CHECK(memcmp(&multiset1, &multiset2, sizeof(multiset1)) == 0);

}

void test_unordered(void) {

    secp256k1_multiset empty, r1,r2,r3;

    secp256k1_multiset_init(ctx, &empty);
    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    secp256k1_multiset_add(ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[1], DATALEN);



    CHECK_NOTEQUAL(&r1,&r2);
    secp256k1_multiset_add(ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[0], DATALEN);
    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    CHECK_EQUAL(&r1,&r2);


    secp256k1_multiset_add(ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r1, data[2], DATALEN);

    secp256k1_multiset_add(ctx, &r2, data[2], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[1], DATALEN);

    secp256k1_multiset_add(ctx, &r3, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[2], DATALEN);


    CHECK_EQUAL(&r1,&r2);
    CHECK_EQUAL(&r1,&r3);

    secp256k1_multiset_combine(ctx, &r3, &empty);
    CHECK_EQUAL(&r1,&r3);
    secp256k1_multiset_combine(ctx, &r3, &r2);
    CHECK_NOTEQUAL(&r1,&r3);

}

void test_combine(void) {

    secp256k1_multiset empty, r1,r2,r3;

    secp256k1_multiset_init(ctx, &empty);
    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    secp256k1_multiset_add(ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[1], DATALEN);



    CHECK_NOTEQUAL(&r1,&r2);
    secp256k1_multiset_add(ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[0], DATALEN);
    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    CHECK_EQUAL(&r1,&r2);


    secp256k1_multiset_add(ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r1, data[2], DATALEN);

    secp256k1_multiset_add(ctx, &r2, data[2], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[1], DATALEN);
    secp256k1_multiset_combine(ctx, &r2, &r3);
    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);
    secp256k1_multiset_add(ctx, &r2, data[2], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[1], DATALEN);
    secp256k1_multiset_combine(ctx, &r2, &r3);
    CHECK_EQUAL(&r1,&r2);


    secp256k1_multiset_combine(ctx, &r2, &empty);
    CHECK_EQUAL(&r1,&r2);
    secp256k1_multiset_combine(ctx, &r2, &r1);
    CHECK_NOTEQUAL(&r1,&r2);

}


void test_remove(void) {

    secp256k1_multiset empty, r1,r2,r3;

    secp256k1_multiset_init(ctx, &empty);
    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_add   (ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add   (ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add   (ctx, &r1, data[3], DATALEN);
    secp256k1_multiset_add   (ctx, &r1, data[9], DATALEN);
    secp256k1_multiset_add   (ctx, &r1, data[8], DATALEN);

    secp256k1_multiset_add   (ctx, &r2, data[1], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[9], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[11], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[10], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[0], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[10], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[3], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[8], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[11], DATALEN);

    secp256k1_multiset_add   (ctx, &r3, data[9], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[15], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[15], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[1], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[9], DATALEN);
    secp256k1_multiset_remove(ctx, &r3, data[15], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[0], DATALEN);
    secp256k1_multiset_remove(ctx, &r3, data[15], DATALEN);
    secp256k1_multiset_remove(ctx, &r3, data[9], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[3], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[8], DATALEN);

    CHECK_EQUAL(&r1,&r2);
    CHECK_EQUAL(&r1,&r3);
    CHECK_NOTEQUAL(&r1,&empty);

    secp256k1_multiset_remove(ctx, &r3, data[8], DATALEN);
    CHECK_NOTEQUAL(&r1,&r3);

    secp256k1_multiset_remove(ctx, &r2, data[0], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[9], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[8], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[1], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[3], DATALEN);

    CHECK_EQUAL(&r2,&empty);


}


void test_empty(void) {
    secp256k1_multiset empty, r1,r2;

    secp256k1_multiset_init(ctx, &empty);
    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);

    CHECK_EQUAL(&empty,&r1);

    /* empty + empty = empty */
    secp256k1_multiset_combine(ctx, &r1, &r2);
    CHECK_EQUAL(&empty, &r1);


}

void run_multiset_tests(void) {

    initdata();


    test_unordered();
    test_combine();
    test_remove();
    test_empty();
    test_infinity();

}

#endif
