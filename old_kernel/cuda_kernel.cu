#define CUDA_KERNEL_IMPL
#include "cuda_kernel.h"

/**
 * Bastardised version of David Sterndark's RC4 implementation, hacked to run
 * on nVidia CUDA-enabled GPUs.
 *
 * Newsgroups: sci.crypt,alt.security,comp.security.misc,alt.privacy
 * From: sterndark@netcom.com (David Sterndark)
 * Subject: RC4 Algorithm revealed.
 * Message-ID: <sternCvKL4B.Hyy@netcom.com>
 * Date: Wed, 14 Sep 1994 06:35:31 GMT
 */

typedef struct rc4_key
{
	unsigned char state[256];
	unsigned char x;
	unsigned char y;
} rc4_key;

__device__ void rc4_prepare_key(unsigned char *key_data_ptr, int key_data_len, rc4_key *key)
{
	unsigned char t;
	unsigned char index1;
	unsigned char index2;
	unsigned char* state;
	short counter;

	state = &key->state[0];

	for(counter = 0; counter < 256; counter++)
		state[counter] = counter;

	key->x = 0;
	key->y = 0;
	index1 = 0;
	index2 = 0;

	for(counter = 0; counter < 256; counter++)
	{
		index2 = (key_data_ptr[index1] + state[counter] + index2) % 256;
		t=state[counter]; state[counter] = state[index2]; state[index2] = t;
		index1 = (index1 + 1) % key_data_len;
	}
}

__device__ void rc4(unsigned char *buffer_ptr, int buffer_len, rc4_key *key)
{
	unsigned char t;
	unsigned char x;
	unsigned char y;
	unsigned char* state;
	unsigned char xorIndex;
	short counter;

	x = key->x;
	y = key->y;
	state = &key->state[0];
	for(counter = 0; counter < buffer_len; counter++)
	{
		x = (x + 1) % 256;
		y = (state[x] + y) % 256;
		t=state[x]; state[x]=state[y]; state[y]=t;
		xorIndex = (state[x] + state[y]) % 256;
		buffer_ptr[counter] ^= state[xorIndex];
	}
	key->x = x;
	key->y = y;
}

//////////////////////////////////////////////////////////////////////////////
// MD5 Engine

/*
  Copyright (C) 1999, 2002 Aladdin Enterprises.  All rights reserved.

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  L. Peter Deutsch
  ghost@aladdin.com

 */
/* $Id: md5.h,v 1.4 2002/04/13 19:20:28 lpd Exp $ */
/*
  Independent implementation of MD5 (RFC 1321).

  This code implements the MD5 Algorithm defined in RFC 1321, whose
  text is available at
        http://www.ietf.org/rfc/rfc1321.txt
  The code is derived from the text of the RFC, including the test suite
  (section A.5) but excluding the rest of Appendix A.  It does not include
  any code or documentation that is identified in the RFC as being
  copyrighted.

  The original and principal author of md5.h is L. Peter Deutsch
  <ghost@aladdin.com>.  Other authors are noted in the change history
  that follows (in reverse chronological order):

  2002-04-13 lpd Removed support for non-ANSI compilers; removed
        references to Ghostscript; clarified derivation from RFC 1321;
        now handles byte order either statically or dynamically.
  1999-11-04 lpd Edited comments slightly for automatic TOC extraction.
  1999-10-18 lpd Fixed typo in header comment (ansi2knr rather than md5);
        added conditionalization for C++ compilation from Martin
        Purschke <purschke@bnl.gov>.
  1999-05-03 lpd Original version.
 */

/*
 * This package supports both compile-time and run-time determination of CPU
 * byte order.  If ARCH_IS_BIG_ENDIAN is defined as 0, the code will be
 * compiled to run only on little-endian CPUs; if ARCH_IS_BIG_ENDIAN is
 * defined as non-zero, the code will be compiled to run only on big-endian
 * CPUs; if ARCH_IS_BIG_ENDIAN is not defined, the code will be compiled to
 * run on either big- or little-endian CPUs, but will run slightly less
 * efficiently on either one than if ARCH_IS_BIG_ENDIAN is defined.
 */

typedef unsigned char md5_byte_t; /* 8-bit byte */
typedef unsigned int md5_word_t; /* 32-bit word */

/* Define the state of the MD5 Algorithm. */
typedef struct md5_state_s {
    md5_word_t count[2];        /* message length in bits, lsw first */
    md5_word_t abcd[4];         /* digest buffer */
    md5_byte_t buf[64];         /* accumulate block */
} md5_state_t;

#define T_MASK ((md5_word_t)~0)
#define T1 /* 0xd76aa478 */ (T_MASK ^ 0x28955b87)
#define T2 /* 0xe8c7b756 */ (T_MASK ^ 0x173848a9)
#define T3    0x242070db
#define T4 /* 0xc1bdceee */ (T_MASK ^ 0x3e423111)
#define T5 /* 0xf57c0faf */ (T_MASK ^ 0x0a83f050)
#define T6    0x4787c62a
#define T7 /* 0xa8304613 */ (T_MASK ^ 0x57cfb9ec)
#define T8 /* 0xfd469501 */ (T_MASK ^ 0x02b96afe)
#define T9    0x698098d8
#define T10 /* 0x8b44f7af */ (T_MASK ^ 0x74bb0850)
#define T11 /* 0xffff5bb1 */ (T_MASK ^ 0x0000a44e)
#define T12 /* 0x895cd7be */ (T_MASK ^ 0x76a32841)
#define T13    0x6b901122
#define T14 /* 0xfd987193 */ (T_MASK ^ 0x02678e6c)
#define T15 /* 0xa679438e */ (T_MASK ^ 0x5986bc71)
#define T16    0x49b40821
#define T17 /* 0xf61e2562 */ (T_MASK ^ 0x09e1da9d)
#define T18 /* 0xc040b340 */ (T_MASK ^ 0x3fbf4cbf)
#define T19    0x265e5a51
#define T20 /* 0xe9b6c7aa */ (T_MASK ^ 0x16493855)
#define T21 /* 0xd62f105d */ (T_MASK ^ 0x29d0efa2)
#define T22    0x02441453
#define T23 /* 0xd8a1e681 */ (T_MASK ^ 0x275e197e)
#define T24 /* 0xe7d3fbc8 */ (T_MASK ^ 0x182c0437)
#define T25    0x21e1cde6
#define T26 /* 0xc33707d6 */ (T_MASK ^ 0x3cc8f829)
#define T27 /* 0xf4d50d87 */ (T_MASK ^ 0x0b2af278)
#define T28    0x455a14ed
#define T29 /* 0xa9e3e905 */ (T_MASK ^ 0x561c16fa)
#define T30 /* 0xfcefa3f8 */ (T_MASK ^ 0x03105c07)
#define T31    0x676f02d9
#define T32 /* 0x8d2a4c8a */ (T_MASK ^ 0x72d5b375)
#define T33 /* 0xfffa3942 */ (T_MASK ^ 0x0005c6bd)
#define T34 /* 0x8771f681 */ (T_MASK ^ 0x788e097e)
#define T35    0x6d9d6122
#define T36 /* 0xfde5380c */ (T_MASK ^ 0x021ac7f3)
#define T37 /* 0xa4beea44 */ (T_MASK ^ 0x5b4115bb)
#define T38    0x4bdecfa9
#define T39 /* 0xf6bb4b60 */ (T_MASK ^ 0x0944b49f)
#define T40 /* 0xbebfbc70 */ (T_MASK ^ 0x4140438f)
#define T41    0x289b7ec6
#define T42 /* 0xeaa127fa */ (T_MASK ^ 0x155ed805)
#define T43 /* 0xd4ef3085 */ (T_MASK ^ 0x2b10cf7a)
#define T44    0x04881d05
#define T45 /* 0xd9d4d039 */ (T_MASK ^ 0x262b2fc6)
#define T46 /* 0xe6db99e5 */ (T_MASK ^ 0x1924661a)
#define T47    0x1fa27cf8
#define T48 /* 0xc4ac5665 */ (T_MASK ^ 0x3b53a99a)
#define T49 /* 0xf4292244 */ (T_MASK ^ 0x0bd6ddbb)
#define T50    0x432aff97
#define T51 /* 0xab9423a7 */ (T_MASK ^ 0x546bdc58)
#define T52 /* 0xfc93a039 */ (T_MASK ^ 0x036c5fc6)
#define T53    0x655b59c3
#define T54 /* 0x8f0ccc92 */ (T_MASK ^ 0x70f3336d)
#define T55 /* 0xffeff47d */ (T_MASK ^ 0x00100b82)
#define T56 /* 0x85845dd1 */ (T_MASK ^ 0x7a7ba22e)
#define T57    0x6fa87e4f
#define T58 /* 0xfe2ce6e0 */ (T_MASK ^ 0x01d3191f)
#define T59 /* 0xa3014314 */ (T_MASK ^ 0x5cfebceb)
#define T60    0x4e0811a1
#define T61 /* 0xf7537e82 */ (T_MASK ^ 0x08ac817d)
#define T62 /* 0xbd3af235 */ (T_MASK ^ 0x42c50dca)
#define T63    0x2ad7d2bb
#define T64 /* 0xeb86d391 */ (T_MASK ^ 0x14792c6e)

__device__ void md5_process(md5_state_t *pms, const md5_byte_t *data /*[64]*/)
{
    md5_word_t
        a = pms->abcd[0], b = pms->abcd[1],
        c = pms->abcd[2], d = pms->abcd[3];
    md5_word_t t;
    /* Define storage for little-endian or both types of CPUs. */
    md5_word_t X[16];

	for (int i=0; i<64; i+=4) {
		X[i/4] = 
			(data[i+0])       |
			(data[i+1] << 8)  |
			(data[i+2] << 16) |
			(data[i+3] << 24);
	}

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

    /* Round 1. */
    /* Let [abcd k s i] denote the operation
       a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define SET(a, b, c, d, k, s, Ti)\
  t = a + F(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
    /* Do the following 16 operations. */
    SET(a, b, c, d,  0,  7,  T1);
    SET(d, a, b, c,  1, 12,  T2);
    SET(c, d, a, b,  2, 17,  T3);
    SET(b, c, d, a,  3, 22,  T4);
    SET(a, b, c, d,  4,  7,  T5);
    SET(d, a, b, c,  5, 12,  T6);
    SET(c, d, a, b,  6, 17,  T7);
    SET(b, c, d, a,  7, 22,  T8);
    SET(a, b, c, d,  8,  7,  T9);
    SET(d, a, b, c,  9, 12, T10);
    SET(c, d, a, b, 10, 17, T11);
    SET(b, c, d, a, 11, 22, T12);
    SET(a, b, c, d, 12,  7, T13);
    SET(d, a, b, c, 13, 12, T14);
    SET(c, d, a, b, 14, 17, T15);
    SET(b, c, d, a, 15, 22, T16);
#undef SET

     /* Round 2. */
     /* Let [abcd k s i] denote the operation
          a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s). */
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define SET(a, b, c, d, k, s, Ti)\
  t = a + G(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
     /* Do the following 16 operations. */
    SET(a, b, c, d,  1,  5, T17);
    SET(d, a, b, c,  6,  9, T18);
    SET(c, d, a, b, 11, 14, T19);
    SET(b, c, d, a,  0, 20, T20);
    SET(a, b, c, d,  5,  5, T21);
    SET(d, a, b, c, 10,  9, T22);
    SET(c, d, a, b, 15, 14, T23);
    SET(b, c, d, a,  4, 20, T24);
    SET(a, b, c, d,  9,  5, T25);
    SET(d, a, b, c, 14,  9, T26);
    SET(c, d, a, b,  3, 14, T27);
    SET(b, c, d, a,  8, 20, T28);
    SET(a, b, c, d, 13,  5, T29);
    SET(d, a, b, c,  2,  9, T30);
    SET(c, d, a, b,  7, 14, T31);
    SET(b, c, d, a, 12, 20, T32);
#undef SET

     /* Round 3. */
     /* Let [abcd k s t] denote the operation
          a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s). */
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define SET(a, b, c, d, k, s, Ti)\
  t = a + H(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
     /* Do the following 16 operations. */
    SET(a, b, c, d,  5,  4, T33);
    SET(d, a, b, c,  8, 11, T34);
    SET(c, d, a, b, 11, 16, T35);
    SET(b, c, d, a, 14, 23, T36);
    SET(a, b, c, d,  1,  4, T37);
    SET(d, a, b, c,  4, 11, T38);
    SET(c, d, a, b,  7, 16, T39);
    SET(b, c, d, a, 10, 23, T40);
    SET(a, b, c, d, 13,  4, T41);
    SET(d, a, b, c,  0, 11, T42);
    SET(c, d, a, b,  3, 16, T43);
    SET(b, c, d, a,  6, 23, T44);
    SET(a, b, c, d,  9,  4, T45);
    SET(d, a, b, c, 12, 11, T46);
    SET(c, d, a, b, 15, 16, T47);
    SET(b, c, d, a,  2, 23, T48);
#undef SET

     /* Round 4. */
     /* Let [abcd k s t] denote the operation
          a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s). */
#define I(x, y, z) ((y) ^ ((x) | ~(z)))
#define SET(a, b, c, d, k, s, Ti)\
  t = a + I(b,c,d) + X[k] + Ti;\
  a = ROTATE_LEFT(t, s) + b
     /* Do the following 16 operations. */
    SET(a, b, c, d,  0,  6, T49);
    SET(d, a, b, c,  7, 10, T50);
    SET(c, d, a, b, 14, 15, T51);
    SET(b, c, d, a,  5, 21, T52);
    SET(a, b, c, d, 12,  6, T53);
    SET(d, a, b, c,  3, 10, T54);
    SET(c, d, a, b, 10, 15, T55);
    SET(b, c, d, a,  1, 21, T56);
    SET(a, b, c, d,  8,  6, T57);
    SET(d, a, b, c, 15, 10, T58);
    SET(c, d, a, b,  6, 15, T59);
    SET(b, c, d, a, 13, 21, T60);
    SET(a, b, c, d,  4,  6, T61);
    SET(d, a, b, c, 11, 10, T62);
    SET(c, d, a, b,  2, 15, T63);
    SET(b, c, d, a,  9, 21, T64);
#undef SET

     /* Then perform the following additions. (That is increment each
        of the four registers by the value it had before this block
        was started.) */
    pms->abcd[0] += a;
    pms->abcd[1] += b;
    pms->abcd[2] += c;
    pms->abcd[3] += d;
}

/* Initialize the algorithm. */
__device__ void md5_init(md5_state_t *pms)
{
    pms->count[0] = pms->count[1] = 0;
    pms->abcd[0] = 0x67452301;
    pms->abcd[1] = /*0xefcdab89*/ T_MASK ^ 0x10325476;
    pms->abcd[2] = /*0x98badcfe*/ T_MASK ^ 0x67452301;
    pms->abcd[3] = 0x10325476;
}

/* Append a string to the message. */
__device__ void md5_append(md5_state_t *pms, const md5_byte_t *data, int nbytes)
{
    const md5_byte_t *p = data;
    int left = nbytes;
    int offset = (pms->count[0] >> 3) & 63;
    md5_word_t nbits = (md5_word_t)(nbytes << 3);

    if (nbytes <= 0)
        return;

    /* Update the message length. */
    pms->count[1] += nbytes >> 29;
    pms->count[0] += nbits;
    if (pms->count[0] < nbits)
        pms->count[1]++;

    /* Process an initial partial block. */
    if (offset) {
        int copy = (offset + nbytes > 64 ? 64 - offset : nbytes);

		for (int i=0; i<copy; i++)
			(pms->buf+offset)[i] = p[i];
        if (offset + copy < 64)
            return;
        p += copy;
        left -= copy;
        md5_process(pms, pms->buf);
    }

    /* Process full blocks. */
    for (; left >= 64; p += 64, left -= 64)
        md5_process(pms, p);

    /* Process a final partial block. */
    if (left)
		for (int i=0; i<left; i++)
			pms->buf[i] = p[i];
}

/* Finish the message and return the digest. */
__device__ void md5_finish(md5_state_t *pms, md5_byte_t digest[16])
{
    const md5_byte_t pad[64] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    md5_byte_t data[8];
    int i;

    /* Save the length before padding. */
    for (i = 0; i < 8; ++i)
        data[i] = (md5_byte_t)(pms->count[i >> 2] >> ((i & 3) << 3));
    /* Pad to 56 bytes mod 64. */
    md5_append(pms, pad, ((55 - (pms->count[0] >> 3)) & 63) + 1);
    /* Append the length. */
    md5_append(pms, data, 8);
    for (i = 0; i < 16; ++i)
        digest[i] = (md5_byte_t)(pms->abcd[i >> 2] >> ((i & 3) << 3));
}

//////////////////////////////////////////////////////////////////////////////
// PDF password checker

__constant__
const unsigned char PADDING[] = { 0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
								  0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
								  0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
								  0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
								};

#define PDF_ALGORITHM_REV 3

// the core of the crypto engine
__global__ void ComputeKernel(ComputeBlock *blocks)
{
	// calculate array offset for this thread's global data
	int i = (blockIdx.x * blockDim.x) + threadIdx.x;

	// don't process passwords longer than 32 bytes (this is invalid anyway)
	if (blocks[i].pwlen > 32) return;

	// get this thread's compute block
	ComputeBlock *block = &blocks[i];

	// MD5 self test
	//// ---- MD5 self test
	unsigned char digest[16];
	const char NUM_VECTORS = 8;
	char testvector[NUM_VECTORS][96] = {
		"",
		"a",
		"abc",
		"message digest",
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		"The quick brown fox jumps over the lazy dog"
	};
	md5_state_t ctx;

	for (int x=0; x<3; x++) {
		md5_init(&ctx);
//		md5_append(&ctx, (unsigned char *)testvector[x], strlen(testvector[x]));
//		md5_finish(&ctx, digest);
		for (int y=0; y<16; y++) {
			int ofs=(x%4)*16;
			block->debug[ofs+y] = digest[y];
		}
	}

#if 0
// Algorithm 3.6 -- Validating User Password.
// 1. Perform all but the last step of Algorithm 3.5.
//
// Algorithm 3.5 -- Computing the Encryption Dictionary's U (User Password)
// value (R3 or greater)
// 1. Create an encryption key based on the User Password String, as
//    described in Algorithm 3.2
	// 1. Pad or truncate the password to exactly 32 bytes.
	if (block->pwlen < 32) {
		// password shorter than 32 bytes, pad up
		for (int i=block->pwlen, j=0; i<32; i++, j++)
			block->password[i] = PADDING[j];
	}

	// NOTE: if password is longer than 32 bytes, it will be rejected by the
	// checks above, thus long pwds don't need truncating.

	// 2. Initialise the MD5 hash function and pass the result of step 1 as
	//    input to this function.
	md5_state_t md5;
	md5_init(&md5);
	md5_append(&md5, (md5_byte_t *)block->password, 32);

	// 3. Pass the value of the encryption dictionary's O entry to the MD5
	//    hash function.
	md5_append(&md5, PDFINFO.O, 32);

	// 4. Treat the value of the P entry as an unsigned 4-byte integer and
	//    pass these bytes to the MD5 hash function, low-order byte first.
	unsigned char P[4];
	P[0] = (PDFINFO.P)       & 0xff;
	P[1] = (PDFINFO.P >> 8)  & 0xff;
	P[2] = (PDFINFO.P >> 16) & 0xff;
	P[3] = (PDFINFO.P >> 24) & 0xff;
	md5_append(&md5, P, 4);

	// 5. Pass the first element of the file's file identifier array (the
	//    value of the ID entry in the document's trailer dictionary) to
	//    the MD5 hash function.
	md5_append(&md5, PDFINFO.FileID, 16);

	// 6. Revision 4 or greater: If document metadata is NOT being encrypted,
	//    pass 4 bytes with the value 0xFF FF FF FF to the MD5 hash function.
#if (PDF_ALGORITHM_REV >= 4)
	const unsigned char FFbuf[] = {0xff, 0xff, 0xff, 0xff};
	md5_append(&md5, FFbuf, 4);
#endif

	// 7. Finish the hash.
	unsigned char digest[16];
	md5_finish(&md5, digest);

memcpy(block->debug, digest, 16);
return;
	// 8. Revision 3 or greater: Do the following 50 times:
#if (PDF_ALGORITHM_REV >= 3)
	const int N = PDFINFO.Length/8;
	for (int i=0; i<50; i++) {
		// Take the output from the previous MD5 hash, and pass the first N
		// bytes of the output as input into a new MD5 hash. N is the number
		// of bytes of the encryption key, as defined by the value of the
		// encryption dictionary's Length entry.
		md5_init(&md5);
		md5_append(&md5, digest, N);
		md5_finish(&md5, digest);
	}
#endif

	// 9. Set the encryption key to the first N bytes of the output from the
	//    final MD5 hash, where N is always 5 for revision 2 but, for revision
	//    3 or greater, depends on the value of the encryption dictionary's
	//    Length entry.
	//
	//    We also save the encryption key (it's used later)
	unsigned char keybuf[16];
	memcpy(keybuf, digest, 16);

/////// End algorithm 3.2. Resume @ step 2 of Algorithm 3.5
// Algorithm 3.5
// 2. Initialise the MD5 hash function and pass the 32-byte padding string
//    shown in step 1 of Algorithm 3.2 to this function.

//  TODO: part of this (maybe upto and including 3.) could probably be
//  precomputed on a per-file basis. Copy it for each run of this part
//  of the algorithm.
	md5_init(&md5);
	md5_append(&md5, (unsigned char *)PADDING, 32);

// 3. Pass the first element of the file's file identifier array to the hash
//    function, then finish the hash.
	md5_append(&md5, PDFINFO.FileID, 16);
	md5_finish(&md5, digest);

// 4. Encrypt the 16-byte result of the hash, using an RC4 encryption function
//    with the encryption key from Step 1. (Algorithm 3.2).
//  RC4() encrypts in-place, so digest
	rc4_key rc4key;
	rc4_prepare_key(keybuf, 16, &rc4key);
	rc4(digest, 16, &rc4key);

// 5. Do the following 19 times: Take the output from the previous invocation
//    of the RC4 function, and pass it as input to a new invocation of the
//    function. Use an encryption key generated by taking each byte of the
//    original encryption key and performing an XOR between that byte and the
//    single-byte value of the iteration counter (from 1 to 19).
	unsigned char new_key[16];
	for (int i=1; i<20; i++) {
		// Generate the new key
		for (int x=0; x<16; x++) {
			new_key[x] = keybuf[x] ^ i;
		}

		// Set up the RC4 engine
		rc4_prepare_key(new_key, 16, &rc4key);
		rc4(digest, 16, &rc4key);
	}

	// "Digest" now contains the first 16 bytes of U, which need to be compared
	// against the "U" value.
	block->match = 1;
	for (int i=0; i<16; i++) {
		if (digest[i] != PDFINFO.U[i]) {
			block->match = 0;
			break;
		}
	}
#endif
}

