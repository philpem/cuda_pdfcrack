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





// the core of the crypto engine
__global__ void ComputeKernel(ComputeBlock *blocks)
{
	// calculate array offset for this thread's global data
	int i = (blockIdx.x * blockDim.x) + threadIdx.x;

	// so we don't process unallocated data
	if ((blocks[i].inlen <= 0) || (blocks[i].keylen <= 0)) return;

	// do an RC4 key init
	rc4_key rc4key;
	rc4_prepare_key(blocks[i].key, blocks[i].keylen, &rc4key);

	// do the encryption
	rc4(blocks[i].input, blocks[i].inlen, &rc4key);
}
