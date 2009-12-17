#ifndef H__CUDA_KERNEL_H
#define H__CUDA_KERNEL_H

typedef struct {
	unsigned char	input[32];
	unsigned char	key[32];
	int				keylen;
	int				inlen;
} ComputeBlock;

// implementation of the password-cracker
__global__ void ComputeKernel(ComputeBlock *blocks);

#endif // H__CUDA_KERNEL_H
