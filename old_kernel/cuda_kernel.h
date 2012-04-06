#ifndef H__CUDA_KERNEL_H
#define H__CUDA_KERNEL_H

#ifdef CUDA_KERNEL_IMPL
#define EXTERN
#else
#define EXTERN extern
#endif

typedef struct {
	char password[32];
	int pwlen;
	int match;
	char debug[64];
} ComputeBlock;

typedef struct {
	unsigned char U[32];
	unsigned char O[32];
	unsigned char FileID[16];
	unsigned int Length;
	unsigned int P;
} PDFINFO_s;

EXTERN __constant__ PDFINFO_s PDFINFO;

// implementation of the password-cracker
__global__ void ComputeKernel(ComputeBlock *blocks);

#endif // H__CUDA_KERNEL_H
