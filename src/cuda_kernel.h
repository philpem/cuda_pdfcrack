#ifndef H__CUDA_KERNEL_H
#define H__CUDA_KERNEL_H

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

// load PDFINFO block
void LoadPdfInfo(PDFINFO_s *info);

// implementation of computation kernel
__global__ void ComputeKernel(ComputeBlock *blocks);

#endif // H__CUDA_KERNEL_H
