#include <stdio.h>
#include "cuda_kernel.h"

// number of threads per block
#define THREADSPERBLOCK	10
// number of blocks per grid
#define BLOCKSPERGRID	10

// total number of threads
#define SIZE (THREADSPERBLOCK * BLOCKSPERGRID)

// check parameters
#if (THREADSPERBLOCK > 512)
# error Number of threads per block exceeds maximum permitted by CUDA
#endif

///////////////////////////////////////////////////////////////////

int main()
{
	ComputeBlock cb[SIZE];
	ComputeBlock *devPtrCb;
	int memsize = SIZE * sizeof(ComputeBlock);

	// allocate GPU memory for the calculations
	cudaMalloc((void**)&devPtrCb, memsize);

	// create some input data
	for (int i=0; i<SIZE; i++) {
		for (int j=0; j<sizeof(cb[i].input); j++) cb[i].input[j]='\0';
		for (int j=0; j<sizeof(cb[i].key);   j++) cb[i].key[j]='\0';
	}
	memcpy(&cb[0].key, "Key", 3);
	memcpy(&cb[0].input, "Plaintext", 9);
	cb[0].keylen = 3;
	cb[0].inlen = 9;

	// copy input data to the graphics chip
	cudaMemcpy(devPtrCb, cb, memsize, cudaMemcpyHostToDevice);

	// __global__ functions are called:  Func<<< Dg, Db, Ns  >>>(parameter);
	ComputeKernel <<< BLOCKSPERGRID, THREADSPERBLOCK >>> (devPtrCb);

	// copy result from GPU to local CPU RAM
	cudaMemcpy(cb, devPtrCb, memsize, cudaMemcpyDeviceToHost);

	// display result
//	for (int i=0; i<SIZE; i++)
//		printf("C[%d]=%f\n",i,C[i]);

	for (int i=0; i<9; i++) {
		printf("%02X ", cb[0].input[i]);
	}

	// free GPU memory
	cudaFree(devPtrCb);
}

