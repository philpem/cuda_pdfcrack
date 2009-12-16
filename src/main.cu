#include <stdio.h>

// number of threads per block
#define THREADSPERBLOCK	512
// number of blocks per grid
#define BLOCKSPERGRID	2

// total number of thread entries
#define SIZE (THREADSPERBLOCK * BLOCKSPERGRID)

// check parameters
#if (THREADSPERBLOCK > 512)
# error Number of threads per block exceeds maximum permitted by CUDA
#endif

//  Kernel definition, see also section 2.3 of Nvidia Cuda Programming Guide
__global__ void vecAdd(float* A, float* B, float* C)
{
	// calculate array offset for this thread's global data
	int i = (blockIdx.x * blockDim.x) + threadIdx.x;

	// so we don't process unallocated data
	if (i >= SIZE) return;

	// calculate c
	C[i] = A[i] + B[i];
}

int main()
{
	float A[SIZE], B[SIZE], C[SIZE];
	float *devPtrA;
	float *devPtrB;
	float *devPtrC;
	int memsize = SIZE * sizeof(float);

	// allocate GPU memory for the calculations
	cudaMalloc((void**)&devPtrA, memsize);
	cudaMalloc((void**)&devPtrB, memsize);
	cudaMalloc((void**)&devPtrC, memsize);

	// create some input data
	for (int i=0; i<SIZE; i++) {
		A[i] = B[i] = i;
	}

	// copy input data to the graphics chip
	cudaMemcpy(devPtrA, A, memsize, cudaMemcpyHostToDevice);
	cudaMemcpy(devPtrB, B, memsize, cudaMemcpyHostToDevice);

	// __global__ functions are called:  Func<<< Dg, Db, Ns  >>>(parameter);
	vecAdd <<< BLOCKSPERGRID, THREADSPERBLOCK >>> (devPtrA, devPtrB, devPtrC);

	// copy result from GPU to local CPU RAM
	cudaMemcpy(C, devPtrC, memsize, cudaMemcpyDeviceToHost);

	// display result
	for (int i=0; i<SIZE; i++)
		printf("C[%d]=%f\n",i,C[i]);

	// free GPU memory
	cudaFree(devPtrA);
	cudaFree(devPtrA);
	cudaFree(devPtrA);
}

