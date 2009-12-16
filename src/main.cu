#include <stdio.h>

//  Kernel definition, see also section 2.3 of Nvidia Cuda Programming Guide
__global__ void vecAdd(float* A, float* B, float* C)
{
	// calculate array offset for this thread's global data
	int i = (blockIdx.x * blockDim.x) + threadIdx.x;

	// calculate c
	C[i] = A[i] + B[i];
}

// size of thread buffer
#define SIZE 10

int main()
{
	int N=SIZE;
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
	vecAdd<<<1, N>>>(devPtrA, devPtrB, devPtrC);

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

