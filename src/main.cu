#include  <stdio.h>

//  Kernel definition, see also section 2.3 of Nvidia Cuda Programming Guide
__global__  void vecAdd(float* A, float* B, float* C)
{
	// calculate array offset for this thread's global data
	int i = (blockIdx.x * blockDim.x) + threadIdx.x;

	// init a, b
	A[i] = B[i] = i;

	// calculate c
	C[i] = A[i] + B[i];
}

#define  SIZE 10

int main()
{
	int N=SIZE;
	float A[SIZE], B[SIZE], C[SIZE];
	float *devPtrA;
	float *devPtrB;
	float *devPtrC;
	int memsize= SIZE * sizeof(float);

	cudaMalloc((void**)&devPtrA, memsize);
	cudaMalloc((void**)&devPtrB, memsize);
	cudaMalloc((void**)&devPtrC, memsize);
	cudaMemcpy(devPtrA, A, memsize,  cudaMemcpyHostToDevice);
	cudaMemcpy(devPtrB, B, memsize,  cudaMemcpyHostToDevice);

	// __global__ functions are called:  Func<<< Dg, Db, Ns  >>>(parameter);
	vecAdd<<<1, N>>>(devPtrA,  devPtrB, devPtrC);
	cudaMemcpy(C, devPtrC, memsize,  cudaMemcpyDeviceToHost);

	for (int i=0; i<SIZE; i++)
		printf("C[%d]=%f\n",i,C[i]);

	cudaFree(devPtrA);
	cudaFree(devPtrA);
	cudaFree(devPtrA);
}

