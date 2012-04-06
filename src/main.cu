#include <stdio.h>
#include <ctype.h>
#include "cutil.h"
#include "cuda_kernel.h"
#include "password_gen.h"

// number of threads per block
#define THREADSPERBLOCK	256
// number of blocks per grid
#define BLOCKSPERGRID	256
//#define BLOCKSPERGRID	512

// total number of threads
#define SIZE (THREADSPERBLOCK * BLOCKSPERGRID)

// check parameters
#if (THREADSPERBLOCK > 512)
# error Number of threads per block exceeds maximum permitted by CUDA
#endif

#ifndef CUDA_SAFE_CALL
#define CUDA_SAFE_CALL
#warning Cuda_safe_call not defined!
#endif

///////////////////////////////////////////////////////////////////

/**
 * @brief Dump the contents of a PDFINFO struct in a human-readable manner
 *
 * @param info The PDFINFO block to be dumped to stdout.
 */
void DumpPDFINFO(PDFINFO_s *p)
{
	// permission flags
	printf("P: %d\n", (int)p->P);

	// crypto key length in bits
	printf("Length: %d\n", p->Length);

	// File ID
	printf("FileID: ");
	for (int i=0; i<16; i++) {
		printf("%02x", p->FileID[i]);
	}
	printf("\n");

	// U
	printf("U: ");
	for (int i=0; i<32; i++) {
		printf("%02x", p->U[i]);
	}
	printf("\n");

	// O
	printf("O: ");
	for (int i=0; i<32; i++) {
		printf("%02x", p->O[i]);
	}
	printf("\n");
}

int ParseCmdline(int argc, char **argv, PDFINFO_s *info)
{
	if (argc < 6) {
		fprintf(stderr, "Syntax: %s P Length FileID U O [Password]\n", argv[0]);
		exit(-1);
	}

	memset(info, 0, sizeof(info));

	// parse command line
	sscanf(argv[1], "%u", &info->P);
	sscanf(argv[2], "%u", &info->Length);

	// parse hexstring argument #1: FileID
	if (strlen(argv[3]) < 32) {
		fprintf(stderr, "ERROR: FileID must be 16 hexpairs (32 characters) in length.\n");
		exit(-1);
	}
	for (int i=0; i<16; i++) {
		char x[3];
		unsigned int y;
		x[0] = tolower(argv[3][(i*2)+0]);
		x[1] = tolower(argv[3][(i*2)+1]);
		x[2] = 0;
		sscanf(x, "%02x", &y);
		info->FileID[i] = y;
	}

	// parse hexstring argument #2: U
	if (strlen(argv[4]) < 64) {
		fprintf(stderr, "ERROR: U must be 32 hexpairs (64 characters) in length.\n");
		exit(-1);
	}
	for (int i=0; i<32; i++) {
		char x[3];
		unsigned int y;
		x[0] = tolower(argv[4][(i*2)+0]);
		x[1] = tolower(argv[4][(i*2)+1]);
		x[2] = 0;
		sscanf(x, "%02x", &y);
		info->U[i] = y;
	}

	// parse hexstring argument #3: O
	if (strlen(argv[5]) < 64) {
		fprintf(stderr, "ERROR: O must be 32 hexpairs (64 characters) in length.\n");
		exit(-1);
	}
	for (int i=0; i<32; i++) {
		char x[3];
		unsigned int y;
		x[0] = tolower(argv[5][(i*2)+0]);
		x[1] = tolower(argv[5][(i*2)+1]);
		x[2] = 0;
		sscanf(x, "%02x", &y);
		info->O[i] = y;
	}

	return 0;
}

///////////////////////////////////////////////////////////////////
void hex_dump(void *data, int size)
{
    /* dumps size bytes of *data to stdout. Looks like:
     * [0000] 75 6E 6B 6E 6F 77 6E 20
     *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
     * (in a single line of course)
     */

    unsigned char *p = (unsigned char *)data;
    unsigned long addr = 0;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4lX",
               addr);
        }
            
        c = *p;
        if (isalnum(c) == 0) {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0) { 
            /* line completed */
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n%8 == 0) {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
		addr++; /* increment address */
    }

    if (strlen(hexstr) > 0) {
        /* print rest of buffer if not empty */
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

int main(int argc, char **argv)
{
	ComputeBlock cb[SIZE];
	ComputeBlock *devPtrCb;
	size_t memsize = SIZE * sizeof(ComputeBlock);
	PDFINFO_s pdfinfo_loc;

	// Parse the command line
	ParseCmdline(argc, argv, &pdfinfo_loc);

	DumpPDFINFO(&pdfinfo_loc);

	// allocate GPU memory for the calculations
	CUDA_SAFE_CALL(cudaMalloc((void**)&devPtrCb, memsize));

	// generate passwords
	int done=false;
	int MINLEN=1, MAXLEN=4;
	int len=MINLEN;
	int counter[32];
	char str[33];
	password_init(32, counter, str);
	do {
		size_t i;

		// create one block of passwords
		for (i=0; i<SIZE; i++) {
			// null terminate and copy into password block
			str[len]='\0';
			strncpy(cb[i].password, str, sizeof(cb[i].password));

			// set password length and match flag
			cb[i].pwlen = len;
			cb[i].match = 99;		// system error

			// if overflow, init for another character in length
			if (password_next(len, counter, str)) {
				password_init(len+1, counter, str);
				len++;
			}

			// break if we hit the maximum length
			if (len > MAXLEN) break;
		}

		// fill unused password blocks
		if (i<SIZE) {
			printf("::::: %d unused\n", SIZE-i);
			for (; i<SIZE; i++) {
				cb[i].pwlen = 0;
				cb[i].match = 99;		// system error
			}
		}

		// process the passwords

		// copy input data to the graphics chip
		CUDA_SAFE_CALL(cudaMemcpy(devPtrCb, cb, memsize, cudaMemcpyHostToDevice));

		// Copy PDFINFO block from CPU --> GPU "constant RAM" space
		LoadPdfInfo(&pdfinfo_loc);

		// __global__ functions are called:  Func<<< Dg, Db, Ns  >>>(parameter);
		ComputeKernel <<< BLOCKSPERGRID, THREADSPERBLOCK >>> (devPtrCb);

		// copy result from GPU to local CPU RAM
		CUDA_SAFE_CALL(cudaMemcpy(cb, devPtrCb, memsize, cudaMemcpyDeviceToHost));

		// scan through the output array
		for (i=0; i<SIZE; i++) {
			// exit if we hit the start of the "empty" compute blocks
			if (cb[i].pwlen == 0) break;

			// don't display non-matching passwords (except the first one in this block)
			if ((!cb[i].match) && (i != 0)) continue;

			// null-terminate the password
			cb[i].password[cb[i].pwlen] = '\0';

			// display the password and status
			printf("%3d\t%s\t%s\n", i, cb[i].password, ((cb[i].match == 99) ? "SysError" : (cb[i].match ? "MATCH" : "fail")));

			// if this is a password match (not a syserror or a no-match), stop the scan
			if (cb[i].match) {
				done = true;
				break;
			}
		}
	} while ((len <= MAXLEN) && (!done));

	// free GPU memory
	CUDA_SAFE_CALL(cudaFree(devPtrCb));
}

