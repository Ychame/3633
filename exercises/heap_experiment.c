#include <stdlib.h>
#include <string.h>
void heap_initialize() {
    // Break Point 1 - heap not yet initialized
    malloc(0x1000);
    // Break Point 2 - heap segment has been created by malloc() with brk()
    malloc(0x10000000);
    // Break Point 3 - anonymous memory mapping segment has been created by malloc() with mmap()
}

void heap_partition() {
    malloc(0x20);
    // Break Point 1 - one allocated heap chunk
    malloc(0x40);
    // Break Point 2 - two allocated heap chunks
}

void tcache_bin() {
    char* p1 = malloc(0x20);
    char* p2 = malloc(0x40);
    char* p3 = malloc(0x40);

    free(p1);
    // Break Point 1 - tcache_bin[1] -> p1
    free(p3);
    // Break Point 2 - tcache_bin[3] -> p3
    free(p2);
    // Break Point 3 - tcache_bin[3] -> p3 -> p2
    char* p4 = malloc(0x40);
    // Break Point 4 - tcache_bin[3] -> p3 -> p2
}

void fast_bin() {

    char* fill_tcache[7];
    for (int i = 0; i < 7; i++)
        fill_tcache[i] = malloc(0x40);
    char* p1 = malloc(0x40);
    // Break Point 1 - allocated 8 chunks

    for (int i = 0; i < 7; i++)
        free(fill_tcache[i]);
    // Break Point 2 - free 7 chunks

    free(p1);
    // Break Point 3 - free 8th chunk

    char* p2 = malloc(0x40);
    // Break Point 4 - allocate one chunk
}

void unsorted_bin() {

    char* fill_tcache[7];
    for (int i = 0; i < 7; i++)
        fill_tcache[i] = malloc(0x100);

    char* p1 = malloc(0x100);
    char* p2 = malloc(0x100);
    char* p3 = malloc(0x100);
    char* p4 = malloc(0x100);
    char* p5 = malloc(0x100);
    char* p6 = malloc(0x100);
    // Break Point 1 - allocated 7 + 5 chunks

    for (int i = 0; i < 7; i++)
        free(fill_tcache[i]);
    // Break Point 2 - free 7 chunks

    free(p6);
    // Break Point 3 - p6 is merged into top_chunk

    free(p4);
    // Break Point 4 - p4 is insert into unsortedbin

    free(p3);
    // Break Point 5 - p3 is merged with p4

    free(p1);
    // Break Point 6 - p1 is inserted into unsorted bin

    char* p7 = malloc(0x40);
    // Break Point 7 - allocate one chunk
}

void free_hook() {
    char* p1 = malloc(0x20);
    strcpy(p1, "/bin/sh");
    // Break Point 1 - before free
    free(p1);
}

int main(int argc, char* argv[]) {

    if (argc != 2)
        return -1;

    switch(atoi(argv[1])) {
        case 1:
            heap_initialize();
            break;
        
        case 2:
            heap_partition();
            break;

        case 3:
            tcache_bin();
            break;

        case 4:
            fast_bin();
            break;

        case 5:
            unsorted_bin();
            break;
        case 6:
            free_hook();
            break;
    }

    return 0;
}