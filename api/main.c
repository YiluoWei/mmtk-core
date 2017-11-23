#include <stdio.h>
#include "mmtk.h"

int main(int argc, char* argv[]){
    gc_init(1024*1024);
    
    for (int i=0;i<10000;i++){
        int arr_size = 10000;
        int* my_arr = alloc(sizeof(int)*arr_size, 8, 0);
        if (!my_arr){
            printf("OOM\n");
            break;
        }
        for (int j=0;j<arr_size;j++){
            my_arr[j]=j;
        }
        for (int j=0;j<arr_size;j++){
            if (my_arr[j]!=j){
                printf("Sanity check failed\n");
            }
        }
        printf("%p\n", my_arr);
    }
    int tmp;
    scanf("%d", &tmp);
    return 0;
}