#include <stdio.h>
#include <stdlib.h>

void quick_sort(long* num, int start, int end){
    if(start >= end)
        return;

    register int l = start;

    for(register int r = start ; r <= end; r++){
        if(num[r] <= num[end]){
            long tmp = num[l];
            num[l] = num[r];
            num[r] = tmp;

            l++;
        }
    }

    l--;
    
    quick_sort(num, start, l-1);
    quick_sort(num, l+1, end);
}

void sort(long* numbers, int n){
    quick_sort(numbers, 0, n-1);
}