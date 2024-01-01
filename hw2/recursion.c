#include <stdio.h>
#include <unistd.h>

int fib(int n){

    printf("n: %d\n", n);

    if(n <= 1)
        return n;
    else return fib(n-1) + fib(n-2);
}

int main(){
    int ans;

    ans = fib(4);
    printf("ans: %d\n", ans);
}