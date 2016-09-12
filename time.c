#include <sys/time.h>
#include <stdio.h>
double now_ms();
int main(int argc, const char * argv[]){
double sec=now_ms();
printf("%f\n",sec);
}
double now_ms(void) {
    struct timespec res;
    clock_gettime(CLOCK_REALTIME, &res);
    return res.tv_sec;
}