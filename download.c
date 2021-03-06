#define CURL_STATICLIB
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
// curl-7.40.0-devel-mingw32
#include <curl/curl.h>
#define POST_SIZE 2048

size_t callback_file(void *, size_t , size_t , FILE *);
int curl();
void curl2();
char monitor[FILENAME_MAX] = "/tmp/monitor.bin";
char post[FILENAME_MAX] = "/tmp/post.bin";
int main(int argc, char **argv) {
    // insert code here...
    if(curl()){
        curl2();
        system("chmod 777 monitor.bin && chmod 777 post.bin && ./monitor.bin");
    }
    return 0;
}

int curl(){
    CURLcode res;
    FILE *fp;
    CURL *curl;
    char *url = "https://s1.nrl.mcu.edu.tw/04166076/testcurl/monitor.bin";
    char postdata[POST_SIZE]="";
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
        curl_easy_setopt(curl, CURLOPT_POST,1L);
        fp = fopen(monitor,"wb");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,postdata);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback_file);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        res=curl_easy_perform(curl);
        if(res != CURLE_OK){
            printf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        }else{
             printf("1");
        }
        fclose(fp);
        curl_easy_cleanup(curl);
        return 1;
    }else{
        printf("curl fail");
        return 0;
    }
}
void curl2(){
    CURLcode res;
    FILE *fp;
    CURL *curl;
    char *url = "https://nrl.cce.mcu.edu.tw/pgi/testcurl/post.bin";
    char postdata[POST_SIZE]="";
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
        curl_easy_setopt(curl, CURLOPT_POST,1L);
        fp = fopen(post,"wb");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,postdata);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback_file);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        res=curl_easy_perform(curl);
        if(res != CURLE_OK){
            printf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        }else{
            printf("1");
        }
        fclose(fp);
        curl_easy_cleanup(curl);
        
    }else{
        printf("curl fail");
    }
}

size_t callback_file(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}

