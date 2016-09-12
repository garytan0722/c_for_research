#define CURL_STATICLIB
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
// curl-7.40.0-devel-mingw32
#include <curl/curl.h>
//#define POST_SIZE 2048

size_t callback_file(void *, size_t , size_t , FILE *);
char filename[FILENAME_MAX] = "/system/tmp/123.txt";

int main(int argc, char **argv) {
    // insert code here...
    CURLcode res;
    FILE *fp;
    CURL *curl;
    char *url = "https://nrl.cce.mcu.edu.tw/pgi/123.txt";
    curl = curl_easy_init();
    if(curl) {
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
    curl_easy_setopt(curl, CURLOPT_POST,1L);
    fp = fopen(filename,"wb");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    res=curl_easy_perform(curl);
        if(res != CURLE_OK){
            printf("curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        }else{
            printf("success!!!");
        }
    fclose(fp);
    
    curl_easy_cleanup(curl);
    }else{
        printf("curl fail");
    }
    system("cat /system/tmp/123.txt");
    
    return 0;
}
size_t callback_file(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}

