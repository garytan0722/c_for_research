#define CURL_STATICLIB
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
// curl-7.40.0-devel-mingw32
#include <curl/curl.h>
#include <sys/system_properties.h>
void curl();
int main(int argc, const char *argv[]) {

    CURL *curl;
    CURLcode res;
    struct curl_httppost *post=NULL;
    struct curl_httppost *last=NULL;
    char path[30];
    char command[30];
    //FILE* fp=fopen("/test.pcap", "rb");
    printf("unixtime::::%s",argv[1]);
    sprintf(path,"/tmp/%s.pcap",argv[1]);
    printf("%s\n",path);
    double speed_upload, total_time;
    char imei_start[15];//strz end 
    int ir = __system_property_get("ro.gsm.imei", imei_start);           
    if(ir > 0)
    {
      printf("method1 got imei %s len %d\r\n",imei_start,strlen(imei_start));
      
    }else{
        strcpy(imei_start,"flase");
    }
    char *url="https://s1.nrl.mcu.edu.tw/04166076/testcurl/curl.php";
    curl = curl_easy_init();
    if (curl) {
        curl_formadd(&post, &last,
                     CURLFORM_COPYNAME, "file",
                     CURLFORM_FILE,path,
                     CURLFORM_END);
        curl_formadd(&post, &last,
                     CURLFORM_COPYNAME, "imei",
                     CURLFORM_COPYCONTENTS,imei_start,
                     CURLFORM_END);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
            //printf("file:",);
            
        }
        else {
            /* now extract transfer info */
            curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD, &speed_upload);
            curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);
            fprintf(stderr, "Speed: %.3f bytes/sec during %.3f seconds\n",
                    speed_upload, total_time);
        }
        curl_formfree(post);
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
    sprintf(command,"rm %s.pcap && ./monitor.bin",argv[1]);
    system(command);
}