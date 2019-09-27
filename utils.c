#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int ipstr_to_bytes_n(char *ipstr, int *ipbytes){
    inet_pton(AF_INET, ipstr, ipbytes);
}

int main(){
    int buf;
    ipstr_to_bytes_n("121.128.247.119",&buf);
    printf("%d",buf);
}