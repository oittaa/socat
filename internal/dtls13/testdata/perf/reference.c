/* Lab-only DTLS 1.3 library comparison. Build against one pinned reference. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef USE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
typedef WOLFSSL SSL;
typedef WOLFSSL_CTX SSL_CTX;
#define SSL_read wolfSSL_read
#define SSL_write wolfSSL_write
#define SSL_get_error wolfSSL_get_error
#define SSL_connect wolfSSL_connect
#define SSL_accept wolfSSL_accept
#define SSL_free wolfSSL_free
#define SSL_CTX_free wolfSSL_CTX_free
#define SSL_ERROR_WANT_READ WOLFSSL_ERROR_WANT_READ
#define SSL_ERROR_WANT_WRITE WOLFSSL_ERROR_WANT_WRITE
#define LIBRARY "wolfssl"
#else
#include <openssl/ssl.h>
#include <openssl/err.h>
#define LIBRARY "openssl"
#endif

static void check(int ok, const char *what) {
    if (!ok) { fprintf(stderr, "%s: %s\n", what, strerror(errno)); exit(1); }
}
static double now(void) {
    struct timespec t; check(clock_gettime(CLOCK_MONOTONIC, &t) == 0, "clock");
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
static unsigned char payload[1024];
static _Thread_local int timed_index = -1;
static void send_record(SSL *ssl, const unsigned char *data) {
    int n = SSL_write(ssl, data, 1024);
    if (n != 1024) {
        fprintf(stderr,"write=%d error=%d timed_record=%d\n",n,SSL_get_error(ssl,n),timed_index);
#ifndef USE_WOLFSSL
        ERR_print_errors_fp(stderr);
#endif
        exit(1);
    }
}
static int receive_record(SSL *ssl, unsigned char *buf, int timeout_ok) {
    int n = SSL_read(ssl, buf, 1024);
    if (n == 1024) return 1;
    int error = SSL_get_error(ssl,n);
    if (timeout_ok && (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)) return 0;
    fprintf(stderr,"read=%d error=%d errno=%d\n",n,error,errno);
#ifndef USE_WOLFSSL
    ERR_print_errors_fp(stderr);
#endif
    exit(1);
}
static void *accept_peer(void *ssl) { check(SSL_accept(ssl)==1,"accept");return NULL; }
static int udp(struct sockaddr_in *addr) {
    int fd=socket(AF_INET,SOCK_DGRAM,0);check(fd>=0,"socket");
    memset(addr,0,sizeof(*addr));addr->sin_family=AF_INET;addr->sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    check(bind(fd,(struct sockaddr*)addr,sizeof(*addr))==0,"bind");
    socklen_t size=sizeof(*addr);check(getsockname(fd,(struct sockaddr*)addr,&size)==0,"getsockname");
    struct timeval timeout={15,0};check(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0,"receive timeout");
    return fd;
}
static SSL *connection(int server,int fd,struct sockaddr_in *peer,const char *cert,const char *key,const char *ca,SSL_CTX **ctx) {
#ifdef USE_WOLFSSL
    *ctx=wolfSSL_CTX_new(server?wolfDTLSv1_3_server_method():wolfDTLSv1_3_client_method());check(*ctx!=NULL,"context");
    check(wolfSSL_CTX_set_cipher_list(*ctx,"TLS13-AES128-GCM-SHA256")==1,"cipher");
    int group=29;check(wolfSSL_CTX_set_groups(*ctx,&group,1)==1,"group");
    if(server){check(wolfSSL_CTX_use_certificate_file(*ctx,cert,WOLFSSL_FILETYPE_PEM)==1,"certificate");check(wolfSSL_CTX_use_PrivateKey_file(*ctx,key,WOLFSSL_FILETYPE_PEM)==1,"key");}
    else{check(wolfSSL_CTX_load_verify_locations(*ctx,ca,NULL)==1,"CA");wolfSSL_CTX_set_verify(*ctx,WOLFSSL_VERIFY_PEER,NULL);}
    SSL *ssl=wolfSSL_new(*ctx);check(ssl!=NULL,"connection");check(wolfSSL_set_fd(ssl,fd)==1,"fd");
    check(wolfSSL_dtls_set_peer(ssl,peer,sizeof(*peer))==1,"peer");check(wolfSSL_dtls_set_mtu(ssl,1200)==1,"MTU");
    if(!server)check(wolfSSL_check_domain_name(ssl,"localhost")==1,"hostname");
#else
    *ctx=SSL_CTX_new(server?DTLS_server_method():DTLS_client_method());check(*ctx!=NULL,"context");
    check(SSL_CTX_set_min_proto_version(*ctx,DTLS1_3_VERSION)==1 && SSL_CTX_set_max_proto_version(*ctx,DTLS1_3_VERSION)==1,"version");
    check(SSL_CTX_set_ciphersuites(*ctx,"TLS_AES_128_GCM_SHA256")==1,"cipher");check(SSL_CTX_set1_groups_list(*ctx,"X25519")==1,"group");
    if(server){check(SSL_CTX_use_certificate_file(*ctx,cert,SSL_FILETYPE_PEM)==1,"certificate");check(SSL_CTX_use_PrivateKey_file(*ctx,key,SSL_FILETYPE_PEM)==1,"key");}
    else{check(SSL_CTX_load_verify_locations(*ctx,ca,NULL)==1,"CA");SSL_CTX_set_verify(*ctx,SSL_VERIFY_PEER,NULL);}
    SSL *ssl=SSL_new(*ctx);check(ssl!=NULL,"connection");
    BIO *bio=BIO_new_dgram(fd,BIO_NOCLOSE);check(bio!=NULL,"BIO");
    check(BIO_ctrl(bio,BIO_CTRL_DGRAM_SET_CONNECTED,0,peer)>0,"BIO peer");SSL_set_bio(ssl,bio,bio);
    check(SSL_set_mtu(ssl,1200)>0,"MTU");if(!server)check(SSL_set1_host(ssl,"localhost")==1,"hostname");
#endif
    return ssl;
}

struct receiver {
    SSL *ssl;
    int count,oneway,received,duplicate,reorder,fd;
    unsigned char *seen;
    atomic_int done;
    double last;
};
static void *receive_loop(void *arg) {
    struct receiver *r=arg;unsigned char buf[1024];int highest=-1;
    if(!r->oneway){for(int i=0;i<r->count;i++){receive_record(r->ssl,buf,0);check(memcmp(buf,payload,1024)==0,"echo payload");send_record(r->ssl,buf);}return NULL;}
    for(;;){
        if(!receive_record(r->ssl,buf,1)){
            struct pollfd wait={.fd=r->fd,.events=POLLIN};int ready=poll(&wait,1,250);
            if(ready<0&&errno==EINTR)continue;check(ready>=0,"poll");
            if(ready==0&&atomic_load(&r->done))break;continue;
        }
        uint64_t seq=0;for(int i=0;i<8;i++)seq=(seq<<8)|buf[i];
        check(seq<(uint64_t)r->count&&memcmp(buf+8,payload+8,1016)==0,"datagram payload");
        if(r->seen[seq]){r->duplicate++;continue;}r->seen[seq]=1;r->received++;r->last=now();
        if((int)seq<highest)r->reorder++;if((int)seq>highest)highest=(int)seq;
    }
    return NULL;
}

int main(int argc,char **argv) {
    check(argc==7,"usage: reference cert key CA rr|oneway count warmup");
    int count=atoi(argv[5]),warmup=atoi(argv[6]);check(count>0&&warmup>=0,"counts");
    check(strcmp(argv[4],"rr")==0||strcmp(argv[4],"oneway")==0,"mode");
#ifdef USE_WOLFSSL
    check(wolfSSL_Init()==1,"init");
#endif
    struct sockaddr_in ca,sa;int cf=udp(&ca),sf=udp(&sa);
    check(connect(cf,(struct sockaddr*)&sa,sizeof(sa))==0&&connect(sf,(struct sockaddr*)&ca,sizeof(ca))==0,"connect UDP");
    SSL_CTX *cc,*sc;SSL *client=connection(0,cf,&sa,argv[1],argv[2],argv[3],&cc),*server=connection(1,sf,&ca,argv[1],argv[2],argv[3],&sc);
    pthread_t thread;check(pthread_create(&thread,NULL,accept_peer,server)==0,"accept thread");check(SSL_connect(client)==1,"handshake");check(pthread_join(thread,NULL)==0,"join handshake");
#ifdef USE_WOLFSSL
    fprintf(stderr,"negotiated %s %s %s\n",wolfSSL_get_version(client),wolfSSL_get_cipher(client),wolfSSL_get_curve_name(client));
    check(strstr(wolfSSL_get_version(client),"1.3")!=NULL,"negotiated version");
#else
    fprintf(stderr,"negotiated %s %s %s\n",SSL_get_version(client),SSL_get_cipher(client),SSL_group_to_name(client,SSL_get_negotiated_group(client)));
    check(SSL_version(client)==DTLS1_3_VERSION,"negotiated version");
#endif
    for(int i=0;i<1024;i++)payload[i]=(unsigned char)i;
    unsigned char reply[1024];for(int i=0;i<warmup;i++){send_record(client,payload);receive_record(server,reply,0);send_record(server,reply);receive_record(client,reply,0);check(memcmp(reply,payload,1024)==0,"warmup echo");}
    struct timeval no_timeout={0,0};check(setsockopt(sf,SOL_SOCKET,SO_RCVTIMEO,&no_timeout,sizeof(no_timeout))==0,"clear receive timeout");check(setsockopt(cf,SOL_SOCKET,SO_RCVTIMEO,&no_timeout,sizeof(no_timeout))==0,"clear client timeout");alarm(120);
    struct receiver r={.ssl=server,.count=count,.fd=sf,.oneway=strcmp(argv[4],"oneway")==0};atomic_init(&r.done,0);
    if(r.oneway){
        r.seen=calloc((size_t)count,1);check(r.seen!=NULL,"sequence tracking");
        check(fcntl(sf,F_SETFL,fcntl(sf,F_GETFL,0)|O_NONBLOCK)==0,"nonblocking receiver");
#ifdef USE_WOLFSSL
        wolfSSL_set_using_nonblock(server,1);
#endif
    }
    check(pthread_create(&thread,NULL,receive_loop,&r)==0,"receiver thread");
    double start=now();for(int i=0;i<count;i++){
        timed_index=i;
        if(r.oneway){uint64_t seq=(uint64_t)i;for(int j=7;j>=0;j--){payload[j]=(unsigned char)seq;seq>>=8;}}
        send_record(client,payload);if(!r.oneway){receive_record(client,reply,0);check(memcmp(reply,payload,1024)==0,"echo payload");}
    }
    double elapsed=now()-start;atomic_store(&r.done,1);check(pthread_join(thread,NULL)==0,"join receiver");
    printf("{\"library\":\"%s\",\"mode\":\"%s\",\"n\":%d,\"frame_bytes\":1024,\"mtu\":1200,\"version\":\"DTLS 1.3\",\"cipher\":\"TLS_AES_128_GCM_SHA256\",\"group\":\"X25519\",\"cid\":false,",LIBRARY,argv[4],count);
    if(r.oneway){check(r.received>0,"received data");double delivered=elapsed;if(r.last-start>delivered)delivered=r.last-start;
        printf("\"elapsed_s\":%.9f,\"send_mib_s\":%.9f,\"receive_mib_s\":%.9f,\"loss_pct\":%.9f,\"received\":%d,\"duplicate\":%d,\"reorder\":%d}\n",delivered,count/1024.0/elapsed,r.received/1024.0/delivered,100.0*(count-r.received)/count,r.received,r.duplicate,r.reorder);
    }else printf("\"elapsed_s\":%.9f,\"rtt_us\":%.9f,\"request_mib_s\":%.9f}\n",elapsed,elapsed*1e6/count,count/1024.0/elapsed);
    free(r.seen);SSL_free(client);SSL_free(server);SSL_CTX_free(cc);SSL_CTX_free(sc);close(cf);close(sf);return 0;
}
