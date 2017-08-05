// ©.
// https://github.com/sizet/ssl_example

#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>




#define DMSG(msg_fmt, msg_args...) \
    printf("%s(%04u): " msg_fmt "\n", __FILE__, __LINE__, ##msg_args)

#define SSL_FILL_EMSG(msg_buf) ERR_error_string_n(ERR_get_error(), msg_buf, sizeof(msg_buf))
#define SSL_FILL_IO_EMSG(ssl_fd, msg_buf) \
    ERR_error_string_n(SSL_get_error(ssl_fd), msg_buf, sizeof(msg_buf))




int shutdown_process = 0;
char *server_key_passphrase = NULL;
char ssl_ebuf[128];




void signal_handle(
    int signal_value)
{
    switch(signal_value)
    {
        case SIGINT:
        case SIGQUIT:
        case SIGTERM:
            shutdown_process = 1;
            break;
    }

    return;
}

int ssl_init(
    SSL_CTX **ssl_ctx_buf)
{
    const SSL_METHOD *ssl_method;
    SSL_CTX *ssl_ctx;


    // SSL 函式庫初始化.
    SSL_library_init();
    // 載入 SSL 錯誤訊息.
    SSL_load_error_strings();
    // 載入 SSL 演算法.
    OpenSSL_add_all_algorithms();

    // 指定使用 TLSv1 協定.
#if OPENSSL_VERSION_NUMBER >= 0x10002000
    ssl_method = TLSv1_2_server_method();
#else
    ssl_method = TLSv1_server_method();
#endif
    if(ssl_method == NULL)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_CTX_new(TLSv1_server_method()) fail [%s]", ssl_ebuf);
        goto FREE_01;
    }

    // 建立 CTX 物件.
    ssl_ctx = SSL_CTX_new(ssl_method);
    if(ssl_ctx == NULL)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_CTX_new(TLSv1_server_method()) fail [%s]", ssl_ebuf);
        goto FREE_01;
    }

    // 此函式非必要, 設定使用的加密演算法的優先權.
    // 使用方法 https://linux.die.net/man/3/ssl_ctx_set_cipher_list
    if(SSL_CTX_set_cipher_list(ssl_ctx, "DEFAULT") != 1)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_CTX_new(TLSv1_server_method()) fail [%s]", ssl_ebuf);
        goto FREE_02;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10002000
    // ECDH 相關, OpenSSL 1.0.2 以上才支援.
    if(SSL_CTX_set_ecdh_auto(ssl_ctx, 1) != 1)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_CTX_set_ecdh_auto() fail [%s]", ssl_ebuf);
        goto FREE_02;
    }
#endif

    *ssl_ctx_buf = ssl_ctx;

    return 0;
FREE_02:
    SSL_CTX_free(ssl_ctx);
FREE_01:
    return -1;
}

int ssl_set_key_passphrase(
    char *buf,
    int size,
    int rwflag,
    void *userdata)
{
    return snprintf(buf, size, "%s", server_key_passphrase);
}

int ssl_load_pem(
    SSL_CTX *ssl_ctx,
    char *server_passphrase,
    char *server_key_path,
    char *server_cert_path,
    char *server_chain_path)
{
    // 設定伺服器的私鑰的密碼.
    // 如果沒有使用 SSL_CTX_set_default_passwd_cb() 設定則會要求手動輸入.
    if(server_passphrase != NULL)
        SSL_CTX_set_default_passwd_cb(ssl_ctx, ssl_set_key_passphrase);

    // 載入伺服器的私鑰 (PEM 格式).
    if(SSL_CTX_use_PrivateKey_file(ssl_ctx, server_key_path, SSL_FILETYPE_PEM) != 1)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_CTX_use_PrivateKey_file(%s) fail [%s]", server_key_path, ssl_ebuf);
        return -1;
    }

    // 載入伺服器的憑證 (PEM 格式).
    if(SSL_CTX_use_certificate_file(ssl_ctx, server_cert_path, SSL_FILETYPE_PEM) != 1)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_CTX_use_certificate_file(%s) fail [%s]", server_cert_path, ssl_ebuf);
        return -1;
    }

    // 檢查伺服器的私鑰和憑證是否批配.
    if(SSL_CTX_check_private_key(ssl_ctx) != 1)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_CTX_check_private_key() fail [%s]", ssl_ebuf);
        return -1;
    }

    // 載入伺服器的憑證串鍊 (PEM 格式), 伺服器端要提供憑證串鍊讓客戶端做驗證.
    // 憑證串鍊的內容就是把伺服器憑證和中繼憑證合併成單一憑證,
    // 憑證串鍊內如必須依照 伺服器憑證 -> 中繼憑證-1 -> .. -> 中繼憑證-N 的順序記錄,
    //
    // 以 www.google.com 為例 :
    // www.google.com 的憑證簽發順序是 (上到下),
    // Equifax Secure Certificate Authority,
    //   GeoTrust Global CA,
    //     Google Internet Authority G2,
    //       www.google.com
    // 憑證串鍊內如必須紀錄除了根憑證 (Equifax Secure Certificate Authority) 之外的憑證,
    // 憑證串鍊檔案內容會像 :
    // -----BEGIN CERTIFICATE-----
    // www.google.com 的憑證內容.
    // -----END CERTIFICATE-----
    // -----BEGIN CERTIFICATE-----
    // Google Internet Authority G2 的憑證內容.
    // -----END CERTIFICATE-----
    // -----BEGIN CERTIFICATE-----
    // GeoTrust Global CA 的憑證內容.
    // -----END CERTIFICATE-----
    if(SSL_CTX_use_certificate_chain_file(ssl_ctx, server_chain_path) != 1)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_CTX_use_certificate_chain_file(%s) fail [%s]",
             server_chain_path, ssl_ebuf);
        return -1;
    }

    return 0;
}

int ssl_socket_init(
    struct sockaddr_in *local_addr,
    socklen_t addr_len,    
    int *sock_fd_buf)
{
    int sock_fd;


    // 建立 socket.
    sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock_fd == -1)
    {
        DMSG("call socket() fail [%s]", strerror(errno));
        return -1;
    }

    // 綁定服務位址.
    if(bind(sock_fd, (struct sockaddr *) local_addr, addr_len) == -1)
    {
        DMSG("call bind() fail [%s]", strerror(errno));
        return -1;
    }

    // 監聽客戶端連線.
    if(listen(sock_fd, 4) == -1)
    {
        DMSG("call listen() fail [%s]", strerror(errno));
        return -1;
    }

    *sock_fd_buf = sock_fd;

    return 0;
}

int ssl_socket_accept(
    int sock_fd,
    SSL_CTX *ssl_ctx,
    socklen_t addr_len,
    int *sock_rfd_buf,
    struct sockaddr_in *remote_addr_buf,
    SSL **ssl_session_buf)
{
    fd_set fdset_fd;
    socklen_t alen = addr_len;
    struct sockaddr_in remote_addr;
    int sock_rfd;
    SSL *ssl_session;


    FD_ZERO(&fdset_fd);
    FD_SET(sock_fd, &fdset_fd);

    // 等待客戶端連線.
    if(select(sock_fd + 1, &fdset_fd, NULL, NULL, NULL) == -1)
    {
        DMSG("call select() fail [%s]", strerror(errno));
        goto FREE_01;
    }

    if(FD_ISSET(sock_fd, &fdset_fd) == 0)
    {
        DMSG("call FD_ISSET() return nothing");
        goto FREE_01;
    }

    // 接收客戶端連線.
    sock_rfd = accept(sock_fd, (struct sockaddr *) &remote_addr, &alen);
    if(sock_rfd == -1)
    {
        DMSG("call accept() fail [%s]", strerror(errno));
        goto FREE_01;
    }

    // 基於 ctx 產生新的 SSL.
    ssl_session = SSL_new(ssl_ctx);
    if(ssl_session == NULL)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_new() fail [%s]", ssl_ebuf);
        goto FREE_02;
    }

    // 指定 SSL 連線使用的 socket.
    if(SSL_set_fd(ssl_session, sock_rfd) != 1)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_set_fd() fail [%s]", ssl_ebuf);
        goto FREE_03;
    }

    // 建立 SSL 連線.
    if(SSL_accept(ssl_session) == -1)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_accept() fail [%s]", ssl_ebuf);
        goto FREE_03;
    }

    *sock_rfd_buf = sock_rfd;
    memcpy(remote_addr_buf, &remote_addr, addr_len);
    *ssl_session_buf = ssl_session;

    return 0;
FREE_03:
    SSL_free(ssl_session);
FREE_02:
    close(sock_rfd);
FREE_01:
    return -1;
}

int ssl_show_info(
    struct sockaddr_in *remote_addr,
    SSL *ssl_session)
{
    X509 *cert_data;
    char data_buf[256];


    DMSG("");

    // 顯示客戶端的位址.
    DMSG("client :");
    DMSG("%s:%u", inet_ntop(AF_INET, &remote_addr->sin_addr, data_buf, sizeof(data_buf)),
         ntohs(remote_addr->sin_port));

    // 顯示連線的 SSL 版本.
    DMSG("version :");
    DMSG("%s", SSL_get_cipher_version(ssl_session));

    // 顯示使用的加密方式.
    DMSG("cipher :");
    DMSG("%s", SSL_get_cipher_name(ssl_session));

    // 取出對方的憑證.
    cert_data = SSL_get_peer_certificate(ssl_session);
    DMSG("client certificate :");
    if(cert_data != NULL)
    {
        // 取出憑證的主旨.
        X509_NAME_oneline(X509_get_subject_name(cert_data), data_buf, sizeof(data_buf));
        DMSG("subject : %s", data_buf);
        // 取出憑證的簽發者.
        X509_NAME_oneline(X509_get_issuer_name(cert_data), data_buf, sizeof(data_buf));
        DMSG("issuer  : %s", data_buf);
    }
    else
    {
        DMSG("no certificate");
    }

    return 0;
}

int ssl_socket_send(
    SSL *ssl_session,
    void *data_con,
    unsigned int data_len)
{
    int slen;


    slen = SSL_write(ssl_session, data_con, data_len);
    if(slen <= 0)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_write() fail [%s]", ssl_ebuf);
        return -1;
    }

    return slen;
}

int ssl_socket_recv(
    SSL *ssl_session,
    void *data_buf,
    unsigned int buf_size)
{
    int rlen;


    rlen = SSL_read(ssl_session, data_buf, buf_size);
    if(rlen <= 0)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_read() fail [%s]", ssl_ebuf);
        return -1;
    }

    return rlen;
}

int main(
    int argc,
    char **argv)
{
    int fret = -1;
    char opt_ch, *server_key_path = NULL, *server_cert_path = NULL, *server_chain_path = NULL;
    char data_buf[256];
    int sock_fd, sock_rfd;
    SSL_CTX *ssl_ctx;
    SSL *ssl_session;
    struct in_addr naddr;
    struct sockaddr_in local_addr, remote_addr;


    while((opt_ch = getopt(argc , argv, "p:k:c:l:"))!= -1)
        switch(opt_ch)
        {
            case 'p':
                server_key_passphrase = optarg;
                break;
            case 'k':
                server_key_path = optarg;
                break;
            case 'c':
                server_cert_path = optarg;
                break;
            case 'l':
                server_chain_path = optarg;
                break;
            default:
                goto FREE_HELP;
        }

    if(server_key_passphrase == NULL)
        goto FREE_HELP;
    if(server_key_path == NULL)
        goto FREE_HELP;
    if(server_cert_path == NULL)
        goto FREE_HELP;
    if(server_chain_path == NULL)
        goto FREE_HELP;

    signal(SIGINT, signal_handle);
    signal(SIGQUIT, signal_handle);
    signal(SIGTERM, signal_handle);

    // 初始化 SSL 資料.
    if(ssl_init(&ssl_ctx) < 0)
    {
        DMSG("call ssl_init() fail");
        goto FREE_01;
    }

    // 載入伺服器的憑證串鍊, 私鑰, 憑證.
    if(ssl_load_pem(ssl_ctx, server_key_passphrase, server_key_path, server_cert_path,
                    server_chain_path) < 0)
    {
        DMSG("call ssl_load_pem() fail");
        goto FREE_02;
    }

    // 設定伺服器服務的位址.
    if(inet_pton(AF_INET, "127.0.0.1", &naddr) != 1)
    {
        DMSG("call inet_pton() fail [%s]", strerror(errno));
        goto FREE_02;
    }
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = naddr.s_addr;
    local_addr.sin_port = htons(443);

    // socket 初始化並監聽連線.
    if(ssl_socket_init(&local_addr, sizeof(local_addr), &sock_fd) < 0)
    {
        DMSG("call ssl_socket_init() fail");
        goto FREE_02;
    }

    DMSG("listen connect");
    while(shutdown_process == 0)
    {
        // 接收連線.
        fret = ssl_socket_accept(sock_fd, ssl_ctx, sizeof(remote_addr),
                                 &sock_rfd, &remote_addr, &ssl_session);
        if(fret < 0)
        {
            DMSG("call ssl_socket_accept() fail");
            goto FREE_02;
        }

        // 顯示 SSL 的連線和憑證等資訊.
        ssl_show_info(&remote_addr, ssl_session);

        // 接收資料.
        if(ssl_socket_recv(ssl_session, data_buf, sizeof(data_buf)) < 0)
        {
            DMSG("call ssl_socket_recv() fail");
            shutdown_process = 1;
            goto FREE_SESSION;
        }
        DMSG("recv : %s", data_buf);

        // 傳送資料.
        snprintf(data_buf, sizeof(data_buf), "hellow, i am server");
        DMSG("send : %s", data_buf);
        if(ssl_socket_send(ssl_session, data_buf, strlen(data_buf)) < 0)
        {
            DMSG("call ssl_socket_send() fail");
            shutdown_process = 1;
            goto FREE_SESSION;
        }

FREE_SESSION:
        DMSG("close connect");
        SSL_shutdown(ssl_session);
        SSL_free(ssl_session);
        close(sock_rfd);
    }

FREE_02:
    SSL_CTX_free(ssl_ctx);
FREE_01:
    return 0;
FREE_HELP:
    printf("\ntls_one_way_server <-p> <-k> <-c> <-l>\n");
    printf("  -p : server private key pass phrase\n");
    printf("       ex : -p john123\n");
    printf("  -k : server private key path\n");
    printf("       ex : -k ../pem/server/server.key.pem\n");
    printf("  -c : server certificate path\n");
    printf("       ex : -c ../pem/server/server.cert.pem\n");
    printf("  -l : server certificate chain path\n");
    printf("       ex : -l ../pem/server/server_chain.cert.pem\n\n");
    return 0;
}
