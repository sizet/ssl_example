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
#define SSL_FILL_IO_EMSG(ssl_session, msg_buf) \
    ERR_error_string_n(SSL_get_error(ssl_session), msg_buf, sizeof(msg_buf))




char *client_key_passphrase = NULL;
char ssl_ebuf[128];




void signal_handle(
    int signal_value)
{
    switch(signal_value)
    {
        case SIGINT:
        case SIGQUIT:
        case SIGTERM:
            exit(0);
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
    ssl_method = TLSv1_2_client_method();
#else
    ssl_method = TLSv1_client_method();
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
    return snprintf(buf, size, "%s", client_key_passphrase);
}

// 驗證伺服器的憑證的函式.
// 憑證的檢查順序是 根憑證 -> 中繼憑證 -> ... -> 客戶端憑證, 每個憑證都會呼叫驗證函式.
// preverify_ok :
//   OpenSSL 在呼叫此函式之前會先對憑證做基本檢查, 這邊會紀錄檢查結果.
//   0 = 憑證錯誤.
//   1 = 憑證正確.
int ssl_verify_cert(
    int preverify_ok,
    X509_STORE_CTX *x509_ctx)
{
    X509 *cert_data;
    int err_code, cert_depth;
    char data_buf[256];
    const char *err_msg;


    // 哪一層的憑證.
    cert_depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    // 錯誤的原因.
    err_code = X509_STORE_CTX_get_error(x509_ctx);

    DMSG("verify client certificate, depth = %d :", cert_depth);

    cert_data = X509_STORE_CTX_get_current_cert(x509_ctx);
    // 取出憑證的主旨.
    X509_NAME_oneline(X509_get_subject_name(cert_data), data_buf, sizeof(data_buf));
    DMSG("subject : %s", data_buf);
    // 取出憑證的簽發者.
    X509_NAME_oneline(X509_get_issuer_name(cert_data), data_buf, sizeof(data_buf));
    DMSG("issuer  : %s", data_buf);

    if(preverify_ok == 0)
    {
        // 憑證錯誤.

        // 錯誤的文字說明.
        err_msg = X509_verify_cert_error_string(err_code);
        DMSG("invalid, %s", err_msg);

        // 設定錯誤原因.
        X509_STORE_CTX_set_error(x509_ctx, err_code);
    }
    else
    {
        // 憑證正確.

        // 可以對憑證作其他額外的檢查,
        // 如果要拒絕此憑證要使用 X509_STORE_CTX_set_error() 設定原因, 並回傳 0 (參考下面說明),
        // 可以設定的值參考 https://linux.die.net/man/3/x509_store_ctx_set_error
    }

    // 回傳值會影響 SSL_connect/SSL_accept 的結果,
    // 0 = 驗證結果錯誤, OpenSSL 會中斷憑證串鍊的驗證並使 SSL_connect/SSL_accept 回傳錯誤.
    // 1 = 驗證結果正確, OpenSSL 會繼續憑證串鍊的驗證.
    return preverify_ok;
}

int ssl_load_pem(
    SSL_CTX *ssl_ctx,
    char *client_passphrase,
    char *client_key_path,
    char *client_cert_path,
    char *client_chain_path,
    char *server_root_ca_path)
{
    // 設定客戶端的私鑰的密碼.
    // 如果沒有使用 SSL_CTX_set_default_passwd_cb() 設定則會要求手動輸入.
    if(client_passphrase != NULL)
        SSL_CTX_set_default_passwd_cb(ssl_ctx, ssl_set_key_passphrase);

    // 載入客戶端的私鑰 (PEM 格式).
    if(SSL_CTX_use_PrivateKey_file(ssl_ctx, client_key_path, SSL_FILETYPE_PEM) != 1)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_CTX_use_PrivateKey_file(%s) fail [%s]", client_key_path, ssl_ebuf);
        return -1;
    }

    // 載入客戶端的憑證 (PEM 格式).
    if(SSL_CTX_use_certificate_file(ssl_ctx, client_cert_path, SSL_FILETYPE_PEM) != 1)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_CTX_use_certificate_file(%s) fail [%s]", client_cert_path, ssl_ebuf);
        return -1;
    }

    // 載入客戶端的憑證串鍊 (PEM 格式), 客戶端端要提供憑證串鍊讓伺服器做驗證.
    if(SSL_CTX_use_certificate_chain_file(ssl_ctx, client_chain_path) != 1)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_CTX_use_certificate_chain_file(%s) fail [%s]",
             client_chain_path, ssl_ebuf);
        return -1;
    }

    if(server_root_ca_path != NULL)
    {
        // 客戶端是否驗證伺服器的憑證.
        // 參數 2 表示驗證模式,
        //   SSL_VERIFY_NONE = 不驗證, 客戶端預設值.
        //   SSL_VERIFY_PEER = 要驗證.
        // 參數 3 表示額外的驗證函式,
        //   NULL = 使用 OpenSSL 內建的驗證函式.
        //   函式 = 指定的額外驗證函式.
        // 使用 SSL_connect/SSL_accept 取得對方憑證後會呼叫指定的額外驗證函式處理.
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, ssl_verify_cert);

        // 載入伺服器的憑證的根憑證做驗證.
        if(SSL_CTX_load_verify_locations(ssl_ctx, server_root_ca_path, NULL) != 1)
        {
            SSL_FILL_EMSG(ssl_ebuf);
            DMSG("call SSL_CTX_load_verify_locations(%s) fail [%s]",
                 server_root_ca_path, ssl_ebuf);
            return -1;
        }
    }

    return 0;
}

int ssl_socket_init(
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

    *sock_fd_buf = sock_fd;

    return 0;
}

int ssl_socket_connect(
    int sock_fd,
    SSL_CTX *ssl_ctx,
    struct sockaddr_in *remote_addr,
    socklen_t addr_len,
    SSL **ssl_session_buf)
{
    int cret;
    SSL *ssl_session;


    // 連線.
    if(connect(sock_fd, (struct sockaddr *) remote_addr, addr_len) == -1)
    {
        DMSG("call connect() fail [%s]", strerror(errno));
        goto FREE_01;
    }

    // 基於 CTX 產生新的 SSL 連線.
    ssl_session = SSL_new(ssl_ctx);
    if(ssl_session == NULL)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_new() fail [%s]", ssl_ebuf);
        goto FREE_01;
    }

    // 指定 SSL 連線使用的 socket.
    if(SSL_set_fd(ssl_session, sock_fd) != 1)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_set_fd() fail [%s]", ssl_ebuf);
        goto FREE_02;
    }

    // 建立 SSL 連線.
    if(SSL_connect(ssl_session) == -1)
    {
        SSL_FILL_EMSG(ssl_ebuf);
        DMSG("call SSL_connect() fail [%s]", ssl_ebuf);
        cret = SSL_get_verify_result(ssl_session);
        if(cret != X509_V_OK)
        {
            DMSG("invalid certificate, %s", X509_verify_cert_error_string(cret));
        }
        goto FREE_02;
    }

    *ssl_session_buf = ssl_session;

    return 0;
FREE_02:
    SSL_free(ssl_session);
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

    // 顯示伺服器的位址.
    DMSG("server :");
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
    DMSG("server certificate :");
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
    int sock_fd;
    char opt_ch, *client_key_path = NULL, *client_cert_path = NULL, *client_chain_path = NULL,
        *server_root_ca_path = NULL, data_buf[256];
    SSL_CTX *ssl_ctx;
    SSL *ssl_session;
    struct in_addr naddr;
    struct sockaddr_in remote_addr;


    while((opt_ch = getopt(argc , argv, "p:k:c:l:r:"))!= -1)
        switch(opt_ch)
        {
            case 'p':
                client_key_passphrase = optarg;
                break;
            case 'k':
                client_key_path = optarg;
                break;
            case 'c':
                client_cert_path = optarg;
                break;
            case 'l':
                client_chain_path = optarg;
                break;
            case 'r':
                server_root_ca_path = optarg;
                break;
            default:
                goto FREE_HELP;
        }

    if(client_key_passphrase == NULL)
        goto FREE_HELP;
    if(client_key_path == NULL)
        goto FREE_HELP;
    if(client_cert_path == NULL)
        goto FREE_HELP;
    if(client_chain_path == NULL)
        goto FREE_HELP;
    if(server_root_ca_path == NULL)
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

    // 載入伺服器的根憑證, 需要驗證伺服器的憑證才需要.
    if(ssl_load_pem(ssl_ctx, client_key_passphrase, client_key_path, client_cert_path,
                    client_chain_path, server_root_ca_path) < 0)
    {
        DMSG("call ssl_load_pem() fail");
        goto FREE_02;
    }

    // socket 初始化.
    if(ssl_socket_init(&sock_fd) < 0)
    {
        DMSG("call ssl_socket_init() fail");
        goto FREE_02;
    }

    // 設定伺服器的位址.
    if(inet_pton(AF_INET, "127.0.0.1", &naddr) != 1)
    {
        DMSG("call inet_pton() fail [%s]", strerror(errno));
        goto FREE_02;
    }
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = naddr.s_addr;
    remote_addr.sin_port = htons(443);

    // 連線.
    if(ssl_socket_connect(sock_fd, ssl_ctx, &remote_addr, sizeof(remote_addr), &ssl_session) < 0)
    {
        DMSG("call ssl_socket_connect() fail");
        goto FREE_03;
    }

    // 顯示 SSL 的連線和憑證等資訊.
    ssl_show_info(&remote_addr, ssl_session);

    // 傳送資料.
    snprintf(data_buf, sizeof(data_buf), "hellow, i am client");
    DMSG("send : %s", data_buf);
    if(ssl_socket_send(ssl_session, data_buf, strlen(data_buf)) < 0)
    {
        DMSG("call ssl_socket_send() fail");
        goto FREE_03;
    }

    // 接收資料.
    if(ssl_socket_recv(ssl_session, data_buf, sizeof(data_buf)) < 0)
    {
        DMSG("call ssl_socket_recv() fail");
        goto FREE_03;
    }
    DMSG("recv : %s", data_buf);

    // 關閉 SSL 連線.
    SSL_shutdown(ssl_session);

    SSL_free(ssl_session);
FREE_03:
    close(sock_fd);
FREE_02:
    SSL_CTX_free(ssl_ctx);
FREE_01:
    return 0;
FREE_HELP:
    printf("\ntls_two_way_client <-p> <-k> <-c> <-l> <-r>\n");
    printf("  -p : client private key pass phrase\n");
    printf("       ex : -p helen123\n");
    printf("  -k : client private key path\n");
    printf("       ex : -k ../pem/client/client.key.pem\n");
    printf("  -c : client certificate path\n");
    printf("       ex : -c ../pem/client/client.cert.pem\n");
    printf("  -l : client certificate chain path\n");
    printf("       ex : -l ../pem/client/client_chain.cert.pem\n");
    printf("  -r : server root CA certificate path\n");
    printf("       ex : -r ../pem/server/root_ca.cert.pem\n");
    return 0;
}
