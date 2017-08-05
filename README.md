**`doc/index.html`**  
如何建立根憑證, 中繼憑證, 終端憑證 (伺服器, 客戶端).

**`pem`**  
程式測試用憑證, 含私鑰, 憑證, 憑證串鍊, 根憑證.

**`tls_one_way/tls_one_way_server.c`**  
單向認證的伺服器程式.
```bash
參數 :
tls_one_way_server
<-p 伺服器私鑰的密碼>
<-k 伺服器私鑰的路徑>
<-c 伺服器憑證的路徑>
<-l 伺服器憑證串鍊的路徑>
範例 :
./tls_one_way_server -p john123 -k ../pem/server/server.key.pem -c ../pem/server/server.cert.pem -l ../pem/server/server_chain.cert.pem
```

**`tls_one_way/tls_one_way_client.c`**  
單向認證的客戶端程式.
```bash
參數 :
tls_one_way_client
<-r 伺服器憑證的根憑證的路徑>
範例 :
./tls_one_way_client -r ../pem/server/root_ca.cert.pem
```

**`tls_two_way/tls_two_way_server.c`**  
雙向認證的伺服器程式.
```bash
參數 :
tls_two_way_server
<-p 伺服器私鑰的密碼>
<-k 伺服器私鑰的路徑>
<-c 伺服器憑證的路徑>
<-l 伺服器憑證串鍊的路徑>
<-r 客戶端憑證的根憑證的路徑>
範例 :
./tls_two_way_server -p john123 -k ../pem/server/server.key.pem -c ../pem/server/server.cert.pem -l ../pem/server/server_chain.cert.pem -r ../pem/client/root_ca.cert.pem
```

**`tls_two_way/tls_two_way_client.c`**  
雙向認證的客戶端程式.
```bash
參數 :
tls_two_way_client
<-p 客戶端私鑰的密碼>
<-k 客戶端私鑰的路徑>
<-c 客戶端憑證的路徑>
<-l 客戶端憑證串鍊的路徑>
<-r 伺服器憑證的根憑證的路徑>
範例 :
./tls_two_way_client -p helen123 -k ../pem/client/client.key.pem -c ../pem/client/client.cert.pem -l ../pem/client/client_chain.cert.pem -r ../pem/server/root_ca.cert.pem
```
