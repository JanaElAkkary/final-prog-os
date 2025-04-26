#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>


#define PORT 8080
#define BUFFER_SIZE 1024
struct client_args {
    int socket;
    SSL_CTX *ctx;
};

void print_server_banner() {
    printf("\033[38;5;206m");  // Start pink
    printf("\n");
    printf("╔════════════════════════════════════╗\n");
    printf("║        JA HOLDING SERVER           ║\n");
    printf("╠════════════════════════════════════╣\n");
    printf("║  AES-128-CBC Encryption Enabled    ║\n");
    printf("║  SSL Protocol Active               ║\n");
    printf("║  Multithreading: ON                ║\n");
    printf("║  Listening on port %-5d           ║\n", PORT);
    printf("╚════════════════════════════════════╝\n\n");
    // printf("\033[0m");     // Reset color
}


void aes_decrypt(const unsigned char *ciphertext, unsigned char *plaintext, int ciphertext_len,
    const unsigned char *key, const unsigned char *iv) {
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
int len;
int plaintext_len;

EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
plaintext_len = len;

EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
plaintext_len += len;
plaintext[plaintext_len] = '\0';

EVP_CIPHER_CTX_free(ctx);
}
struct User {
    char username[50];
    char role[20];
};

// Authenticate against users.txt
int authenticate(const char *user, const char *pass, char *out_role) {
    FILE *fp = fopen("users.txt", "r");
    if (!fp) {
        perror("[ERROR] Could not open users.txt");
        return 0;
    }

    char stored_user[50], stored_pass[50], stored_role[20];
    while (fscanf(fp, "%s %s %s", stored_user, stored_pass, stored_role) == 3) {
        if (strcmp(user, stored_user) == 0 && strcmp(pass, stored_pass) == 0) {
            strcpy(out_role, stored_role);
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}
void deliver_messages(const char *username, SSL *ssl, unsigned char *key, unsigned char *iv) {
    char path[100];
    snprintf(path, sizeof(path), "messages/%s.txt", username);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        int zero = 0;
        SSL_write(ssl, &zero, sizeof(int));  // No messages
        return;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    if (fsize <= 0) {
        fclose(fp);
        int zero = 0;
        SSL_write(ssl, &zero, sizeof(int));  // No messages
        return;
    }

    char *msg_buf = malloc(fsize + 1);
    fread(msg_buf, 1, fsize, fp);
    msg_buf[fsize] = '\0';
    fclose(fp);
    remove(path);  // clear messages after reading

    unsigned char enc_msg[BUFFER_SIZE * 2];
    int enc_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, enc_msg, &len, (unsigned char *)msg_buf, fsize);
    enc_len = len;
    EVP_EncryptFinal_ex(ctx, enc_msg + len, &len);
    enc_len += len;
    EVP_CIPHER_CTX_free(ctx);

    SSL_write(ssl, &enc_len, sizeof(int));
    SSL_write(ssl, enc_msg, enc_len);
    free(msg_buf);
}
#include <dirent.h>

void handle_ls_request(SSL *ssl, const unsigned char *key, const unsigned char *iv) {
    DIR *d;
    struct dirent *dir;
    d = opendir("server_files");
    if (!d) {
        SSL_write(ssl, "Unable to open server_files directory", 37);
        return;
    }

    char file_list[BUFFER_SIZE] = {0};
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_REG) {  // Only regular files
            strcat(file_list, dir->d_name);
            strcat(file_list, "\n");
        }
    }
    closedir(d);

    unsigned char enc_buf[BUFFER_SIZE];
    int enc_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, enc_buf, &len, (unsigned char *)file_list, strlen(file_list));
    enc_len = len;
    EVP_EncryptFinal_ex(ctx, enc_buf + len, &len);
    enc_len += len;
    EVP_CIPHER_CTX_free(ctx);

    SSL_write(ssl, &enc_len, sizeof(int));
    SSL_write(ssl, enc_buf, enc_len);
}




// Threaded client handler

void *handle_client(void *arg) {
    printf("================================NEW CLIENT================================\n");
    struct client_args *args = (struct client_args *)arg;
    int client_socket = args->socket;
    SSL_CTX *ctx = args->ctx;
    free(args);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(client_socket);
        pthread_exit(NULL);
    }
    
    unsigned char aes_key[16], aes_iv[16];
    SSL_read(ssl, aes_key, 16);
    SSL_read(ssl, aes_iv, 16);
    
    int attempts = 0;
    int authenticated = 0;

    while (attempts < 2 && !authenticated) {

       
        int user_len;
        SSL_read(ssl, &user_len, sizeof(int));
        int enc_user_len = ((user_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        unsigned char enc_user[BUFFER_SIZE], dec_user[BUFFER_SIZE];
        SSL_read(ssl, enc_user, enc_user_len);

        // Print encrypted username (hex)
        printf("Encrypted Username: ");
        for (int i = 0; i < enc_user_len; i++) printf("%02x", enc_user[i]);
        printf("\n");

        aes_decrypt(enc_user, dec_user, enc_user_len, aes_key, aes_iv);
        printf("Decrypted Username: %s\n", dec_user);


        int pass_len;
        SSL_read(ssl, &pass_len, sizeof(int));
        int enc_pass_len = ((pass_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        unsigned char enc_pass[BUFFER_SIZE], dec_pass[BUFFER_SIZE];
        SSL_read(ssl, enc_pass, enc_pass_len);

        // Print encrypted password (hex)
        printf("Encrypted Password: ");
        for (int i = 0; i < enc_pass_len; i++) printf("%02x", enc_pass[i]);
        printf("\n");

        aes_decrypt(enc_pass, dec_pass, enc_pass_len, aes_key, aes_iv);
        printf("Decrypted Password: %s\n", dec_pass);

        char role[20] = {0};
        if (authenticate((char *)dec_user, (char *)dec_pass, role)) {
            authenticated = 1;
            printf("[✔] Authentication successful\n");
            printf("User role: %s\n", role);
            SSL_write(ssl, "Authentication successful", strlen("Authentication successful"));
            SSL_write(ssl, role, strlen(role));  
            deliver_messages((char *)dec_user, ssl, aes_key, aes_iv);
            //==========messaege==============================================
            while (1) {
                int msg_type;
                if (SSL_read(ssl, &msg_type, sizeof(int)) <= 0) break;
                
            
                if (msg_type == 1) {
                    int msg_len;
                    if (SSL_read(ssl, &msg_len, sizeof(int)) <= 0) break;
            
                    int enc_msg_len = ((msg_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
                    unsigned char *enc_msg = malloc(enc_msg_len);
                    unsigned char *dec_msg = calloc(1, enc_msg_len + AES_BLOCK_SIZE);
            
                    int total_received = 0;
                    while (total_received < enc_msg_len) {
                        int r = SSL_read(ssl, enc_msg + total_received, enc_msg_len - total_received);
                        if (r <= 0) break;
                        total_received += r;
                    }
            
                    aes_decrypt(enc_msg, dec_msg, enc_msg_len, aes_key, aes_iv);
                    printf("\033[38;5;206m[Server Received Message]: %s\033[0m\n", dec_msg);
                    SSL_write(ssl, "Message delivered to server", strlen("Message delivered to server"));
            
                    free(enc_msg);
                    free(dec_msg);
                }
            
                else if (msg_type == 2) {
                    char recipient[50];
                    int rec_len, msg_len;
                
                    SSL_read(ssl, &rec_len, sizeof(int));
                    SSL_read(ssl, recipient, rec_len);
                    recipient[rec_len] = '\0';
                
                    SSL_read(ssl, &msg_len, sizeof(int));
                    int enc_msg_len = ((msg_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
                    unsigned char *enc_msg = malloc(enc_msg_len);
                    unsigned char *dec_msg = calloc(1, enc_msg_len + AES_BLOCK_SIZE);
                
                    int total_received = 0;
                    while (total_received < enc_msg_len) {
                        int r = SSL_read(ssl, enc_msg + total_received, enc_msg_len - total_received);
                        if (r <= 0) break;
                        total_received += r;
                    }
                
                    aes_decrypt(enc_msg, dec_msg, enc_msg_len, aes_key, aes_iv);
                
                    char path[100];
                    snprintf(path, sizeof(path), "messages/%s.txt", recipient);
                    FILE *fp = fopen(path, "a");
                    if (fp) {
                        fprintf(fp, "From %s: %s\n", dec_user, dec_msg);
                        fclose(fp);
                        SSL_write(ssl, "Message sent to client", strlen("Message sent to client"));
                    } else {
                        SSL_write(ssl, "Failed to send message: Unable to write to file", strlen("Failed to send message: Unable to write to file"));
                    }
                
                    free(enc_msg);
                    free(dec_msg);
                }
                
                else if (msg_type == 3) {
                    handle_ls_request(ssl, aes_key, aes_iv);

                }
                else if (msg_type == 4) { // Read file
                    int name_len;
                    char filename[256];
                    if (SSL_read(ssl, &name_len, sizeof(int)) <= 0) break;
                    if (SSL_read(ssl, filename, name_len) <= 0) break;
                    filename[name_len] = '\0';
                
                    char path[300];
                    snprintf(path, sizeof(path), "./server_files/%s", filename);
                
                    FILE *fp = fopen(path, "r");
                    if (!fp) {
                        int not_found = -1;
                        SSL_write(ssl, &not_found, sizeof(int));
                        continue;
                    }
                
                    fseek(fp, 0, SEEK_END);
                    long fsize = ftell(fp);
                    rewind(fp);
                
                    char *content = malloc(fsize + 1);
                    fread(content, 1, fsize, fp);
                    content[fsize] = '\0';
                    fclose(fp);
                
                    SSL_write(ssl, &fsize, sizeof(int));
                    SSL_write(ssl, content, fsize);
                    free(content);
                }
                else if (msg_type == 5) { // Edit file
                    int name_len;
                    char filename[256];
                    if (SSL_read(ssl, &name_len, sizeof(int)) <= 0) break;
                    if (SSL_read(ssl, filename, name_len) <= 0) break;
                    filename[name_len] = '\0';
                
                    int content_len;
                    if (SSL_read(ssl, &content_len, sizeof(int)) <= 0) break;
                
                    char content[BUFFER_SIZE];
                    if (SSL_read(ssl, content, content_len) <= 0) break;
                    content[content_len] = '\0';
                
                    char path[300];
                    snprintf(path, sizeof(path), "./server_files/%s", filename);
                    FILE *fp = fopen(path, "a");
                    if (!fp) {
                        SSL_write(ssl, "Failed to open file for editing", strlen("Failed to open file for editing"));
                        continue;
                    }
                
                    fprintf(fp, "%s\n", content);
                    fclose(fp);
                    SSL_write(ssl, "Edit successful", strlen("Edit successful"));
                }
                else if (msg_type == 5) {  // Receive file from client
                    int name_len;
                    char filename[256];
                    SSL_read(ssl, &name_len, sizeof(int));
                    SSL_read(ssl, filename, name_len);
                    filename[name_len] = '\0';
                
                    long fsize;
                    SSL_read(ssl, &fsize, sizeof(long));
                    char *content = malloc(fsize + 1);
                    SSL_read(ssl, content, fsize);
                    content[fsize] = '\0';
                
                    char filepath[512];
                    snprintf(filepath, sizeof(filepath), "./server_files/%s", filename);
                    FILE *fp = fopen(filepath, "w");
                    if (fp) {
                        fwrite(content, 1, fsize, fp);
                        fclose(fp);
                    }
                    free(content);
                }
                else if (msg_type == 6) {  // Send file to client
                    int name_len;
                    char filename[256];
                    SSL_read(ssl, &name_len, sizeof(int));
                    SSL_read(ssl, filename, name_len);
                    filename[name_len] = '\0';
                
                    char filepath[512];
                    snprintf(filepath, sizeof(filepath), "./server_files/%s", filename);
                    FILE *fp = fopen(filepath, "r");
                    if (!fp) {
                        long fail = -1;
                        SSL_write(ssl, &fail, sizeof(long));
                        continue;
                    }
                
                    fseek(fp, 0, SEEK_END);
                    long fsize = ftell(fp);
                    rewind(fp);
                
                    char *content = malloc(fsize + 1);
                    fread(content, 1, fsize, fp);
                    content[fsize] = '\0';
                    fclose(fp);
                
                    SSL_write(ssl, &fsize, sizeof(long));
                    SSL_write(ssl, content, fsize);
                    free(content);
                }
                
                
                
                else if (msg_type == 999) {  // 999 means "exit" sent from client
                    break;
                }
            }
        }
        else {
            attempts++;
            if (attempts < 2) {
                const char *fail_msg = "Wrong username or password. Try again";
                SSL_write(ssl, fail_msg, strlen(fail_msg));
            } else {
                const char *fail_msg = "Authentication failed";
                SSL_write(ssl, fail_msg, strlen(fail_msg));
            }
            printf("[✖] Authentication failed\n");
        }
                
    }
    
    SSL_shutdown(ssl);
    SSL_free(ssl);    
    close(client_socket);
    pthread_exit(NULL);
}

int main() {
    print_server_banner();
    int server_fd, *new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());

if (!SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) ||
    !SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM)) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}


//====================================================== dont change ====================================================
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    // printf("Server listening on port %d...\n", PORT);
//=============================================== finish dont change ====================================================

while (1) {
    struct client_args *args = malloc(sizeof(struct client_args));
    args->socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
    args->ctx = ctx;

    if (args->socket < 0) {
        perror("Accept failed");
        free(args);
        continue;
    }

    pthread_t tid;
    if (pthread_create(&tid, NULL, handle_client, args) != 0) {
        perror("Thread creation failed");
        close(args->socket);
        free(args);
    }

    pthread_detach(tid);
}


    close(server_fd);
    return 0;
}
