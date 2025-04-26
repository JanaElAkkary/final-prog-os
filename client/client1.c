#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <time.h>


#define PORT 8080
#define BUFFER_SIZE 1024

void print_client_banner() {
    printf("\033[38;5;182m");  // Purple color
    printf("\n");
    printf("╔════════════════════════════════════╗\n");
    printf("║        JA HOLDING CLIENT           ║\n");
    printf("╠════════════════════════════════════╣\n");
    printf("║  Encryption : AES-128-CBC          ║\n");
    printf("║  Protocol   : SSL                  ║\n");
    printf("║  Status     : Connecting to server ║\n");
    printf("╚════════════════════════════════════╝\n\n");
    printf("\033[0m");  // Reset color
}

void aes_encrypt(const unsigned char *plaintext, unsigned char *ciphertext, int plaintext_len,
    const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}
void log_action(const char *username, const char *action) {
    FILE *log_fp = fopen("logs.txt", "a");
    if (log_fp) {
        fprintf(log_fp, "%s: %s\n", username, action);
        fclose(log_fp);
    } else {
        perror("[✖] Failed to write to logs.txt");
    }
}



void request_server_ls(SSL *ssl, unsigned char *aes_key, unsigned char *aes_iv) {
    int msg_type = 3;
    SSL_write(ssl, &msg_type, sizeof(int));

    int enc_len;
    SSL_read(ssl, &enc_len, sizeof(int));

    unsigned char enc_buf[BUFFER_SIZE * 2], dec_buf[BUFFER_SIZE * 2];
    int total_received = 0;
    while (total_received < enc_len) {
        int r = SSL_read(ssl, enc_buf + total_received, enc_len - total_received);
        if (r <= 0) break;
        total_received += r;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, aes_iv);
    EVP_DecryptUpdate(ctx, dec_buf, &len, enc_buf, enc_len);
    int dec_len = len;
    EVP_DecryptFinal_ex(ctx, dec_buf + len, &len);
    dec_len += len;
    dec_buf[dec_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);

    printf("\033[1;32m[Server Files]:\033[0m\n\n%s", dec_buf);
}

void read_file(const char *folder_path) {
    char filename[256];
    FILE *fp;

    while (1) {
        printf("Enter filename to read (or type 'exit' to go back): ");
        fgets(filename, sizeof(filename), stdin);
        filename[strcspn(filename, "\n")] = 0;

        if (strcmp(filename, "exit") == 0) return;

        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", folder_path, filename);

        fp = fopen(full_path, "r");
        if (fp) {
            printf("\n\033[1;34m[Content of %s]:\033[0m\n", filename);
            char line[BUFFER_SIZE];
            while (fgets(line, sizeof(line), fp)) {
                printf("%s", line);
            }
            printf("\n");
            fclose(fp);
            return;
        } else {
            printf("\033[1;31m[✖] File not found. Please try again.\033[0m\n");
        }
    }
}
void copy_file(const char *folder_path) {
    char filename[256], source_path[512], dest_path[512];
    FILE *src_fp, *dest_fp;

    while (1) {
        printf("Enter filename to copy (or type 'exit' to go back): ");
        fgets(filename, sizeof(filename), stdin);
        filename[strcspn(filename, "\n")] = 0;

        if (strcmp(filename, "exit") == 0) return;

        snprintf(source_path, sizeof(source_path), "%s/%s", folder_path, filename);
        snprintf(dest_path, sizeof(dest_path), "%s/%s(copy1).txt", folder_path, strtok(filename, "."));

        src_fp = fopen(source_path, "r");
        if (!src_fp) {
            printf("\033[1;31m[✖] Source file not found. Try again.\033[0m\n");
            continue;
        }

        dest_fp = fopen(dest_path, "w");
        if (!dest_fp) {
            printf("\033[1;31m[✖] Failed to create copy.\033[0m\n");
            fclose(src_fp);
            return;
        }

        char line[BUFFER_SIZE];
        while (fgets(line, sizeof(line), src_fp)) {
            fputs(line, dest_fp);
        }

        fclose(src_fp);
        fclose(dest_fp);

        printf("\033[1;32m[✔] File copied to: %s\033[0m\n", dest_path);
        return;
    }
}
void edit_file(const char *folder_path) {
    char filename[256], line[BUFFER_SIZE];
    FILE *fp;

    while (1) {
        printf("Enter filename to edit (or type 'exit' to go back): ");
        fgets(filename, sizeof(filename), stdin);
        filename[strcspn(filename, "\n")] = 0;

        if (strcmp(filename, "exit") == 0) return;

        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", folder_path, filename);

        fp = fopen(full_path, "a");
        if (!fp) {
            printf("\033[1;31m[✖] File not found. Please try again.\033[0m\n");
            continue;
        }

        printf("Enter content to append (type 'exit' to stop):\n");
        while (1) {
            printf(">> ");
            fgets(line, sizeof(line), stdin);
            line[strcspn(line, "\n")] = 0;

            if (strcmp(line, "exit") == 0) break;
            fprintf(fp, "%s\n", line);
        }

        fclose(fp);
        printf("\033[1;32m[✔] Changes saved to %s\033[0m\n", full_path);
        return;
    }
}
void send_file_to_server(SSL *ssl, const char *client_folder) {
    char filename[256], filepath[512], file_content[BUFFER_SIZE];
    printf("Enter filename to send to server (or type 'exit' to cancel): ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = 0;
    if (strcmp(filename, "exit") == 0) return;

    snprintf(filepath, sizeof(filepath), "%s/%s", client_folder, filename);
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        printf("\033[1;31m[✖] File not found.\033[0m\n");
        return;
    }

    // Send opcode to server
    int msg_type = 5;
    SSL_write(ssl, &msg_type, sizeof(int));

    // Send filename
    int name_len = strlen(filename);
    SSL_write(ssl, &name_len, sizeof(int));
    SSL_write(ssl, filename, name_len);

    // Send file content
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

    printf("\033[1;32m[✔] File sent to server.\033[0m\n");
}

void receive_file_from_server(SSL *ssl, const char *client_folder) {
    char filename[256], filepath[512];
    printf("Enter filename to receive from server (or type 'exit' to cancel): ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = 0;
    if (strcmp(filename, "exit") == 0) return;

    // Send opcode
    int msg_type = 6;
    SSL_write(ssl, &msg_type, sizeof(int));

    // Send filename
    int name_len = strlen(filename);
    SSL_write(ssl, &name_len, sizeof(int));
    SSL_write(ssl, filename, name_len);

    // Read size from server
    long fsize;
    SSL_read(ssl, &fsize, sizeof(long));
    if (fsize == -1) {
        printf("\033[1;31m[✖] File not found on server.\033[0m\n");
        return;
    }

    char *content = malloc(fsize + 1);
    SSL_read(ssl, content, fsize);
    content[fsize] = '\0';

    snprintf(filepath, sizeof(filepath), "%s/%s", client_folder, filename);
    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        printf("\033[1;31m[✖] Could not create file.\033[0m\n");
        free(content);
        return;
    }

    fwrite(content, 1, fsize, fp);
    fclose(fp);
    free(content);
    printf("\033[1;32m[✔] File saved to client_files.\033[0m\n");
}
void create_file(const char *folder_path) {
    char filename[256], filepath[512], content[BUFFER_SIZE];
    
    printf("Enter new filename to create (or type 'exit' to cancel): ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = 0;

    if (strcmp(filename, "exit") == 0) return;

    snprintf(filepath, sizeof(filepath), "%s/%s", folder_path, filename);

    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        printf("\033[1;31m[✖] Could not create file.\033[0m\n");
        return;
    }

    printf("Enter content for the file:\n");
    fgets(content, sizeof(content), stdin);
    content[strcspn(content, "\n")] = 0;

    fprintf(fp, "%s\n", content);
    fclose(fp);

    printf("\033[1;32m[✔] File created at: %s\033[0m\n", filepath);
}
void delete_file(const char *folder_path) {
    char filename[256], full_path[512];

    while (1) {
        printf("Enter filename to delete (or type 'exit' to cancel): ");
        fgets(filename, sizeof(filename), stdin);
        filename[strcspn(filename, "\n")] = 0;

        if (strcmp(filename, "exit") == 0) return;

        snprintf(full_path, sizeof(full_path), "%s/%s", folder_path, filename);

        if (access(full_path, F_OK) != 0) {
            printf("\033[1;31m[✖] File not found. Try again.\033[0m\n");
            continue;
        }

        if (remove(full_path) == 0) {
            printf("\033[1;32m[✔] Deleted: %s\033[0m\n", full_path);
        } else {
            printf("\033[1;31m[✖] Failed to delete the file.\033[0m\n");
        }
        return;
    }
}






int main() {
    print_client_banner();
    int sock;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE] = {0};
    char username[50], password[50], message[BUFFER_SIZE];

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define server address
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY; // Connect to localhost

    // Connect to server
    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Send username
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_connect(ssl);

    // Generate and send AES key and IV
    unsigned char aes_key[16], aes_iv[16];
    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(aes_iv, sizeof(aes_iv));
    SSL_write(ssl, aes_key, 16);
    SSL_write(ssl, aes_iv, 16);

    char role[20] = {0};

    int attempts=0;
    int authenticated = 0;
    while (attempts < 2 && !authenticated) {

        // Get username and password
        printf("Enter username: ");
        scanf("%s", username);
        printf("Enter password: ");
        scanf("%s", password);

        int user_len = strlen(username);
        int pass_len = strlen(password);
        unsigned char enc_user[BUFFER_SIZE], enc_pass[BUFFER_SIZE];
        aes_encrypt((unsigned char *)username, enc_user, user_len, aes_key, aes_iv);
        aes_encrypt((unsigned char *)password, enc_pass, pass_len, aes_key, aes_iv);

        int enc_user_len = ((user_len / 16) + 1) * 16;
        int enc_pass_len = ((pass_len / 16) + 1) * 16;

        SSL_write(ssl, &user_len, sizeof(int));
        SSL_write(ssl, enc_user, enc_user_len);
        SSL_write(ssl, &pass_len, sizeof(int));
        SSL_write(ssl, enc_pass, enc_pass_len);

        // Receive response from server
        int bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0'; 
            printf("Server: %s\n", buffer);

            if (strcmp(buffer, "Authentication successful") == 0) {
                authenticated = 1;
                printf("\033[1;32m[✔] Authentication successful!\033[0m\n");

                memset(buffer, 0, BUFFER_SIZE);
                int bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
                if (bytes_received > 0) {
                    buffer[bytes_received] = '\0';
                    strcpy(role, buffer);
                    printf("Your role: \033[38;5;206m%s\033[0m\n", buffer); 

                    // ===== Receive messages if any =====
                    int enc_len;
                    SSL_read(ssl, &enc_len, sizeof(int));
                    if (enc_len > 0) {
                        unsigned char enc_msg[BUFFER_SIZE * 2], dec_msg[BUFFER_SIZE * 2];
                        int total_received = 0;
                        while (total_received < enc_len) {
                            int r = SSL_read(ssl, enc_msg + total_received, enc_len - total_received);
                            if (r <= 0) break;
                            total_received += r;
                        }

                        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                        int len;
                        EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, aes_iv);
                        EVP_DecryptUpdate(ctx, dec_msg, &len, enc_msg, enc_len);
                        int dec_len = len;
                        EVP_DecryptFinal_ex(ctx, dec_msg + len, &len);
                        dec_len += len;
                        dec_msg[dec_len] = '\0';
                        EVP_CIPHER_CTX_free(ctx);

                        printf("\033[1;35m[ Inbox]:\033[0m\n%s\n", dec_msg);
                    } else {
                        printf("\033[1;35m[ Inbox]:\033[0m No new messages.\n");
                    }

                    // ===== MAIN MENU LOOP =====
                    while (1) {
                        printf("\n\033[38;5;206mMAIN MENU\033[0m\n");
                        printf("1. Actions\n");
                        printf("2. Send a message\n");
                        printf("3. Exit\n");
                        printf("Choose from (1-3): ");

                        int choice;
                        scanf("%d", &choice);
                        getchar(); // Consume leftover newline

                        if (choice == 1) {
                            int sub_choice;
                            printf("\n\033[38;5;206mDo you want server action menu (1) or client access menu (2)? Choose (1-2): ");
                            scanf("%d", &sub_choice);
                            getchar(); // consume newline

                            if (strcmp(role, "Entry") == 0) {
                                if (sub_choice == 1) {
                                    // Server Action Menu for Entry
                                    while (1) {
                                        printf("\n\033[38;5;206mEntry Action Server Menu\033[0m\n");
                                        printf("Automatically directed to: /home/jana/Music/prog_client_server (2)/server/server_files\n");
                                        printf("1. List \n");
                                        printf("2. Read \n");
                                        printf("3. Exit to main menu\n");
                                        printf("Choose from (1-3): ");
                                        int act_choice;
                                        scanf("%d", &act_choice);
                                        getchar();
                                        if (act_choice == 1) {
                                            if (sub_choice == 1) {
                                                request_server_ls(ssl, aes_key, aes_iv);
                                            } else {
                                                printf("\033[1;32m[Client Files]:\033[0m\n");
                                                system("ls client_files");
                                                log_action(username, "listed server files");

                                            }
                                        } else if (act_choice == 2) {
                                            if (sub_choice == 1) {
                                                read_file("/home/jana/Music/prog_client_server (2)/server/server_files");
                                                log_action(username, "readed server files");

                                            } else {
                                                read_file("/home/jana/Music/prog_client_server (2)/client/client_files");
                                            }
                                           
                                            
                                        } else if (act_choice == 3) {
                                            break;
                                            log_action(username, "existed action menu");
                                        } else {
                                            printf("Coming soon...\n");
                                        }
                                    }
                                } else if (sub_choice == 2) {
                                    // Client Action Menu for Entry
                                    while (1) {
                                        printf("\n\033[38;5;206mEntry Action Client Menu\033[0m\n");
                                        printf("Automatically directed to:/home/jana/Music/prog_client_server (2)/client/client_files\n");
                                        printf("1. List \n");
                                        printf("2. Read \n");
                                        printf("3. Exit to main menu\n");
                                        printf("Choose from (1-3): ");
                                        int act_choice;
                                        scanf("%d", &act_choice);
                                        getchar();
                                        if (act_choice == 1) {
                                            if (sub_choice == 1) {
                                                request_server_ls(ssl, aes_key, aes_iv);
                                            } else {
                                                printf("\033[1;32m[Client Files]:\033[0m\n");
                                                system("ls client_files");
                                                log_action(username, "listed client files");
                                            }
                                        } else if (act_choice == 2) {
                                            read_file("/home/jana/Music/prog_client_server (2)/client/client_files");
                                            log_action(username, "readed client files");
                                        } else if (act_choice == 3) {
                                            break;
                                            log_action(username, "existed action menu");
                                        }else {
                                            printf("Coming soon...\n");
                                        }
                                    }
                                    } else {
                                        printf("Invalid choice. Returning to main menu.\n");
                                }
                            } else if (strcmp(role, "Medium") == 0) {
                                if (sub_choice == 1) {
                                    // Medium Server Action Menu
                                    while (1) {
                                        printf("\n\033[38;5;206mMedium Action Server Menu\033[0m\n");
                                        printf("Automatically directed to: /home/jana/Music/prog_client_server (2)/server/server_files\n");
                                        printf("1. List \n");
                                        printf("2. Read \n");
                                        printf("3. Copy \n");
                                        printf("4. Edit \n");
                                        printf("5. Exit to main menu\n");
                                        printf("Choose from (1-5): ");
                                        int act_choice;
                                        scanf("%d", &act_choice);
                                        getchar();
                                        if (act_choice == 1) {
                                            if (sub_choice == 1) {
                                                request_server_ls(ssl, aes_key, aes_iv);
                                                log_action(username, "listed server files");
                                            } else {
                                                printf("\033[1;32m[Client Files]:\033[0m\n");
                                                system("ls client_files");
                                            }
                                        } else if (act_choice == 2) {
                                            read_file("/home/jana/Music/prog_client_server (2)/server/server_files");
                                            log_action(username, "readed server files");
                                        } 
                                        else if (act_choice == 3) {
                                            copy_file("/home/jana/Music/prog_client_server (2)/server/server_files");
                                        }else if (act_choice == 4) {
                                            edit_file("/home/jana/Music/prog_client_server (2)/server/server_files");
                                        }else if (act_choice == 5) {
                                            break;
                                            log_action(username, "existed action menu");
                                        } else {
                                            printf("Coming soon...\n");
                                        }
                                    }
                                } else if (sub_choice == 2) {
                                    // Medium Client Action Menu
                                    while (1) {
                                        printf("\n\033[38;5;206mMedium Action Client Menu\033[0m\n");
                                        printf("Automatically directed to: /home/jana/Music/prog_client_server (2)/client/client_files\n");
                                        printf("1. List \n");
                                        printf("2. Read \n");
                                        printf("3. Copy \n");
                                        printf("4. Edit \n");
                                        printf("5. Exit to main menu\n");
                                        printf("Choose from (1-5): ");
                                        int act_choice;
                                        scanf("%d", &act_choice);
                                        getchar();
                                        if (act_choice == 1) {
                                            if (sub_choice == 1) {
                                                request_server_ls(ssl, aes_key, aes_iv);
                                            } else {
                                                printf("\033[1;32m[Client Files]:\033[0m\n");
                                                system("ls client_files");
                                                log_action(username, "listed client files");
                                            }
                                        } else if (act_choice == 2) {
                                            read_file("/home/jana/Music/prog_client_server (2)/client/client_files");
                                            log_action(username, "readed client files");
                                        }else if (act_choice == 3) {
                                            copy_file("/home/jana/Music/prog_client_server (2)/client/client_files");

                                        } else if (act_choice == 4) {
                                            edit_file("/home/jana/Music/prog_client_server (2)/client/client_files");
                                        }else if (act_choice == 5) {
                                            break;
                                            log_action(username, "existed action menu");
                                        } else {
                                            printf("Coming soon...\n");
                                        }
                                    }
                                }
                            } else if (strcmp(role, "Top") == 0) {
                                if (sub_choice == 1) {
                                    // Top Server Action Menu
                                    while (1) {
                                        printf("\n\033[38;5;206mTop Action Server Menu\033[0m\n");
                                        printf("Automatically directed to: /home/jana/Music/prog_client_server (2)/server/server_files\n");
                                        printf("1. List \n");
                                        printf("2. Read \n");
                                        printf("3. Copy \n");
                                        printf("4. Edit \n");
                                        printf("5. Send to client\n");
                                        printf("6. Create a file \n");
                                        printf("7. Delete\n");
                                        printf("8. Exit to main menu\n");
                                        printf("Choose from (1-8): ");
                                        int act_choice;
                                        scanf("%d", &act_choice);
                                        getchar();
                                        if (act_choice == 1) {
                                            if (sub_choice == 1) {
                                                request_server_ls(ssl, aes_key, aes_iv);
                                                log_action(username, "listed server files");
                                            } else {
                                                printf("\033[1;32m[Client Files]:\033[0m\n");
                                                system("ls client_files");
                                            }
                                        } else if (act_choice == 2) {
                                            read_file("/home/jana/Music/prog_client_server (2)/server/server_files");
                                            log_action(username, "readed server files");
                                        }  else if (act_choice == 3) {
                                            copy_file("/home/jana/Music/prog_client_server (2)/server/server_files");
                                        } else if (act_choice == 4) {
                                            edit_file("/home/jana/Music/prog_client_server (2)/server/server_files");
                                        }else if (act_choice == 5 ) {
                                            receive_file_from_server(ssl, "client_files");
                                        }else if (act_choice == 6) {
                                            create_file("/home/jana/Music/prog_client_server (2)/server/server_files");
                                        }else if (act_choice == 7) {
                                            delete_file("/home/jana/Music/prog_client_server (2)/server/server_files");
                                        } else if (act_choice == 8) {
                                            break;
                                            log_action(username, "existed action menu");
                                        }else {
                                            printf("Coming soon...\n");
                                        }
                                    }
                                } else if (sub_choice == 2) {
                                    // Top Client Action Menu
                                    while (1) {
                                        printf("\n\033[38;5;206mTop Action Client Menu\033[0m\n");
                                        printf("Automatically directed to: /home/jana/Music/prog_client_server (2)/client/client_files\n");
                                        printf("1. List \n");
                                        printf("2. Read \n");
                                        printf("3. Copy \n");
                                        printf("4. Edit \n");
                                        printf("5. Send to server \n");
                                        printf("6. Create a file \n");
                                        printf("7. Delete \n");
                                        printf("8. Exit to main menu\n");
                                        printf("Choose from (1-8): ");
                                        int act_choice;
                                        scanf("%d", &act_choice);
                                        getchar();
                                        if (act_choice == 1) {
                                            if (sub_choice == 1) {
                                                request_server_ls(ssl, aes_key, aes_iv);
                                            } else {
                                                printf("\033[1;32m[Client Files]:\033[0m\n");
                                                system("ls client_files");
                                                log_action(username, "listed client files");
                                            }
                                        } else if (act_choice == 2) {
                                            read_file("/home/jana/Music/prog_client_server (2)/client/client_files");
                                            log_action(username, "readed client files");
                                        }  else if (act_choice == 3) {
                                            copy_file("/home/jana/Music/prog_client_server (2)/client/client_files");
                                        }else if (act_choice == 4) {
                                            edit_file("/home/jana/Music/prog_client_server (2)/client/client_files");
                                        }else if (act_choice == 5) {
                                            send_file_to_server(ssl, "client_files");
                                        }else if (act_choice == 6) {
                                            create_file("/home/jana/Music/prog_client_server (2)/client/client_files");
                                        }else if (act_choice == 7) {
                                            delete_file("/home/jana/Music/prog_client_server (2)/client/client_files");
                                        } else if (act_choice == 8) {
                                            break;
                                            log_action(username, "existed action menu");
                                        } else {
                                            printf("Coming soon...\n");
                                        }
                                    }
                                }
                            }
                        } else if (choice == 2) {
                            // Message Menu for all roles
                            while (1) {
                                printf("\n\033[38;5;206mMessage Menu\033[0m\n");
                                printf("1. Send a message to the server (coming soon)\n");
                                printf("2. Send a message to another client (coming soon)\n");
                                printf("3. Exit to main menu\n");
                                printf("Choose from (1-3): ");

                                int msg_choice;
                                scanf("%d", &msg_choice);
                                getchar();  // Consume newline

                                if (msg_choice == 3) break;
                                if (msg_choice == 1) {
                                    char message[BUFFER_SIZE];
                                    printf("\033[38;5;182mEnter your message: ");
                                    fgets(message, BUFFER_SIZE, stdin);
                                    message[strcspn(message, "\n")] = 0;

                                    int msg_len = strlen(message);
                                    unsigned char enc_msg[BUFFER_SIZE];
                                    aes_encrypt((unsigned char *)message, enc_msg, msg_len, aes_key, aes_iv);
                                    int enc_msg_len = ((msg_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

                                    int msg_type = 1;
                                    SSL_write(ssl, &msg_type, sizeof(int));
                                    SSL_write(ssl, &msg_len, sizeof(int));
                                    SSL_write(ssl, enc_msg, enc_msg_len);

                                    int reply_len = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
                                    if (reply_len > 0) {
                                        buffer[reply_len] = '\0';
                                        printf("\033[1;32m[✔] %s\033[0m\n", buffer);
                                    }
                                } else if (msg_choice == 2) {
                                    char recipient[50], message[BUFFER_SIZE];
                                    printf("Enter recipient username: ");
                                    scanf("%s", recipient);
                                    getchar();

                                    printf("Enter your message: ");
                                    fgets(message, BUFFER_SIZE, stdin);
                                    message[strcspn(message, "\n")] = 0;

                                    int msg_type = 2;
                                    int msg_len = strlen(message);
                                    int rec_len = strlen(recipient);

                                    unsigned char enc_msg[BUFFER_SIZE];
                                    aes_encrypt((unsigned char *)message, enc_msg, msg_len, aes_key, aes_iv);
                                    int enc_msg_len = ((msg_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

                                    SSL_write(ssl, &msg_type, sizeof(int));
                                    SSL_write(ssl, &rec_len, sizeof(int));
                                    SSL_write(ssl, recipient, rec_len);
                                    SSL_write(ssl, &msg_len, sizeof(int));
                                    SSL_write(ssl, enc_msg, enc_msg_len);

                                    int reply_len = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
                                    if (reply_len > 0) {
                                        buffer[reply_len] = '\0';
                                        printf("\033[1;32m[✔] %s\033[0m\n", buffer);
                                    }
                                } else {
                                    printf("Invalid choice. Please choose between 1 and 3.\n");
                                }
                            }
                        } else if (choice == 3) {
                            printf("Exiting...\n");
                            printf("Goodbye!\n");
                            int exit_type = 999;
                            SSL_write(ssl, &exit_type, sizeof(int));
                            break;
                        } else {
                            printf("Invalid choice. Please try again.\n");
                        }
                    }
                }
            } else {
                printf("\033[1;31m[✖] Login failed. Try again.\033[0m\n");
            }
        } else {
            printf("No response from server.\n");
            close(sock);
            return 0;
        }
    }

    SSL_CTX_free(ctx);
    close(sock);
    return 0;
}
