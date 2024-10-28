#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#define SERVER_PORT 21
#define BUFFER_SIZE 1024

void send_command(int sock, char *command);
void send_command_with_arg(int sock, char *command, char *argument);
ssize_t recv_response(int sock, char *buffer);
void send_port_command(int control_sock, int data_port);
int get_available_port();
void handle_data_transfer(char *command, char *argument, int data_port);
void send_file(int data_sock, char *filename);
void receive_file(int data_sock, char *filename);
void receive_list(int data_sock);

int main(int argc, char *argv[]) {
    int control_sock;
    struct sockaddr_in server_addr;
    char server_ip[INET_ADDRSTRLEN];
    char buffer[BUFFER_SIZE];
    char cmdline[BUFFER_SIZE];
    char *command, *argument;
    ssize_t n;

    if (argc != 2) {
        printf("Usage: %s <server_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    strcpy(server_ip, argv[1]);

    // Create socket
    if ((control_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Control socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid server IP address");
        exit(EXIT_FAILURE);
    }

    if (connect(control_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Control connection failed");
        exit(EXIT_FAILURE);
    }

    // Read welcome message
    n = recv(control_sock, buffer, BUFFER_SIZE - 1, 0);
    if (n > 0) {
        buffer[n] = '\0';
        printf("%s", buffer);
    }

    // Command loop
    while (1) {
        printf("ftp> ");
        if (fgets(cmdline, sizeof(cmdline), stdin) == NULL) {
            break;
        }
        cmdline[strcspn(cmdline, "\r\n")] = 0; // Remove newline

        // Check for local commands
        if (cmdline[0] == '!') {
            if (strcasecmp(cmdline, "!PWD") == 0) {
                char cwd[256];
                if (getcwd(cwd, sizeof(cwd)) != NULL) {
                    printf("%s\n", cwd);
                } else {
                    perror("getcwd() error");
                }
            } else if (strncasecmp(cmdline, "!CWD", 4) == 0) {
                argument = cmdline + 5;
                if (argument == NULL || strlen(argument) == 0) {
                    printf("Usage: !CWD <directory>\n");
                } else {
                    if (chdir(argument) == 0) {
                        printf("Local directory changed to %s\n", argument);
                    } else {
                        perror("chdir() error");
                    }
                }
            } else if (strcasecmp(cmdline, "!LIST") == 0) {
                system("ls -l");
            } else {
                system(cmdline + 1);
            }
            continue;
        }

        // Parse command
        command = strtok(cmdline, " ");
        if (command == NULL)
            continue;

        argument = strtok(NULL, "");

        // Handle commands
        if (strcasecmp(command, "QUIT") == 0) {
            send_command(control_sock, "QUIT");
            n = recv_response(control_sock, buffer);
            if (n > 0) {
                printf("%s", buffer);
            }
            close(control_sock);
            break;
        } else if (strcasecmp(command, "USER") == 0 || strcasecmp(command, "PASS") == 0 ||
                   strcasecmp(command, "CWD") == 0 || strcasecmp(command, "PWD") == 0 ||
                   strcasecmp(command, "PORT") == 0) {
            // Send command directly
            send_command_with_arg(control_sock, command, argument);
            n = recv_response(control_sock, buffer);
            if (n > 0) {
                printf("%s", buffer);
            }
        } else if (strcasecmp(command, "RETR") == 0 ||
                   strcasecmp(command, "STOR") == 0 ||
                   strcasecmp(command, "LIST") == 0) {
            // Handle data transfer commands
            // Send PORT command first
            int data_port = get_available_port();
            send_port_command(control_sock, data_port);

            n = recv_response(control_sock, buffer);
            if (n > 0) {
                printf("%s", buffer);
            }

            // Send command
            if (argument)
                send_command_with_arg(control_sock, command, argument);
            else
                send_command(control_sock, command);

            n = recv_response(control_sock, buffer);
            if (n > 0) {
                printf("%s", buffer);
                if (strncmp(buffer, "150", 3) == 0) {
                    // Start data transfer
                    handle_data_transfer(command, argument, data_port);
                    n = recv_response(control_sock, buffer);
                    if (n > 0) {
                        printf("%s", buffer);
                    }
                }
            }
        } else {
            printf("Invalid command.\n");
        }
    }

    return 0;
}

void send_command(int sock, char *command) {
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "%s\r\n", command);
    send(sock, buffer, strlen(buffer), 0);
}

void send_command_with_arg(int sock, char *command, char *argument) {
    char buffer[BUFFER_SIZE];
    if (argument)
        snprintf(buffer, sizeof(buffer), "%s %s\r\n", command, argument);
    else
        snprintf(buffer, sizeof(buffer), "%s\r\n", command);
    send(sock, buffer, strlen(buffer), 0);
}

ssize_t recv_response(int sock, char *buffer) {
    ssize_t n = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (n > 0) {
        buffer[n] = '\0';
    }
    return n;
}

void send_port_command(int control_sock, int data_port) {
    char buffer[BUFFER_SIZE];
    char ip[INET_ADDRSTRLEN];
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);

    // Get local IP address
    getsockname(control_sock, (struct sockaddr *)&local_addr, &addr_len);
    inet_ntop(AF_INET, &local_addr.sin_addr, ip, sizeof(ip));

    // Split IP into octets
    int h1,h2,h3,h4;
    sscanf(ip, "%d.%d.%d.%d", &h1,&h2,&h3,&h4);

    // Split port into p1 and p2
    int p1 = data_port / 256;
    int p2 = data_port % 256;

    snprintf(buffer, sizeof(buffer), "PORT %d,%d,%d,%d,%d,%d\r\n", h1,h2,h3,h4,p1,p2);
    send(control_sock, buffer, strlen(buffer), 0);
}

int get_available_port() {
    static int base_port = 1025;
    return base_port++;
}

void handle_data_transfer(char *command, char *argument, int data_port) {
    int data_sock, new_sock;
    struct sockaddr_in data_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int opt = 1;

    // Create socket
    if ((data_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Data socket creation failed");
        return;
    }

    if (setsockopt(data_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(data_sock);
        return;
    }

    // Bind to data port
    memset(&data_addr, 0, sizeof(data_addr));
    data_addr.sin_family = AF_INET;
    data_addr.sin_addr.s_addr = INADDR_ANY;
    data_addr.sin_port = htons(data_port);

    if (bind(data_sock, (struct sockaddr *)&data_addr, sizeof(data_addr)) < 0) {
        perror("Data socket bind failed");
        close(data_sock);
        return;
    }

    // Listen
    if (listen(data_sock, 1) < 0) {
        perror("Data socket listen failed");
        close(data_sock);
        return;
    }

    // Accept connection
    new_sock = accept(data_sock, (struct sockaddr *)&client_addr, &addr_len);
    if (new_sock < 0) {
        perror("Data connection accept failed");
        close(data_sock);
        return;
    }

    if (strcasecmp(command, "RETR") == 0) {
        // Receive file from server
        receive_file(new_sock, argument);
    } else if (strcasecmp(command, "STOR") == 0) {
        // Send file to server
        send_file(new_sock, argument);
    } else if (strcasecmp(command, "LIST") == 0) {
        // Receive directory listing
        receive_list(new_sock);
    }

    close(new_sock);
    close(data_sock);
}

void send_file(int data_sock, char *filename) {
    int fd;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read, bytes_sent;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file for reading");
        return;
    }

    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        bytes_sent = send(data_sock, buffer, bytes_read, 0);
        if (bytes_sent < 0) {
            perror("Failed to send file data");
            break;
        }
    }

    close(fd);
}

void receive_file(int data_sock, char *filename) {
    int fd;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received, bytes_written;

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        perror("Failed to open file for writing");
        return;
    }

    while ((bytes_received = recv(data_sock, buffer, BUFFER_SIZE, 0)) > 0) {
        bytes_written = write(fd, buffer, bytes_received);
        if (bytes_written < 0) {
            perror("Failed to write to file");
            break;
        }
    }

    close(fd);
}

void receive_list(int data_sock) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    while ((bytes_received = recv(data_sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';
        printf("%s", buffer);
    }
}
