// ftp_server.c

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
#include <sys/select.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#define SERVER_PORT 21
#define DATA_PORT 20
#define MAX_CLIENTS 30
#define BUFFER_SIZE 1024
#define USER_FILE "../users.txt"

struct client_session {
    int control_fd; // Control connection socket descriptor
    int data_fd;    // Data connection socket descriptor
    int logged_in;  // Authentication status
    char username[64];
    char current_dir[256];
    char client_ip[INET_ADDRSTRLEN];
    int client_data_port;
    struct sockaddr_in client_addr;
};

void process_command(struct client_session *client, char *cmd);
void send_response(struct client_session *client, char *message);
int authenticate(char *username, char *password);
int parse_port_command(struct client_session *client, char *argument);
void start_data_transfer(struct client_session *client, char *command, char *argument);
void send_file(int data_sock, char *filename);
void receive_file(int data_sock, char *filename);
void send_list(int data_sock);

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    struct client_session clients[MAX_CLIENTS];
    fd_set read_fds;
    int max_sd;
    int i;

    // Ignore SIGCHLD to prevent zombie processes
    signal(SIGCHLD, SIG_IGN);

    // Initialize clients
    for (i = 0; i < MAX_CLIENTS; i++) {
        clients[i].control_fd = 0;
    }

    // Create a socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Bind to port 21
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(server_fd, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("FTP Server is listening on port %d\n", SERVER_PORT);

    while(1) {
        // Clear the socket set
        FD_ZERO(&read_fds);

        // Add server socket to set
        FD_SET(server_fd, &read_fds);
        max_sd = server_fd;

        // Add child sockets to set
        for (i = 0; i < MAX_CLIENTS; i++) {
            int sd = clients[i].control_fd;

            if(sd > 0)
                FD_SET(sd, &read_fds);

            if(sd > max_sd)
                max_sd = sd;
        }

        // Wait for activity
        int activity = select(max_sd + 1, &read_fds, NULL, NULL, NULL);

        if ((activity < 0) && (errno!=EINTR)) {
            printf("select error");
        }

        // Incoming connection
        if (FD_ISSET(server_fd, &read_fds)) {
            if ((new_socket = accept(server_fd,
                (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }

            // Inform user of socket number
            printf("New connection, socket fd is %d, ip is : %s, port : %d\n",
                new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

            // Send welcome message
            char *message = "220 Service ready for new user.\r\n";
            send(new_socket, message, strlen(message), 0);

            // Add new socket to array of clients
            for (i = 0; i < MAX_CLIENTS; i++) {
                if( clients[i].control_fd == 0 ) {
                    clients[i].control_fd = new_socket;
                    clients[i].logged_in = 0;
                    getcwd(clients[i].current_dir, sizeof(clients[i].current_dir)); // Set default directory
                    strcpy(clients[i].client_ip, inet_ntoa(address.sin_addr));
                    clients[i].client_data_port = 0;
                    clients[i].data_fd = 0;
                    clients[i].client_addr = address;
                    printf("Adding to list of sockets as %d\n" , i);

                    break;
                }
            }
        }

        // IO operation on other sockets
        for (i = 0; i < MAX_CLIENTS; i++) {
            int sd = clients[i].control_fd;

            if (FD_ISSET( sd , &read_fds)) {
                // Check if it was for closing
                char buffer[BUFFER_SIZE];
                int valread;
                if ((valread = read( sd , buffer, BUFFER_SIZE)) == 0) {
                    // Disconnection
                    getpeername(sd , (struct sockaddr*)&address , \
                        (socklen_t*)&addrlen);
                    printf("Host disconnected , ip %s , port %d \n" ,
                        inet_ntoa(address.sin_addr) , ntohs(address.sin_port));

                    // Close the socket
                    close( sd );
                    clients[i].control_fd = 0;
                } else {
                    // Process the command
                    buffer[valread] = '\0';
                    process_command(&clients[i], buffer);
                }
            }
        }
    }

    return 0;
}

void process_command(struct client_session *client, char *cmd) {
    char response[BUFFER_SIZE];
    char *token;
    char *argument;

    // Remove CRLF
    cmd[strcspn(cmd, "\r\n")] = 0;

    printf("Received command from client %d: %s\n", client->control_fd, cmd);

    // Tokenize command
    token = strtok(cmd, " ");
    if (token == NULL) {
        send_response(client, "500 Syntax error, command unrecognized.\r\n");
        return;
    }

    if (strcasecmp(token, "USER") == 0) {
        argument = strtok(NULL, " ");
        if (argument == NULL) {
            send_response(client, "501 Syntax error in parameters or arguments.\r\n");
            return;
        }
        strcpy(client->username, argument);
        send_response(client, "331 Username OK, need password.\r\n");
    } else if (strcasecmp(token, "PASS") == 0) {
        argument = strtok(NULL, " ");
        if (argument == NULL) {
            send_response(client, "501 Syntax error in parameters or arguments.\r\n");
            return;
        }
        if (authenticate(client->username, argument)) {
            client->logged_in = 1;
            send_response(client, "230 User logged in, proceed.\r\n");
        } else {
            send_response(client, "530 Not logged in.\r\n");
        }
    } else if (strcasecmp(token, "PORT") == 0) {
        argument = strtok(NULL, " ");
        if (argument == NULL) {
            send_response(client, "501 Syntax error in parameters or arguments.\r\n");
            return;
        }
        // Parse PORT command argument
        if (parse_port_command(client, argument)) {
            send_response(client, "200 PORT command successful.\r\n");
        } else {
            send_response(client, "501 Syntax error in parameters or arguments.\r\n");
        }
    } else if (strcasecmp(token, "RETR") == 0) {
        if (!client->logged_in) {
            send_response(client, "530 Not logged in.\r\n");
            return;
        }
        argument = strtok(NULL, " ");
        if (argument == NULL) {
            send_response(client, "501 Syntax error in parameters or arguments.\r\n");
            return;
        }
        // Start data transfer
        send_response(client, "150 File status okay; about to open data connection.\r\n");
        start_data_transfer(client, "RETR", argument);
    } else if (strcasecmp(token, "STOR") == 0) {
        if (!client->logged_in) {
            send_response(client, "530 Not logged in.\r\n");
            return;
        }
        argument = strtok(NULL, " ");
        if (argument == NULL) {
            send_response(client, "501 Syntax error in parameters or arguments.\r\n");
            return;
        }
        // Start data transfer
        send_response(client, "150 File status okay; about to open data connection.\r\n");
        start_data_transfer(client, "STOR", argument);
    } else if (strcasecmp(token, "LIST") == 0) {
        if (!client->logged_in) {
            send_response(client, "530 Not logged in.\r\n");
            return;
        }
        // Start data transfer
        send_response(client, "150 File status okay; about to open data connection.\r\n");
        start_data_transfer(client, "LIST", NULL);
    } else if (strcasecmp(token, "PWD") == 0) {
        if (!client->logged_in) {
            send_response(client, "530 Not logged in.\r\n");
            return;
        }
        snprintf(response, sizeof(response), "257 \"%s\".\r\n", client->current_dir);
        send_response(client, response);
    } else if (strcasecmp(token, "CWD") == 0) {
        if (!client->logged_in) {
            send_response(client, "530 Not logged in.\r\n");
            return;
        }
        argument = strtok(NULL, " ");
        if (argument == NULL) {
            send_response(client, "501 Syntax error in parameters or arguments.\r\n");
            return;
        }
        // Construct new path
        char new_path[256];
        if (argument[0] == '/') {
            // Absolute path
            snprintf(new_path, sizeof(new_path), "%s", argument);
        } else {
            // Relative path
            snprintf(new_path, sizeof(new_path), "%s/%s", client->current_dir, argument);
        }
        if (access(new_path, F_OK) == 0) {
            // Update client's current directory
            strncpy(client->current_dir, new_path, sizeof(client->current_dir));
            snprintf(response, sizeof(response), "200 directory changed to %s.\r\n", client->current_dir);
            send_response(client, response);
        } else {
            send_response(client, "550 No such file or directory.\r\n");
        }
    } else if (strcasecmp(token, "QUIT") == 0) {
        send_response(client, "221 Service closing control connection.\r\n");
        close(client->control_fd);
        client->control_fd = 0;
    } else {
        send_response(client, "202 Command not implemented.\r\n");
    }
}

void send_response(struct client_session *client, char *message) {
    send(client->control_fd, message, strlen(message), 0);
}

int authenticate(char *username, char *password) {
    FILE *fp;
    char line[128];
    char *file_username, *file_password;

    fp = fopen(USER_FILE, "r");
    if (fp == NULL) {
        perror("Failed to open users file");
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        file_username = strtok(line, " \t\n");
        file_password = strtok(NULL, " \t\n");
        if (file_username && file_password) {
            if (strcmp(username, file_username) == 0 && strcmp(password, file_password) == 0) {
                fclose(fp);
                return 1;
            }
        }
    }

    fclose(fp);
    return 0;
}

int parse_port_command(struct client_session *client, char *argument) {
    int h1,h2,h3,h4,p1,p2;
    int result = sscanf(argument, "%d,%d,%d,%d,%d,%d", &h1,&h2,&h3,&h4,&p1,&p2);
    if (result != 6) {
        return 0;
    }
    sprintf(client->client_ip, "%d.%d.%d.%d", h1,h2,h3,h4);
    client->client_data_port = (p1 * 256) + p2;
    return 1;
}

void start_data_transfer(struct client_session *client, char *command, char *argument) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("Fork failed");
        send_response(client, "425 Can't open data connection.\r\n");
        return;
    } else if (pid == 0) {
        // Child process to handle data transfer
        int data_sock;
        struct sockaddr_in data_addr;

        // Create socket
        if ((data_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Data socket creation failed");
            exit(EXIT_FAILURE);
        }

        // Bind to port 20
        int enable = 1;
        if (setsockopt(data_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
            perror("setsockopt(SO_REUSEADDR) failed");
        }

        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = INADDR_ANY;
        local_addr.sin_port = htons(DATA_PORT);

        if (bind(data_sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
            perror("Data socket bind failed");
            exit(EXIT_FAILURE);
        }

        // Connect to client
        memset(&data_addr, 0, sizeof(data_addr));
        data_addr.sin_family = AF_INET;
        data_addr.sin_port = htons(client->client_data_port);
        if (inet_pton(AF_INET, client->client_ip, &data_addr.sin_addr) <= 0) {
            perror("Invalid client IP address");
            exit(EXIT_FAILURE);
        }

        if (connect(data_sock, (struct sockaddr *)&data_addr, sizeof(data_addr)) < 0) {
            perror("Data connection failed");
            exit(EXIT_FAILURE);
        }

        // Change to client's current directory
        if (chdir(client->current_dir) != 0) {
            perror("Failed to change directory");
            exit(EXIT_FAILURE);
        }

        if (strcmp(command, "RETR") == 0) {
            // Send file to client
            send_file(data_sock, argument);
        } else if (strcmp(command, "STOR") == 0) {
            // Receive file from client
            receive_file(data_sock, argument);
        } else if (strcmp(command, "LIST") == 0) {
            // Send directory listing
            send_list(data_sock);
        }

        close(data_sock);

        // Send transfer complete message
        send_response(client, "226 Transfer completed.\r\n");
        exit(0);
    } else {
        // Parent process
        // Do nothing
    }
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

void send_list(int data_sock) {
    DIR *d;
    struct dirent *dir;
    char buffer[BUFFER_SIZE];

    d = opendir(".");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_name[0] == '.')
                continue;
            snprintf(buffer, sizeof(buffer), "%s\r\n", dir->d_name);
            send(data_sock, buffer, strlen(buffer), 0);
        }
        closedir(d);
    }
}
