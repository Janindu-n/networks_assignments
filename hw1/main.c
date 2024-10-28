#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define GLOBAL_HEADER_LENGTH 24
#define RECORD_HEADER_LENGTH 16
#define ETHERNET_HEADER_LENGTH 14
#define IP_HEADER_LENGTH 20
#define UDP_HEADER_LENGTH 8
#define SKIP_HEADERS_LENGTH 50

struct udp_info {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned short length;
    unsigned short checksum;
};

void printPacket(const unsigned char *data, int data_length) {
    struct udp_info *udp = (struct udp_info *)(data);
    printf("============================\n");
    printf("Src Port: %u\n", ntohs(udp->source_port));
    printf("Des Port: %u\n", ntohs(udp->dest_port));
    printf("UDP Packet Length: %u\n", ntohs(udp->length));
    printf("Checksum: 0x%x\n", ntohs(udp->checksum));

    printf("Data: ");
    for (int i = sizeof(struct udp_info); i < data_length; i++) {
        if (data[i] >= 32 && data[i] <= 126) {
            printf("%c", data[i]); 
        } else {
            printf("."); 
        }
    }
    printf("\n\n");
}


void readFile(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    //upd data init
    unsigned char buffer[65536]; 
    int packet_count = 0;

    //skip the global header 
    fseek(file, GLOBAL_HEADER_LENGTH, SEEK_SET);

    while (fread(buffer, 1, SKIP_HEADERS_LENGTH, file) == SKIP_HEADERS_LENGTH) {
        //read 16 + 14 + 20 bytes
        //read UDP header
        fread(buffer, 1, UDP_HEADER_LENGTH, file); 

        struct udp_info *udp = (struct udp_info *)(buffer);
        int udp_length = ntohs(udp->length); 


        //data to read after headers
        int data_size = udp_length - UDP_HEADER_LENGTH; 
        fread(buffer + UDP_HEADER_LENGTH, 1, data_size, file);
        printf("Packet #%d:\n", ++packet_count);
        printPacket(buffer, udp_length);

        
    }

    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("wrong entry, please enter:  %s  {pcap filname} \n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *pcap_file = argv[1];
    readFile(pcap_file);

    return EXIT_SUCCESS;
}
