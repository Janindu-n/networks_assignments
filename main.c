#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define PCAP_GLOBAL_HEADER_LEN 24
#define PCAP_RECORD_HEADER_LEN 16
#define ETHERNET_HEADER_LEN 14
#define IP_HEADER_LEN 20
#define UDP_HEADER_LEN 8
#define SKIP_HEADERS_LEN (PCAP_RECORD_HEADER_LEN + ETHERNET_HEADER_LEN + IP_HEADER_LEN)

struct udp_header {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned short length;
    unsigned short checksum;
};

// Function to print UDP packet details
void print_udp_packet(const unsigned char *data, int data_len) {
    struct udp_header *udp = (struct udp_header *)(data);

    printf("============================\n");
    printf("Src Port: %u\n", ntohs(udp->source_port));
    printf("Des Port: %u\n", ntohs(udp->dest_port));
    printf("UDP Packet Length: %u\n", ntohs(udp->length));
    printf("Checksum: 0x%x\n", ntohs(udp->checksum));

    printf("Data: ");
    for (int i = sizeof(struct udp_header); i < data_len; i++) {
        if (data[i] >= 32 && data[i] <= 126) {
            printf("%c", data[i]); // ASCII characters
        } else {
            printf("."); // Non-printable characters
        }
    }
    printf("\n\n");
}

// Function to read and parse a PCAP file
void read_pcap_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    unsigned char buffer[65536]; // Buffer to store packet data
    int packet_count = 0;

    // Skip the global header (first 24 bytes)
    fseek(file, PCAP_GLOBAL_HEADER_LEN, SEEK_SET);

    while (fread(buffer, 1, SKIP_HEADERS_LEN, file) == SKIP_HEADERS_LEN) {
        // reading 16 + 14 + 20 bytes, we are now at the UDP header
        // Read UDP header
        fread(buffer, 1, UDP_HEADER_LEN, file); 

        struct udp_header *udp = (struct udp_header *)(buffer);
        int udp_length = ntohs(udp->length); 


        // data to read after headers
        int data_size = udp_length - UDP_HEADER_LEN; 
        fread(buffer + UDP_HEADER_LEN, 1, data_size, file);
        printf("Packet #%d:\n", ++packet_count);
        print_udp_packet(buffer, udp_length);

        
    }

    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pcap_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *pcap_file = argv[1];
    read_pcap_file(pcap_file);

    return EXIT_SUCCESS;
}
