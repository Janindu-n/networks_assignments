#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define PCAP_GLOBAL_HEADER_LEN 24
#define PCAP_RECORD_HEADER_LEN 16
#define ETHERNET_HEADER_LEN 14
#define IP_HEADER_LEN 20
#define SKIP_BYTES (PCAP_RECORD_HEADER_LEN + ETHERNET_HEADER_LEN + IP_HEADER_LEN)

struct udp_header {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned short length;
    unsigned short checksum;
};

// Function to print UDP packet details
void print_udp_packet(const unsigned char *data, int size, int temp_s) {
    //for (int i=temp_s; i>0; i-=udp->length)
    struct udp_header *udp = (struct udp_header *)(data);

    printf("============================\n");
    printf("Src Port: %u\n", ntohs(udp->source_port));
    printf("Des Port: %u\n", ntohs(udp->dest_port));
    printf("UDP Packet Length: %u\n", ntohs(udp->length));
    printf("Checksum: 0x%x\n", ntohs(udp->checksum));

    printf("Data: ");
    for (int i = sizeof(struct udp_header); i < size; i++) {
        if (data[i] >= 32 && data[i] <= 126) {
            printf("%c", data[i]); // ASCII characters
        } else {
            printf("."); // Non-printable characters
        }
    }
    printf("\n\n");
    int rem_packet =size-ntohs(udp->length);
    printf("Remaining size: %d\n", rem_packet);
    if (rem_packet>0){
        print_udp_packet(data-rem_packet, rem_packet,temp_s);
    }
}

// Function to read and parse a PCAP file
void read_pcap_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    unsigned char buffer[65536]; 
    int packet_count = 0;

    fseek(file, PCAP_GLOBAL_HEADER_LEN, SEEK_SET);

    while (fread(buffer, 1, SKIP_BYTES, file) == SKIP_BYTES) {






        int udp_data_size = fread(buffer, 1, sizeof(buffer), file);
        int tempsize = udp_data_size;
        if (udp_data_size > 0) {

            
                printf("%d", udp_data_size);
                printf("Packet #%d:\n", ++packet_count);
                print_udp_packet(buffer, udp_data_size, tempsize);


            
            
            
        } else {
            break;
        }
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
