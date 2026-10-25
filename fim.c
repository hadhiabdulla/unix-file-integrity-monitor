/*
 * fim.c - File Integrity Monitor
 * Unix System Programming Mini Project
 *
 * Watches a directory tree, hashes every file with SHA-256, and raises
 * an alert whenever a file is modified, created, or deleted.
 *
 * USP concepts demonstrated:
 *   - File I/O        : open(), read(), close()        (hashing files)
 *   - Directories     : opendir(), readdir(), closedir() (tree traversal)
 *   - File metadata   : stat()                          (size, mtime, type)
 *   - Processes       : fork(), setsid()                (daemon mode)
 *   - Signals         : sigaction() on SIGINT/SIGTERM   (graceful shutdown)
 *   - Inter-process   : exit status of check mode usable in shell scripts
 *
 * Build : gcc -Wall -Wextra -O2 -std=c11 -o fim fim.c   (or just `make`)
 * Usage : ./fim init    <directory>
 *         ./fim check   <directory>
 *         ./fim monitor <directory> [-i seconds] [--daemon]
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* SHA-256 (public-domain style, self contained - no crypto library)   */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  data[64];
    size_t   datalen;
} SHA256_CTX;

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)  (ROTR(x,2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x)  (ROTR(x,6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7)  ^ ROTR(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[])
{
    uint32_t a,b,c,d,e,f,g,h,t1,t2,m[64];
    int i,j;

    for (i = 0, j = 0; i < 16; i++, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) |
               ((uint32_t)data[j+2] << 8) | ((uint32_t)data[j+3]);
    for (; i < 64; i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }

    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen  = 0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[32])
{
    size_t i = ctx->datalen;

    ctx->data[i++] = 0x80;
    if (ctx->datalen < 56) {
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; i++) {
        hash[i]      = (uint8_t)((ctx->state[0] >> (24 - i*8)) & 0xff);
        hash[i+4]    = (uint8_t)((ctx->state[1] >> (24 - i*8)) & 0xff);
        hash[i+8]    = (uint8_t)((ctx->state[2] >> (24 - i*8)) & 0xff);
        hash[i+12]   = (uint8_t)((ctx->state[3] >> (24 - i*8)) & 0xff);
        hash[i+16]   = (uint8_t)((ctx->state[4] >> (24 - i*8)) & 0xff);
        hash[i+20]   = (uint8_t)((ctx->state[5] >> (24 - i*8)) & 0xff);
        hash[i+24]   = (uint8_t)((ctx->state[6] >> (24 - i*8)) & 0xff);
        hash[i+28]   = (uint8_t)((ctx->state[7] >> (24 - i*8)) & 0xff);
    }
}

/* Hash a whole file with open()/read()/close(). Returns 0 on success. */
static int hash_file(const char *path, char out_hex[65])
{
    uint8_t buf[4096], digest[32];
    SHA256_CTX ctx;
    ssize_t n;
    int fd, i;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    sha256_init(&ctx);
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        sha256_update(&ctx, buf, (size_t)n);
    close(fd);

    if (n < 0)
        return -1;

    sha256_final(&ctx, digest);
    for (i = 0; i < 32; i++)
        sprintf(out_hex + i*2, "%02x", digest[i]);
    out_hex[64] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* Snapshot of the watched directory                                   */
/* ------------------------------------------------------------------ */

#define MAX_PATH_LEN 4096
#define BASELINE_NAME ".fim_baseline"
#define LOG_NAME      ".fim.log"

typedef struct {
    char   path[MAX_PATH_LEN];
    char   hash[65];
    off_t  size;
    time_t mtime;
} FileRec;

typedef struct {
    FileRec *recs;
    size_t   count;
    size_t   cap;
} Snapshot;

static void snap_init(Snapshot *s) { s->recs = NULL; s->count = 0; s->cap = 0; }
static void snap_free(Snapshot *s) { free(s->recs); snap_init(s); }

static int snap_add(Snapshot *s, const char *path, const char *hash,
                    off_t size, time_t mtime)
{
    FileRec *r;
    if (s->count == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 64;
        FileRec *nr = realloc(s->recs, ncap * sizeof(FileRec));
        if (!nr)
            return -1;
        s->recs = nr;
        s->cap = ncap;
    }
    r = &s->recs[s->count++];
    snprintf(r->path, sizeof(r->path), "%s", path);
    snprintf(r->hash, sizeof(r->hash), "%s", hash);
    r->size  = size;
    r->mtime = mtime;
    return 0;
}

static FileRec *snap_find(Snapshot *s, const char *path)
{
    size_t i;
    for (i = 0; i < s->count; i++)
        if (strcmp(s->recs[i].path, path) == 0)
            return &s->recs[i];
    return NULL;
}

/* Recursively walk dir with opendir()/readdir()/stat() and hash files. */
static int scan_dir(const char *dir, Snapshot *snap)
{
    DIR *dp;
    struct dirent *entry;
    struct stat st;
    char full[MAX_PATH_LEN], hash[65];

    dp = opendir(dir);
    if (!dp) {
        fprintf(stderr, "fim: cannot open directory '%s': %s\n",
                dir, strerror(errno));
        return -1;
    }

    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        /* never watch our own baseline / log files */
        if (strcmp(entry->d_name, BASELINE_NAME) == 0 ||
            strcmp(entry->d_name, LOG_NAME) == 0)
            continue;

        snprintf(full, sizeof(full), "%s/%s", dir, entry->d_name);

        if (lstat(full, &st) < 0) {
            fprintf(stderr, "fim: warning: cannot stat '%s': %s\n",
                    full, strerror(errno));
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (scan_dir(full, snap) < 0)
                continue;   /* unreadable subdir - keep going */
        } else if (S_ISREG(st.st_mode)) {
            if (hash_file(full, hash) == 0)
                snap_add(snap, full, hash, st.st_size, st.st_mtime);
            else
                fprintf(stderr, "fim: warning: cannot read '%s'\n", full);
        }
    }
    closedir(dp);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Baseline persistence (plain text: "<hash>  <size>  <mtime>  <path>") */
/* ------------------------------------------------------------------ */

static void baseline_path(const char *dir, char out[MAX_PATH_LEN])
{
    snprintf(out, MAX_PATH_LEN, "%s/%s", dir, BASELINE_NAME);
}

static int baseline_save(const char *dir, Snapshot *snap)
{
    char path[MAX_PATH_LEN];
    FILE *f;
    size_t i;

    baseline_path(dir, path);
    f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "fim: cannot write baseline '%s': %s\n",
                path, strerror(errno));
        return -1;
    }
    for (i = 0; i < snap->count; i++)
        fprintf(f, "%s  %lld  %lld  %s\n",
                snap->recs[i].hash,
                (long long)snap->recs[i].size,
                (long long)snap->recs[i].mtime,
                snap->recs[i].path);
    fclose(f);
    return 0;
}

static int baseline_load(const char *dir, Snapshot *snap)
{
    char path[MAX_PATH_LEN], line[MAX_PATH_LEN + 160];
    FILE *f;

    baseline_path(dir, path);
    f = fopen(path, "r");
    if (!f)
        return -1;

    while (fgets(line, sizeof(line), f)) {
        char hash[65], fpath[MAX_PATH_LEN];
        long long size, mtime;
        if (sscanf(line, "%64s %lld %lld %4095[^\n]",
                   hash, &size, &mtime, fpath) == 4)
            snap_add(snap, fpath, hash, (off_t)size, (time_t)mtime);
    }
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Output helpers                                                      */
/* ------------------------------------------------------------------ */

static int use_color = 0;
#define C_RED     "\033[1;31m"
#define C_GREEN   "\033[1;32m"
#define C_YELLOW  "\033[1;33m"
#define C_CYAN    "\033[1;36m"
#define C_RESET   "\033[0m"

static void timestamp(char out[16])
{
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    strftime(out, 16, "%H:%M:%S", tm);
}

static void info(const char *fmt, const char *arg)
{
    char ts[16];
    timestamp(ts);
    if (use_color)
        printf("%s[%s]%s ", C_CYAN, ts, C_RESET);
    else
        printf("[%s] ", ts);
    printf(fmt, arg);
    putchar('\n');
    fflush(stdout);
}

typedef enum { ALERT_MODIFIED, ALERT_NEW, ALERT_DELETED } AlertKind;

static void alert(AlertKind kind, const char *path)
{
    char ts[16];
    const char *label, *color;
    timestamp(ts);

    switch (kind) {
    case ALERT_MODIFIED: label = "MODIFIED"; color = C_RED;    break;
    case ALERT_NEW:      label = "NEW FILE"; color = C_YELLOW; break;
    default:             label = "DELETED";  color = C_RED;    break;
    }

    if (use_color)
        printf("%s[ALERT %s] %s:%s %s\n", color, ts, label, C_RESET, path);
    else
        printf("[ALERT %s] %s: %s\n", ts, label, path);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/* Compare a fresh scan against the baseline. Returns # of changes.    */
/* ------------------------------------------------------------------ */

static int diff_snapshots(Snapshot *base, Snapshot *cur, int verbose_ok)
{
    size_t i;
    int changes = 0;

    /* new + modified */
    for (i = 0; i < cur->count; i++) {
        FileRec *b = snap_find(base, cur->recs[i].path);
        if (!b) {
            alert(ALERT_NEW, cur->recs[i].path);
            snap_add(base, cur->recs[i].path, cur->recs[i].hash,
                     cur->recs[i].size, cur->recs[i].mtime);
            changes++;
        } else if (strcmp(b->hash, cur->recs[i].hash) != 0) {
            alert(ALERT_MODIFIED, cur->recs[i].path);
            snprintf(b->hash, sizeof(b->hash), "%s", cur->recs[i].hash);
            b->size  = cur->recs[i].size;
            b->mtime = cur->recs[i].mtime;
            changes++;
        }
    }

    /* deleted: in baseline but not in current scan */
    for (i = 0; i < base->count; i++) {
        if (!snap_find(cur, base->recs[i].path)) {
            alert(ALERT_DELETED, base->recs[i].path);
            /* remove from baseline by swapping with last */
            base->recs[i] = base->recs[base->count - 1];
            base->count--;
            i--;
            changes++;
        }
    }

    if (!changes && verbose_ok) {
        char ts[16];
        timestamp(ts);
        if (use_color)
            printf("%s[%s]%s OK - no changes detected\n", C_GREEN, ts, C_RESET);
        else
            printf("[%s] OK - no changes detected\n", ts);
        fflush(stdout);
    }
    return changes;
}

/* ------------------------------------------------------------------ */
/* Signal handling for the monitor loop                                */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

static void install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

static int cmd_init(const char *dir)
{
    Snapshot snap;
    snap_init(&snap);

    info("Scanning %s ...", dir);
    if (scan_dir(dir, &snap) < 0) {
        snap_free(&snap);
        return 1;
    }
    if (baseline_save(dir, &snap) < 0) {
        snap_free(&snap);
        return 1;
    }

    printf("[FIM] Baseline created: %zu file(s) hashed with SHA-256\n", snap.count);
    {
        char bp[MAX_PATH_LEN];
        baseline_path(dir, bp);
        printf("[FIM] Baseline saved to %s\n", bp);
        printf("[FIM] Run: ./fim monitor %s\n", dir);
    }
    snap_free(&snap);
    return 0;
}

static int cmd_check(const char *dir)
{
    Snapshot base, cur;
    int changes;

    snap_init(&base);
    snap_init(&cur);

    if (baseline_load(dir, &base) < 0) {
        fprintf(stderr, "fim: no baseline for '%s' - run './fim init %s' first\n",
                dir, dir);
        return 2;
    }
    if (scan_dir(dir, &cur) < 0) {
        snap_free(&base);
        snap_free(&cur);
        return 2;
    }

    changes = diff_snapshots(&base, &cur, 1);
    if (changes) {
        printf("[FIM] %d change(s) detected (baseline NOT updated in check mode)\n",
               changes);
    }
    snap_free(&base);
    snap_free(&cur);
    return changes ? 1 : 0;   /* usable as exit status in scripts */
}

static int cmd_monitor(const char *dir, int interval, int daemon_mode)
{
    Snapshot base;
    int total_alerts = 0;
    time_t started = time(NULL);
    char absdir[MAX_PATH_LEN];

    /* resolve to an absolute path before any daemon chdir() games */
    if (!realpath(dir, absdir)) {
        fprintf(stderr, "fim: cannot resolve '%s': %s\n", dir, strerror(errno));
        return 2;
    }

    snap_init(&base);
    if (baseline_load(absdir, &base) < 0) {
        fprintf(stderr, "fim: no baseline for '%s' - run './fim init %s' first\n",
                absdir, absdir);
        snap_free(&base);
        return 2;
    }

    if (daemon_mode) {
        /* classic daemonize: fork + setsid, log to <dir>/.fim.log */
        pid_t pid = fork();
        if (pid < 0) {
            perror("fim: fork");
            snap_free(&base);
            return 2;
        }
        if (pid > 0) {
            printf("[FIM] Daemon started (PID %d), logging to %s/%s\n",
                   (int)pid, absdir, LOG_NAME);
            printf("[FIM] Stop it with: kill %d\n", (int)pid);
            snap_free(&base);
            return 0;
        }
        /* child */
        if (setsid() < 0)
            _exit(2);
        {
            char logp[MAX_PATH_LEN + 32];
            int fd;
            snprintf(logp, sizeof(logp), "%s/%s", absdir, LOG_NAME);
            fd = open(logp, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd >= 0) {
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                if (fd > STDERR_FILENO)
                    close(fd);
            }
            close(STDIN_FILENO);
        }
        use_color = 0;
    }

    install_signal_handlers();

    info("Monitoring", NULL);
    printf("       directory : %s\n", absdir);
    printf("       files     : %zu under watch\n", base.count);
    printf("       interval  : every %d second(s)\n", interval);
    printf("       stop      : Ctrl+C\n\n");
    fflush(stdout);

    while (running) {
        Snapshot cur;
        int changes, i;
        snap_init(&cur);

        if (scan_dir(absdir, &cur) == 0) {
            changes = diff_snapshots(&base, &cur, 0);
            total_alerts += changes;
        }
        snap_free(&cur);

        /* sleep in 1s slices so Ctrl+C is answered immediately */
        for (i = 0; i < interval && running; i++)
            sleep(1);
    }

    printf("\n[FIM] Monitor stopped.\n");
    printf("[FIM] Watched %zu file(s) for %lld second(s), %d alert(s) raised.\n",
           base.count, (long long)(time(NULL) - started), total_alerts);
    snap_free(&base);
    return 0;
}

static void usage(const char *prog)
{
    printf("fim - File Integrity Monitor (Unix System Programming mini project)\n\n");
    printf("Usage:\n");
    printf("  %s init    <dir>                 create the SHA-256 baseline\n", prog);
    printf("  %s check   <dir>                 one-shot integrity check\n", prog);
    printf("  %s monitor <dir> [-i sec] [--daemon]\n", prog);
    printf("                                   watch continuously (default 2s)\n");
    printf("\nOptions:\n");
    printf("  -i sec     scan interval in seconds (default: 2)\n");
    printf("  --daemon   run in background, alerts go to <dir>/%s\n", LOG_NAME);
    printf("\nAlerts: MODIFIED (content changed), NEW FILE, DELETED\n");
}

int main(int argc, char *argv[])
{
    const char *cmd, *dir;
    int i, interval = 2, daemon_mode = 0;

    use_color = isatty(STDOUT_FILENO);

    if (argc < 3) {
        usage(argv[0]);
        return 2;
    }
    cmd = argv[1];
    dir = argv[2];

    for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--daemon") == 0)
            daemon_mode = 1;
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc)
            interval = atoi(argv[++i]);
        else {
            fprintf(stderr, "fim: unknown option '%s'\n", argv[i]);
            return 2;
        }
    }
    if (interval < 1)
        interval = 1;

    if (strcmp(cmd, "init") == 0)
        return cmd_init(dir);
    if (strcmp(cmd, "check") == 0)
        return cmd_check(dir);
    if (strcmp(cmd, "monitor") == 0)
        return cmd_monitor(dir, interval, daemon_mode);

    usage(argv[0]);
    return 2;
}
