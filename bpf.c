#include <linux/sched.h>

BPF_HASH(switch_table, u32, s64);
enum life_types { execve = 1, execve_arg, nanosleep, waitid, exit };

static s64 test_uid() {
    // when switch_table[0] == -1, watch all user's process
    // else watch only the uid process
    u32  uidkey    = 0;
    s64 *puid      = switch_table.lookup(&uidkey);
    s64  watch_uid = 0;
    if (puid) watch_uid = *puid;

    s64 current_uid = (u32)bpf_get_current_uid_gid();
    // watch all users
    if (watch_uid == -1) return current_uid;
    // return -1 means not watch this
    if (watch_uid != current_uid) return -1;
    return current_uid;
}

static u32 test_tid() {
    u32  pidkey    = 10;
    s64 *ppid      = switch_table.lookup(&pidkey);
    u32  watch_pid = 0;
    if (ppid) watch_pid = *ppid;

    u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    if (watch_pid == 0) return current_pid;
    if (watch_pid != current_pid) return 0;
    return current_pid;
}

static u32 test_use(enum life_types my_type) {
    // test should this tracepoint be used
    s64 *pr = switch_table.lookup(&my_type);
    u32  r  = 0;
    if (pr) r = *pr;
    return r;
}


BPF_PERF_OUTPUT(execve_output);
struct execve_t {
    u32             uid;
    u32             tid;
    enum life_types type;
    char            data[256];
};
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    // watch process execve event
    s64 t = test_uid();
    if (t == -1) return 0;
    u32 uid = t;
    u32 tid = test_tid();
    if (!test_use(execve) || !tid) return 0;

    struct execve_t e;
    __builtin_memset(&e, 0, sizeof(e));
    e.uid  = uid;
    e.tid  = tid;
    e.type = execve;
    bpf_probe_read_user_str(e.data, sizeof(e.data), args->filename);
    execve_output.perf_submit(args, &e, sizeof(e));

    char **argv = (char **)args->argv;
    if (argv[0] == NULL) return 0;
    e.type = execve_arg;
    u32 i  = 1;
    while (i < 16) {
        if (argv[i] == NULL) break;

        u32 len = bpf_probe_read_user_str(e.data, sizeof(e.data), argv[i]);
        if (len <= 0) {
            break;
        }
        execve_output.perf_submit(args, &e, sizeof(e));
        i++;
    }

    return 0;
}


BPF_PERF_OUTPUT(nanosleep_output);
struct nanosleep_t {
    u32 uid;
    u32 tid;
    u64 sec;
    u64 nsec;
};
TRACEPOINT_PROBE(syscalls, sys_enter_nanosleep) {
    // watch process sleep event
    s64 t = test_uid();
    if (t == -1) return 0;
    u32 uid = t;
    u32 tid = test_tid();
    if (!test_use(nanosleep) || !tid) return 0;

    struct nanosleep_t e;
    __builtin_memset(&e, 0, sizeof(e));
    e.uid = uid;
    e.tid = tid;
    bpf_probe_read_user(&e.sec, sizeof(e.sec), &args->rqtp->tv_sec);
    bpf_probe_read_user(&e.nsec, sizeof(e.nsec), &args->rqtp->tv_nsec);
    nanosleep_output.perf_submit(args, &e, sizeof(e));

    return 0;
}


BPF_PERF_OUTPUT(waitid_output);
struct waitid_t {
    u32 uid;
    u32 tid;
    u64 idtype;
    u64 id;
};
TRACEPOINT_PROBE(syscalls, sys_enter_waitid) {
    // watch waitid event
    s64 t = test_uid();
    if (t == -1) return 0;
    u32 uid = t;
    u32 tid = test_tid();
    if (!test_use(waitid) || !tid) return 0;

    struct waitid_t e;
    __builtin_memset(&e, 0, sizeof(e));
    e.uid = uid;
    e.tid = tid;
    bpf_probe_read_kernel(&e.idtype, sizeof(e.idtype), &args->which);
    bpf_probe_read_kernel(&e.id, sizeof(e.id), &args->upid);
    waitid_output.perf_submit(args, &e, sizeof(e));

    return 0;
}


BPF_PERF_OUTPUT(exit_output);
struct exit_t {
    u32 uid;
    u32 tid;
    int exit_code;
};
TRACEPOINT_PROBE(sched, sched_process_exit) {
    // watch exit event
    // cannot use sys_enter_exit to collect, cause some events will not be watched
    s64 t = test_uid();
    if (t == -1) return 0;
    u32 uid = t;
    u32 tid = test_tid();
    if (!test_use(exit) || !tid) return 0;

    struct exit_t e;
    __builtin_memset(&e, 0, sizeof(e));
    e.uid                    = uid;
    e.tid                    = tid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e.exit_code              = task->exit_code;
    exit_output.perf_submit(args, &e, sizeof(e));

    return 0;
}