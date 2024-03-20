from bcc import BPF
from time import sleep
from ctypes import c_uint32, c_int64
from threading import Thread
from queue import Queue
from enum import Enum
import argparse


class ELifeType(Enum):
    execve = 1
    execve_arg = 2
    nanosleep = 3
    waitid = 4
    exit = 5


idtype_to_str = {0: "P_ALL", 1: "P_PID", 2: "P_PGID", 3: "P_PIDFD"}
lifes = [ELifeType.execve, ELifeType.nanosleep, ELifeType.waitid, ELifeType.exit]
lifes_str: list[str] = []
lifes_switch: dict[str, int] = {}
for life in lifes:
    lifes_str.append(life.name)
    lifes_switch[life.name] = 0


execve_args: dict[int, list[str]] = {}
q_print = Queue(128)


def args_collect(uid: int, tid: int, type: str, comm: str):
    # sleep for a while to collectl all args of execve
    sleep(0.2)
    data = comm
    if tid in execve_args:
        for arg in execve_args[tid]:
            data += " " + arg
        del execve_args[tid]
    q_print.put((uid, tid, type, data))


# on_* func is called when *_output perf output info
def on_execve(cpu, data, size):
    data = bpf_prog["execve_output"].event(data)
    if data.type == ELifeType.execve.value:
        Thread(target=args_collect, args=(data.uid, data.tid, ELifeType.execve.name, data.data.decode())).start()

    elif data.type == ELifeType.execve_arg.value:
        if not data.tid in execve_args:
            execve_args[data.tid] = []
        execve_args[data.tid].append(data.data.decode())


def on_nanosleep(cpu, data, size):
    data = bpf_prog["nanosleep_output"].event(data)
    q_print.put((data.uid, data.tid, ELifeType.nanosleep.name, f"{data.sec}s {data.nsec}ns"))


def on_waitid(cpu, data, size):
    data = bpf_prog["waitid_output"].event(data)
    q_print.put((data.uid, data.tid, ELifeType.waitid.name, f"idtype:{idtype_to_str[data.idtype]} of id:{data.id}"))


def on_exit(cpu, data, size):
    data = bpf_prog["exit_output"].event(data)
    q_print.put((data.uid, data.tid, ELifeType.exit.name, f"code: {data.exit_code}"))


def print_event():
    while True:
        (uid, tid, type, data) = q_print.get()
        if len(data) == 0:
            print(f"uid:{uid} tid:{tid} {type}")
        else:
            print(f"uid:{uid} tid:{tid} {type}: {data}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="通过ebpf监听进程生命周期事件")
    parser.add_argument("-u", "--uid", type=int, help="选择监听某个用户的进程，-1监听所有用户", default="-1")
    parser.add_argument("-t", "--tid", type=int, help="选择监听的进程tid，0监听所有进程", default="0")
    parser.add_argument(
        "-l",
        "--life",
        type=str,
        help="选择监听的生命周期事件，默认所有",
        choices=lifes_str,
        default=lifes_str,
        nargs="+",
    )
    args = parser.parse_args()
    for choice in args.life:
        lifes_switch[choice] = 1

    Thread(target=print_event, daemon=True).start()

    bpf_prog = BPF(src_file=b"bpf.c")
    # watch which user, if -1, all user
    bpf_prog["switch_table"][c_uint32(0)] = c_int64(args.uid)
    # watch which process, if 0, all processes
    bpf_prog["switch_table"][c_uint32(10)] = c_int64(args.tid)

    for life in lifes:
        # for each tracepoint, set each switch_table map entry to 1 to use it,
        # or 0 to not use it
        bpf_prog["switch_table"][c_uint32(life.value)] = c_int64(lifes_switch[life.name])

    bpf_prog["execve_output"].open_perf_buffer(on_execve)
    bpf_prog["nanosleep_output"].open_perf_buffer(on_nanosleep)
    bpf_prog["waitid_output"].open_perf_buffer(on_waitid)
    bpf_prog["exit_output"].open_perf_buffer(on_exit)

    while True:
        bpf_prog.perf_buffer_poll()
