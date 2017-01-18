import psutil


def find_test_instance(iss, tag):
    match = {"-i": iss, "-t": tag}

    for proc in psutil.process_iter():
        try:
            cmd = proc.cmdline()
        except psutil.AccessDenied:
            continue

        if len(cmd) < 5:
            continue

        flag = 0
        for first, second in match.items():
            try:
                i = cmd.index(first)
            except ValueError:
                break

            if cmd[i + 1] != second:
                break
            else:
                flag += 1

        if flag == len(match):
            return proc
    return None


def find_test_instances(prog):
    pid = {}
    for proc in psutil.process_iter():
        try:
            cmd = proc.cmdline()
        except psutil.AccessDenied:
            continue

        if len(cmd) > 5:
            if cmd[0].endswith('Python') and cmd[1].endswith(prog):
                i = cmd.index('-i')
                iss = cmd[i + 1]
                i = cmd.index('-t')
                tag = cmd[i + 1]
                i = cmd.index('-p')
                port = cmd[i + 1]
                pid[proc.pid] = {'iss': iss, 'tag': tag, 'port': port}

    return pid


def kill_test_instance(iss, tag):
    proc = find_test_instance(iss, tag)
    if proc:
        proc.kill()


def kill_process(pid):
    proc = psutil.Process(pid)
    proc.kill()


def isrunning(iss, tag):
    proc = find_test_instance(iss, tag)
    if proc:
        return proc.pid
    else:
        return 0


def pid_isrunning(pid):
    proc = psutil.Process(pid)
    return proc


if __name__ == "__main__":
    # iss = sys.argv[1]
    # tag = sys.argv[2]

    inst = find_test_instances('optest.py')
    print(inst)
