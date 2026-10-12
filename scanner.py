# -*- coding: utf-8 -*-
"""
高校代理扫描器 —— 三阶段 + 分片 + 断点续跑 + 短路优化
阶段 1 common：约 400 探针端口（TCP 探活，发现 1 个 open 立即跳过剩余端口）
阶段 2 proxy ：171 常见代理端口（只扫存活 IP，必须扫完所有端口）
阶段 3 full  ：65535 全端口（只扫 proxy 未找到代理的 IP，必须扫完所有端口）
验证方式：curl，3 种协议（http / socks5 / socks4）
验证目标：http://myip.ipip.net
"""

import os
import re
import sys
import json
import time
import socket
import shutil
import argparse
import subprocess
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============ 配置 ============
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
CONNECT_TIMEOUT = 5
MAX_TIME = 15

MAX_RUNTIME_SEC = int(os.environ.get('MAX_RUNTIME_SEC', 20880))

PROBE_BATCH_SIZE = 50
SCAN_BATCH_SIZE = 30


def _build_common_ports():
    """约 400 探针端口，优先级排序"""
    priority = [
        80, 443, 22, 8080, 3389, 8443, 8000, 8888, 3128, 1080,
        8081, 8001, 8082, 8083, 8880, 9000, 9090, 7890, 10808,
        81, 8008, 8009, 8088, 8090, 9443, 10443, 18080,
        5000, 5060, 3000, 4000, 5432, 3306, 6379, 27017, 1433, 1521,
        21, 23, 25, 110, 143, 465, 587, 993, 995, 5900, 5901,
    ]

    others = set()
    others.update([20, 53, 69, 79, 88, 111, 119, 123, 135, 137, 138, 139,
                   161, 162, 179, 194, 389, 445, 500, 512, 513, 514, 515,
                   520, 548, 554, 623, 631, 636, 873, 989, 990, 1025])
    others.update([1434, 1701, 1723, 1883, 1900, 2049, 2082, 2083, 2121,
                   2181, 2222, 2375, 2376, 2480, 3001, 3260, 3478, 3479,
                   3480, 3690, 4040, 4443, 4444, 4505, 4506, 4711, 4848,
                   5001, 5222, 5228, 5357, 5555, 5672, 5678, 5800, 5984,
                   5985, 5986, 6000, 6443, 7001, 7002, 7070, 7443, 7474,
                   7680])
    others.update([8002, 8003, 8004, 8005, 8006, 8007, 8010, 8043, 8069,
                   8084, 8085, 8086, 8087, 8089, 8091, 8092, 8093, 8094,
                   8095, 8096, 8097, 8098, 8099, 8100, 8118, 8123, 8161,
                   8180, 8200, 8222, 8243, 8280, 8333, 8400, 8444, 8500,
                   8529, 8580, 8600, 8800, 8834, 8843, 8850, 8881, 8882,
                   8883, 8884, 8885, 8886, 8887, 8889, 8890, 8900, 8983])
    others.update([9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009,
                   9010, 9042, 9043, 9060, 9080, 9091, 9092, 9093, 9094,
                   9095, 9096, 9097, 9098, 9099, 9100, 9200, 9300, 9400,
                   9500, 9600, 9800, 9999, 1081, 1082, 1083, 1084,
                   1085, 1086, 1087, 1088, 1089, 1090, 10809, 10810,
                   10811, 10812, 10813, 10814, 10815, 10816, 10817, 10818,
                   10819, 10820, 11211, 11311, 12000, 12345, 13306, 14000,
                   14147, 14265, 15000, 15001, 16379, 16992, 16993, 17000,
                   17698, 18081, 18082, 18083, 18084, 18085, 18086, 18087,
                   18088, 18089, 18090, 18091, 18092, 18093, 18094, 18095,
                   19090, 19132, 20000, 20202, 20520, 20600, 23791, 25000,
                   25143, 25565, 26000, 26379, 27018, 27019, 27080, 28017,
                   30001, 31280, 32100, 32768, 32800, 33000, 33890, 34443,
                   34567, 36379, 38080, 38081, 38082, 38083, 38084, 38085,
                   38086, 38087, 38088, 38089, 38090, 38888, 40000, 42000,
                   44343, 44443, 45000, 48080, 48888, 50000, 50001, 50050,
                   50051, 50100, 51000, 53000, 54000, 55553, 55554, 55555,
                   56789, 58080, 58888, 59000, 60000, 61000, 62000, 63333,
                   64738, 65000, 65530, 65531, 65532, 65533, 65534, 65535])
    others.update([10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007,
                   10008, 10009, 10010, 10050, 10051, 10080, 10081, 10082,
                   10083, 10084, 10085, 10086, 10250, 10255, 10256, 10554])

    groups = [
        (1080, 1090), (7890, 7899), (8000, 8010), (8080, 8090),
        (8888, 8890), (9000, 9010), (9090, 9099), (10000, 10010),
        (10080, 10086), (10808, 10820), (1194, 1199), (2052, 2096),
        (3128, 3130), (51820, 51830), (8388, 8389), (8443, 8444),
        (9050, 9051), (9150, 9151),
    ]
    for a, b in groups:
        others.update(range(a, b + 1))

    result = []
    seen = set()
    for p in priority:
        if p not in seen:
            seen.add(p)
            result.append(p)
    for p in sorted(others):
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


def _build_proxy_ports():
    """171 常见代理端口"""
    groups = [
        (1080, 1090), (10808, 10820), (7890, 7899), (8080, 8090),
        (8000, 8010), (8888, 8890), (9000, 9010), (9090, 9099),
        (10000, 10010), (10080, 10086), (3128, 3130), (8388, 8389),
        (8443, 8444), (2052, 2096), (51820, 51830), (1194, 1199),
        (9050, 9051), (9150, 9151),
    ]
    s = set()
    for a, b in groups:
        s.update(range(a, b + 1))
    return sorted(s)


COMMON_PORTS = _build_common_ports()
PROXY_PORTS = _build_proxy_ports()
FULL_PORTS = list(range(1, 65536))

parser = argparse.ArgumentParser()
parser.add_argument('--shard', type=int, default=0)
parser.add_argument('--shard-total', type=int, default=1)
args, _ = parser.parse_known_args()

SHARD_INDEX = args.shard
SHARD_TOTAL = args.shard_total

TCP_TIMEOUT = 3
VERIFY_TIMEOUT = 30
VERIFY_RETRY = 0
VERIFY_DELAY = 0.0
TCP_WORKERS = 20
PORT_WORKERS = 10
IP_COOLDOWN = 0.5
VERIFY_RATE_LIMIT = 1

INPUT_FILE = 'ip_list.txt'
PHASE_FILE = 'phase.json'
RUNNER_TEMP = os.environ.get('RUNNER_TEMP', '/tmp')

if SHARD_TOTAL > 1:
    STATE_FILE = 'progress_shard%d.json' % SHARD_INDEX
    OUTPUT_FILE = 'working_proxies_shard%d.txt' % SHARD_INDEX
    OPEN_IPS_FILE = 'open_ips_shard%d.txt' % SHARD_INDEX
    PROXY_MISSING_FILE = 'proxy_missing_shard%d.txt' % SHARD_INDEX
else:
    STATE_FILE = 'progress.json'
    OUTPUT_FILE = 'working_proxies.txt'
    OPEN_IPS_FILE = 'open_ips.txt'
    PROXY_MISSING_FILE = 'proxy_missing.txt'

CRLF = '\r\n'

CURL = shutil.which('curl') or 'curl'

PROTOCOLS = ('http', 'socks5', 'socks4')


def log(msg):
    print(msg, flush=True)


_WS_RE = re.compile(r'\s+')


def _clean_note(s):
    if not s:
        return ''
    s = s.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')
    s = s.replace('@', ' ')
    return _WS_RE.sub(' ', s).strip()


QQWRY_RANGE_RE = re.compile(
    r'(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})'
)
SINGLE_IP_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')


def _valid_ipv4(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def parse_ip_range(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    for tok in line.split():
        if '/' in tok:
            try:
                net = ipaddress.ip_network(tok, strict=False)
                if net.version != 4:
                    continue
                return int(net.network_address), int(net.broadcast_address), ''
            except Exception:
                pass
    m = QQWRY_RANGE_RE.search(line)
    if m:
        a, b = m.group(1), m.group(2)
        if _valid_ipv4(a) and _valid_ipv4(b):
            sa = int(ipaddress.IPv4Address(a))
            sb = int(ipaddress.IPv4Address(b))
            note = ''
            if '|' in line:
                note = _clean_note(line.split('|', 1)[1])
            return min(sa, sb), max(sa, sb), note
    m = SINGLE_IP_RE.search(line)
    if m:
        a = m.group(1)
        if _valid_ipv4(a):
            return int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(a)), ''
    return None


def load_ip_ranges(path):
    ranges = []
    with open(path, 'r', encoding='utf-8-sig', errors='ignore') as f:
        for line in f:
            r = parse_ip_range(line)
            if r:
                ranges.append(r)
    return ranges


def ip_int_to_str(ip_int):
    return str(ipaddress.IPv4Address(ip_int))


def load_existing_proxies(path):
    s = set()
    if not os.path.exists(path):
        return s
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('@') or line.startswith('#'):
                    continue
                if '@' in line:
                    s.add(line.split('@', 1)[0].strip())
                elif '#' in line:
                    s.add(line.split('#', 1)[0].strip())
                else:
                    parts = line.split()
                    if parts:
                        s.add(parts[0])
    except Exception:
        pass
    return s


def load_ip_set(path):
    s = set()
    if not os.path.exists(path):
        return s
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:
                    s.add(line)
    except Exception:
        pass
    return s


def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def save_json(path, data):
    try:
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception as e:
        log('[!] 保存 %s 失败: %s' % (path, e))


_rate_lock = threading.Lock()
_rate_last = [0.0]


def verify_rate_wait():
    if VERIFY_RATE_LIMIT <= 0:
        return
    min_interval = 1.0 / VERIFY_RATE_LIMIT
    while True:
        with _rate_lock:
            now = time.time()
            wait = _rate_last[0] + min_interval - now
            if wait <= 0:
                _rate_last[0] = now
                return
        time.sleep(min(wait, 0.2))


def tcp_check(ip, port, timeout=TCP_TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _build_curl_args(ip, port, protocol):
    address = '%s:%d' % (ip, port)
    if protocol == 'http':
        return ['-x', address, 'http://myip.ipip.net']
    if protocol == 'socks5':
        return ['--socks5-hostname', address, 'http://myip.ipip.net']
    if protocol == 'socks4':
        return ['--socks4a', address, 'http://myip.ipip.net']
    return None


def verify_proxy(ip, port, protocol):
    args = _build_curl_args(ip, port, protocol)
    if args is None:
        return False
    verify_rate_wait()
    cmd = [
        CURL,
        '-sS',
        '-L',
        '-4',
        '--connect-timeout', str(CONNECT_TIMEOUT),
        '--max-time', str(MAX_TIME),
        '-A', UA,
    ] + args
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=MAX_TIME + 3)
        output = proc.stdout.decode('utf-8', errors='ignore')
        if '当前 IP' in output or '当前IP' in output:
            return True
        return False
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def scan_port_common(ip, port):
    """common 阶段：只做 TCP 探活"""
    return tcp_check(ip, port), None


def scan_port_full(ip, port):
    """proxy / full 阶段：TCP + 代理验证"""
    if not tcp_check(ip, port):
        return False, None
    for proto in PROTOCOLS:
        if verify_proxy(ip, port, proto):
            return True, (ip, port, proto)
    return True, None


def slice_ranges(ranges, shard_index, shard_total):
    if shard_total <= 1:
        return ranges
    total = sum(e - s + 1 for s, e, _ in ranges)
    shard_size = (total + shard_total - 1) // shard_total
    lo = shard_index * shard_size
    hi = min(lo + shard_size, total)
    if lo >= hi:
        return []
    result = []
    cursor = 0
    for s, e, note in ranges:
        span = e - s + 1
        seg_lo = cursor
        seg_hi = cursor + span
        if seg_hi <= lo or seg_lo >= hi:
            cursor = seg_hi
            continue
        local_lo = max(0, lo - seg_lo)
        local_hi = min(span, hi - seg_lo)
        result.append((s + local_lo, s + local_hi - 1, note))
        cursor = seg_hi
    return result


def expand_ranges_to_ips(ranges):
    flat = []
    for s, e, note in ranges:
        for ip_int in range(s, e + 1):
            flat.append((ip_int, note))
    return flat


def get_phase_config(phase):
    if phase == 'common':
        return COMMON_PORTS, None, OPEN_IPS_FILE, 'common', PROBE_BATCH_SIZE
    elif phase == 'proxy':
        return PROXY_PORTS, OPEN_IPS_FILE, PROXY_MISSING_FILE, 'proxy', SCAN_BATCH_SIZE
    elif phase == 'full':
        return FULL_PORTS, PROXY_MISSING_FILE, None, 'full', SCAN_BATCH_SIZE
    else:
        raise ValueError('未知阶段: %s' % phase)


def _skip_this_shard(state_file, output_filter_file, phase, ports_count):
    state = {
        'position': 0, 'done': 0, 'total_ips': 0, 'total_tasks': 0,
        'ports_count': ports_count, 'phase': phase,
        'shard_index': SHARD_INDEX, 'shard_total': SHARD_TOTAL,
        'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'completed': True,
        'completed_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'session': 1,
    }
    save_json(state_file, state)
    if output_filter_file:
        try:
            with open(output_filter_file, 'w', encoding='utf-8', newline='') as f:
                pass
        except Exception:
            pass


def main():
    if not os.path.exists(INPUT_FILE):
        log('未找到 %s' % INPUT_FILE)
        sys.exit(1)

    all_ranges = load_ip_ranges(INPUT_FILE)
    if not all_ranges:
        log('未读取到有效 IP 范围')
        sys.exit(1)

    phase_state = load_json(PHASE_FILE) or {
        'current': 'common',
        'common_completed': False,
        'proxy_completed': False,
        'full_completed': False,
    }
    current_phase = phase_state.get('current', 'common')
    PORTS, upstream_file, output_filter_file, phase_name, batch_size = get_phase_config(current_phase)

    ranges = slice_ranges(all_ranges, SHARD_INDEX, SHARD_TOTAL)
    ip_list = expand_ranges_to_ips(ranges)

    if upstream_file is not None:
        if os.path.exists(upstream_file):
            wanted = load_ip_set(upstream_file)
            if wanted:
                before = len(ip_list)
                ip_list = [(ip_int, note) for (ip_int, note) in ip_list
                           if ip_int_to_str(ip_int) in wanted]
                log('[%s] 上游过滤 (%s): %d → %d'
                    % (current_phase, upstream_file, before, len(ip_list)))
            else:
                log('[%s] 上游文件为空，本片无待扫 IP，跳过' % current_phase)
                _skip_this_shard(STATE_FILE, output_filter_file, current_phase, len(PORTS))
                return
        else:
            log('[%s] 无上游文件 %s，视为无待扫 IP，本片跳过'
                % (current_phase, upstream_file))
            _skip_this_shard(STATE_FILE, output_filter_file, current_phase, len(PORTS))
            return

    total_ips = len(ip_list)

    def ip_at_position(pos):
        return ip_list[pos]

    state = load_json(STATE_FILE)
    new_round = True
    if (state and not state.get('completed')
            and state.get('total_ips') == total_ips
            and state.get('phase') == current_phase):
        new_round = False

    if new_round:
        state = {
            'position': 0, 'done': 0, 'total_ips': total_ips,
            'phase': current_phase, 'shard_index': SHARD_INDEX,
            'shard_total': SHARD_TOTAL,
            'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'completed': False, 'session': 1,
        }
        with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as f:
            f.write('@ 代理扫描结果 [分片 %d/%d, 阶段 %s]'
                    % (SHARD_INDEX, SHARD_TOTAL, current_phase) + CRLF)
            f.write('@ 开始时间: %s' % state['started_at'] + CRLF)
            f.write('@' + '-' * 58 + CRLF)
        existing = set()
        log('=== 新一轮扫描 [分片 %d/%d, phase=%s] ==='
            % (SHARD_INDEX, SHARD_TOTAL, current_phase))
    else:
        state['session'] = state.get('session', 1) + 1
        existing = load_existing_proxies(OUTPUT_FILE)
        log('=== 续跑 [分片 %d/%d, phase=%s, session %d] ==='
            % (SHARD_INDEX, SHARD_TOTAL, current_phase, state['session']))
        log('上次位置: %d / %d (%.1f%%)'
            % (state['position'], total_ips,
               state['position'] * 100.0 / total_ips if total_ips else 0))

    log('本片 IP 段数: %d' % len(ranges))
    log('本片 IP 总数: %d' % total_ips)
    log('端口数: %d' % len(PORTS))
    log('每批端口: %d' % batch_size)
    short_circuit_note = '开启（找到 1 个 open 立即跳）' if current_phase == 'common' else '关闭（必须扫完所有端口）'
    log('短路: %s' % short_circuit_note)
    log('本次起点: IP #%d' % state['position'])
    log('已找到代理: %d' % len(existing))
    log('搜索连接超时: %d s | 验证超时: %d s' % (TCP_TIMEOUT, VERIFY_TIMEOUT))
    log('IP 并发: %d  ×  端口并发: %d  =  全局最大 %d 条连接'
        % (TCP_WORKERS, PORT_WORKERS, TCP_WORKERS * PORT_WORKERS))
    log('验证方式: curl (%s)' % CURL)
    log('验证目标: http://myip.ipip.net')
    log('验证协议: %s' % (', '.join(PROTOCOLS)))
    log('成功判定: 输出含"当前 IP"')
    log('curl 超时: 连接 %d s / 总 %d s' % (CONNECT_TIMEOUT, MAX_TIME))
    log('全局限速: %d 次/秒' % VERIFY_RATE_LIMIT if VERIFY_RATE_LIMIT > 0 else '不限速')
    log('最大运行时长: %d 秒 (%.2f 小时)'
        % (MAX_RUNTIME_SEC, MAX_RUNTIME_SEC / 3600.0))
    log('-' * 60)

    pos_lock = threading.Lock()
    current_pos = [state['position']]
    found_lock = threading.Lock()
    found_count = [len(existing)]
    processed_ips = [0]
    port_tasks = [0]
    stop_flag = [False]
    t0 = time.time()

    open_ips_lock = threading.Lock()
    open_ips = set()
    proxy_found_ips = set()
    proxy_missing_ips = set()

    def next_position():
        with pos_lock:
            if current_pos[0] >= total_ips:
                return None
            p = current_pos[0]
            current_pos[0] += 1
            return p

    port_pool = ThreadPoolExecutor(max_workers=TCP_WORKERS * PORT_WORKERS)
    scan_fn = scan_port_common if current_phase == 'common' else scan_port_full
    # ★ 只有 common 阶段短路
    short_circuit = (current_phase == 'common')

    def worker():
        while not stop_flag[0]:
            p = next_position()
            if p is None:
                return
            ip_int, note = ip_at_position(p)
            ip = ip_int_to_str(ip_int)

            ip_has_open = False
            ip_has_proxy = False

            for batch_start in range(0, len(PORTS), batch_size):
                if stop_flag[0]:
                    return
                # ★ 只有 common 阶段 + short_circuit=True 时提前退出
                if short_circuit and ip_has_open:
                    break

                batch = PORTS[batch_start:batch_start + batch_size]
                futures = []
                for port in batch:
                    key = '%s:%d' % (ip, port)
                    if key in existing:
                        continue
                    futures.append((port, port_pool.submit(scan_fn, ip, port)))

                for port, fut in futures:
                    if stop_flag[0]:
                        return
                    try:
                        is_open, r = fut.result()
                    except Exception:
                        is_open, r = False, None
                    if is_open:
                        ip_has_open = True
                    if r:
                        ip_has_proxy = True
                        with found_lock:
                            existing.add('%s:%d' % (r[0], r[1]))
                            found_count[0] += 1
                            if note:
                                line_out = '%s:%d@%s@%s' % (r[0], r[1], r[2], note)
                            else:
                                line_out = '%s:%d@%s' % (r[0], r[1], r[2])
                            with open(OUTPUT_FILE, 'a', encoding='utf-8', newline='') as f:
                                f.write(line_out + CRLF)
                            log('[+] ' + line_out)
                    with found_lock:
                        port_tasks[0] += 1
                    # ★ 只有 common 阶段短路
                    if short_circuit and ip_has_open:
                        break

            if current_phase == 'common':
                if ip_has_open:
                    with open_ips_lock:
                        open_ips.add(ip)
            elif current_phase == 'proxy':
                with open_ips_lock:
                    if ip_has_proxy:
                        proxy_found_ips.add(ip)
                    else:
                        proxy_missing_ips.add(ip)

            with found_lock:
                processed_ips[0] += 1
                if processed_ips[0] % 200 == 0:
                    elapsed = time.time() - t0
                    speed = port_tasks[0] / elapsed if elapsed > 0 else 0
                    pct = processed_ips[0] * 100.0 / total_ips if total_ips else 0
                    with open_ips_lock:
                        open_count = len(open_ips)
                        pf_count = len(proxy_found_ips)
                        pm_count = len(proxy_missing_ips)
                    if current_phase == 'common':
                        extra = '存活 %d' % open_count
                    elif current_phase == 'proxy':
                        extra = '找到 %d | 待深扫 %d' % (pf_count, pm_count)
                    else:
                        extra = ''
                    log('[进度] 已处理 %d/%d IP | 全局 %.2f%% | %s | 代理 %d | %.1f task/s | %.0f s'
                        % (processed_ips[0], total_ips, pct, extra,
                           found_count[0], speed, elapsed))

            if IP_COOLDOWN > 0:
                time.sleep(IP_COOLDOWN)

    def watchdog():
        while not stop_flag[0]:
            if time.time() - t0 > MAX_RUNTIME_SEC:
                log('[!] 达到最大运行时长，优雅停止')
                stop_flag[0] = True
                return
            time.sleep(5)

    threading.Thread(target=watchdog, daemon=True).start()

    try:
        with ThreadPoolExecutor(max_workers=TCP_WORKERS) as ip_pool:
            futures = [ip_pool.submit(worker) for _ in range(TCP_WORKERS)]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as ex:
                    log('[!] worker 异常: %s' % ex)
    finally:
        stop_flag[0] = True
        port_pool.shutdown(wait=False)

    with pos_lock:
        state['position'] = current_pos[0]
    state['done'] = state.get('done', 0) + port_tasks[0]

    if state['position'] >= total_ips:
        state['completed'] = True
        state['completed_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
        log('=' * 60)
        log('[分片 %d/%d, 阶段 %s] 本阶段本片扫描完成！'
            % (SHARD_INDEX, SHARD_TOTAL, current_phase))
    else:
        log('=' * 60)
        log('[分片 %d/%d, 阶段 %s] 本次 session 结束，剩余 %d 个 IP'
            % (SHARD_INDEX, SHARD_TOTAL, current_phase,
               total_ips - state['position']))

    # 先写产出，再 save state
    if current_phase == 'common' and open_ips:
        try:
            existing_open = load_ip_set(OPEN_IPS_FILE)
            existing_open.update(open_ips)
            with open(OPEN_IPS_FILE, 'w', encoding='utf-8', newline='') as f:
                for ip in sorted(existing_open):
                    f.write(ip + CRLF)
            log('本 session 存活 IP: %d 个' % len(open_ips))
            log('存活 IP 列表已更新: %s (本 session %d, 累计 %d)'
                % (OPEN_IPS_FILE, len(open_ips), len(existing_open)))
        except Exception as e:
            log('[!] 写存活 IP 文件失败: %s' % e)

    elif current_phase == 'proxy' and proxy_missing_ips:
        try:
            existing_missing = load_ip_set(PROXY_MISSING_FILE)
            existing_missing.update(proxy_missing_ips)
            with open(PROXY_MISSING_FILE, 'w', encoding='utf-8', newline='') as f:
                for ip in sorted(existing_missing):
                    f.write(ip + CRLF)
            log('本 session 找到代理的 IP: %d 个' % len(proxy_found_ips))
            log('本 session 待深扫 IP: %d 个' % len(proxy_missing_ips))
            log('待深扫列表已更新: %s (本 session %d, 累计 %d)'
                % (PROXY_MISSING_FILE, len(proxy_missing_ips), len(existing_missing)))
        except Exception as e:
            log('[!] 写待深扫文件失败: %s' % e)

    save_json(STATE_FILE, state)

    dt = time.time() - t0
    log('-' * 60)
    log('本 session 耗时: %.1f 秒 (%.2f 小时)' % (dt, dt / 3600.0))
    log('累计找到代理: %d' % found_count[0])
    log('本片进度: %d/%d (%.1f%%)'
        % (state['position'], total_ips,
           state['position'] * 100.0 / total_ips if total_ips else 0))


if __name__ == '__main__':
    main()
