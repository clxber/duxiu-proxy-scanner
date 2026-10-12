# -*- coding: utf-8 -*-
"""
高校代理扫描器 —— 分片 + 两阶段 + 断点续跑
分片：按 IP 切分，每片独立，同一 IP 不被两片同时扫
阶段：common（171 端口） → full（65535 端口）
"""

import os
import re
import sys
import json
import time
import socket
import bisect
import argparse
import ipaddress
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============ 配置 ============
DUXIU_URL = 'http://www.duxiu.com/'
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
DUXIU_KEYWORDS = ['读秀学术搜索', '超星', '读秀知识库']

MAX_RUNTIME_SEC = int(os.environ.get('MAX_RUNTIME_SEC', 20880))


def _build_common_ports():
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
FULL_PORTS = list(range(1, 65536))

# ============ 命令行参数 ============
parser = argparse.ArgumentParser()
parser.add_argument('--shard', type=int, default=0)
parser.add_argument('--shard-total', type=int, default=1)
args, _ = parser.parse_known_args()

SHARD_INDEX = args.shard
SHARD_TOTAL = args.shard_total

# ============ 参数 ============
TCP_TIMEOUT = 3
VERIFY_TIMEOUT = 20
VERIFY_RETRY = 0
VERIFY_DELAY = 1.0
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
else:
    STATE_FILE = 'progress.json'
    OUTPUT_FILE = 'working_proxies.txt'

CRLF = '\r\n'


def log(msg):
    print(msg, flush=True)


# ============ 文本清理 ============
_WS_RE = re.compile(r'\s+')


def _clean_note(s):
    if not s:
        return ''
    s = s.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')
    s = s.replace('@', ' ')
    return _WS_RE.sub(' ', s).strip()


# ============ IP 解析 ============
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


# ============ JSON ============
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


# ============ 全局读秀请求限速 ============
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


# ============ 扫描 ============
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


def verify_duxiu(ip, port, protocol):
    proxy_url = '%s://%s:%d' % (protocol, ip, port)
    proxies = {'http': proxy_url, 'https': proxy_url}
    if VERIFY_DELAY > 0:
        time.sleep(VERIFY_DELAY)
    verify_rate_wait()
    try:
        r = requests.get(DUXIU_URL, proxies=proxies, timeout=VERIFY_TIMEOUT,
                         headers={'User-Agent': UA}, allow_redirects=True)
        if r.status_code != 200:
            return False
        try:
            text = r.content.decode('gbk', errors='ignore')
        except Exception:
            text = r.text
        if 'duxiu.com' not in r.url and 'duxiu.com' not in text:
            return False
        if not any(kw in text for kw in DUXIU_KEYWORDS):
            return False
        return True
    except Exception:
        return False


def scan_ip_port(ip, port):
    if not tcp_check(ip, port):
        return None
    for proto in ('http', 'socks5', 'socks4'):
        if verify_duxiu(ip, port, proto):
            return (ip, port, proto)
    return None


# ============ 分片 IP 分配 ============
def slice_ranges(ranges, shard_index, shard_total):
    """把 IP 范围按顺序切分，返回第 shard_index 片的 [(s, e, note), ...]"""
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


def main():
    if not os.path.exists(INPUT_FILE):
        log('未找到 %s' % INPUT_FILE)
        sys.exit(1)

    all_ranges = load_ip_ranges(INPUT_FILE)
    if not all_ranges:
        log('未读取到有效 IP 范围')
        sys.exit(1)

    # 读 phase
    phase_state = load_json(PHASE_FILE) or {
        'current': 'common',
        'common_completed': False,
        'full_completed': False,
    }
    current_phase = phase_state.get('current', 'common')
    PORTS = COMMON_PORTS if current_phase == 'common' else FULL_PORTS

    # 分片
    ranges = slice_ranges(all_ranges, SHARD_INDEX, SHARD_TOTAL)
    total_ips = sum(e - s + 1 for s, e, _ in ranges)
    total_tasks = total_ips * len(PORTS)

    range_cum = []
    acc = 0
    for s, e, _ in ranges:
        range_cum.append(acc)
        acc += e - s + 1

    def ip_at_position(pos):
        idx = bisect.bisect_right(range_cum, pos) - 1
        s, e, note = ranges[idx]
        return s + (pos - range_cum[idx]), note

    # 恢复 / 重置
    state = load_json(STATE_FILE)
    new_round = True
    if (state and not state.get('completed')
            and state.get('total_ips') == total_ips
            and state.get('phase') == current_phase):
        new_round = False

    if new_round:
        state = {
            'position': 0,
            'done': 0,
            'total_ips': total_ips,
            'total_tasks': total_tasks,
            'ports_count': len(PORTS),
            'phase': current_phase,
            'shard_index': SHARD_INDEX,
            'shard_total': SHARD_TOTAL,
            'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'completed': False,
            'session': 1,
        }
        with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as f:
            f.write('@ 读秀代理扫描结果 [分片 %d/%d]' % (SHARD_INDEX, SHARD_TOTAL) + CRLF)
            f.write('@ 阶段: %s' % current_phase + CRLF)
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
    log('任务总量: %d' % total_tasks)
    log('本次起点: IP #%d' % state['position'])
    log('已找到代理: %d' % len(existing))
    log('IP 并发: %d  ×  端口并发: %d' % (TCP_WORKERS, PORT_WORKERS))
    log('TCP 超时: %d s | 验证超时: %d s' % (TCP_TIMEOUT, VERIFY_TIMEOUT))
    log('最大运行时长: %d 秒 (%.2f 小时)'
        % (MAX_RUNTIME_SEC, MAX_RUNTIME_SEC / 3600.0))
    log('-' * 60)

    pos_lock = threading.Lock()
    current_pos = [state['position']]
    found_lock = threading.Lock()
    found_count = [len(existing)]
    scanned = [0]
    stop_flag = [False]
    t0 = time.time()

    def next_position():
        with pos_lock:
            if current_pos[0] >= total_ips:
                return None
            p = current_pos[0]
            current_pos[0] += 1
            return p

    port_pool = ThreadPoolExecutor(max_workers=TCP_WORKERS * PORT_WORKERS)

    def worker():
        while not stop_flag[0]:
            p = next_position()
            if p is None:
                return
            ip_int, note = ip_at_position(p)
            ip = ip_int_to_str(ip_int)
            pending = []
            for port in PORTS:
                key = '%s:%d' % (ip, port)
                if key in existing:
                    continue
                pending.append((port, port_pool.submit(scan_ip_port, ip, port)))
            for port, fut in pending:
                if stop_flag[0]:
                    return
                try:
                    r = fut.result()
                except Exception:
                    r = None
                if r:
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
                    scanned[0] += 1
                    if scanned[0] % 2000 == 0:
                        elapsed = time.time() - t0
                        speed = scanned[0] / elapsed if elapsed > 0 else 0
                        done_now = state['position'] + scanned[0] / len(PORTS)
                        pct = done_now * 100.0 / total_ips if total_ips else 0
                        log('[进度] 本 session %d 任务 | 全局 %.2f%% | '
                            '找到 %d | %.2f task/s | %.0f s'
                            % (scanned[0], pct, found_count[0], speed, elapsed))
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
    state['done'] = state.get('done', 0) + scanned[0]

    if state['position'] >= total_ips:
        state['completed'] = True
        state['completed_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
        log('=' * 60)
        log('[分片 %d/%d] 本阶段本片扫描完成！' % (SHARD_INDEX, SHARD_TOTAL))
    else:
        log('=' * 60)
        log('[分片 %d/%d] 本次 session 结束，剩余 %d 个 IP'
            % (SHARD_INDEX, SHARD_TOTAL, total_ips - state['position']))

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
