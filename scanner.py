# -*- coding: utf-8 -*-
"""
高校代理扫描器 —— 五阶段 + 分片 + 断点续跑
阶段 1 verify_existing：验证已有代理（只有分片 0 干活）
阶段 2 common         ：12 探针 + 171 代理（TCP 探活，短路）
阶段 3 revalidate     ：12 探针 + 171 代理（重新探活，短路）
阶段 4 proxy          ：171 代理端口（完整扫描 + 双验证）
阶段 5 full           ：65535 全端口（只扫 proxy 未找到代理的 IP）
双验证：curl 通过代理访问 百度 + 读秀，两个都通过才算有效代理
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

# ★ 双验证目标：全部通过才算有效代理
VERIFY_TARGETS = [
    {
        'name': 'baidu',
        'url': 'http://www.baidu.com/',
        'keywords': ['baidu.com', '百度'],
        'encoding': 'utf-8',
    },
    {
        'name': 'duxiu',
        'url': 'http://www.duxiu.com/',
        'keywords': ['读秀学术搜索'],
        'encoding': 'gbk',
    },
]

MAX_RUNTIME_SEC = int(os.environ.get('MAX_RUNTIME_SEC', 20880))


def _build_probe_ports_12():
    return [22, 80, 443, 3389, 1080, 1081, 8080, 8081, 7890, 3128, 8000, 8443]


def _build_proxy_ports():
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


def _build_common_ports():
    probe12 = _build_probe_ports_12()
    proxy = _build_proxy_ports()
    seen = set()
    result = []
    for p in probe12:
        if p not in seen:
            seen.add(p)
            result.append(p)
    for p in proxy:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result


PROBE_PORTS_12 = _build_probe_ports_12()
PROXY_PORTS = _build_proxy_ports()
COMMON_PORTS = _build_common_ports()
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
    OPEN_IPS_REVALIDATED_FILE = 'open_ips_revalidated_shard%d.txt' % SHARD_INDEX
    PROXY_MISSING_FILE = 'proxy_missing_shard%d.txt' % SHARD_INDEX
else:
    STATE_FILE = 'progress.json'
    OUTPUT_FILE = 'working_proxies.txt'
    OPEN_IPS_FILE = 'open_ips.txt'
    OPEN_IPS_REVALIDATED_FILE = 'open_ips_revalidated.txt'
    PROXY_MISSING_FILE = 'proxy_missing.txt'

CRLF = '\r\n'
EXISTING_PROXIES_FILE = 'working_proxies.txt'

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


def load_proxy_list(path):
    result = []
    if not os.path.exists(path):
        return result
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('@') or line.startswith('#'):
                continue
            parts = line.split('@')
            if len(parts) < 2:
                continue
            addr = parts[0].strip()
            proto = parts[1].strip().lower()
            note = '@'.join(parts[2:]).strip() if len(parts) > 2 else ''
            if ':' not in addr:
                continue
            ip, port_str = addr.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                continue
            if proto not in PROTOCOLS:
                continue
            result.append((ip, port, proto, note))
    return result


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


def _build_curl_args(ip, port, protocol, url):
    address = '%s:%d' % (ip, port)
    if protocol == 'http':
        return ['-x', address, url]
    if protocol == 'socks5':
        return ['--socks5-hostname', address, url]
    if protocol == 'socks4':
        return ['--socks4a', address, url]
    return None


def _verify_one_target(ip, port, protocol, target):
    """通过代理访问单个目标，返回 True 表示命中"""
    args = _build_curl_args(ip, port, protocol, target['url'])
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
        raw = proc.stdout
        try:
            text = raw.decode(target['encoding'], errors='ignore')
        except Exception:
            text = raw.decode('utf-8', errors='ignore')
        return any(kw in text for kw in target['keywords'])
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def verify_proxy(ip, port, protocol):
    """
    双验证：百度 + 读秀，全部通过才算有效代理。
    任一失败立即返回 False。
    """
    for target in VERIFY_TARGETS:
        if not _verify_one_target(ip, port, protocol, target):
            return False
    return True


def scan_port_common(ip, port):
    return tcp_check(ip, port), None


def scan_port_full(ip, port):
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
        return COMMON_PORTS, None, OPEN_IPS_FILE
    elif phase == 'revalidate':
        return COMMON_PORTS, OPEN_IPS_FILE, OPEN_IPS_REVALIDATED_FILE
    elif phase == 'proxy':
        return PROXY_PORTS, OPEN_IPS_REVALIDATED_FILE, PROXY_MISSING_FILE
    elif phase == 'full':
        return FULL_PORTS, PROXY_MISSING_FILE, None
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


# ============ verify_existing 阶段 ============

def run_verify_existing_phase():
    if SHARD_INDEX != 0:
        log('[verify_existing] 分片 %d 跳过（只有分片 0 做验证）' % SHARD_INDEX)
        _skip_this_shard(STATE_FILE, None, 'verify_existing', 0)
        return

    proxy_list = load_proxy_list(EXISTING_PROXIES_FILE)
    log('[verify_existing] 从 %s 读到 %d 个历史代理'
        % (EXISTING_PROXIES_FILE, len(proxy_list)))

    with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as f:
        f.write('@ 代理扫描结果 [verify_existing]' + CRLF)
        f.write('@ 开始时间: %s' % time.strftime('%Y-%m-%d %H:%M:%S') + CRLF)
        f.write('@ 验证: 百度 + 读秀（双验证）' + CRLF)
        f.write('@' + '-' * 58 + CRLF)

    if not proxy_list:
        log('[verify_existing] 无历史代理可验证，跳过')
        state = {
            'position': 0, 'done': 0, 'total_ips': 0, 'total_tasks': 0,
            'ports_count': 0, 'phase': 'verify_existing',
            'shard_index': 0, 'shard_total': SHARD_TOTAL,
            'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'completed': True,
            'completed_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'session': 1,
        }
        save_json(STATE_FILE, state)
        return

    valid_count = [0]
    checked_count = [0]
    found_lock = threading.Lock()
    t0 = time.time()

    def verify_one(item):
        ip, port, proto, note = item
        ok = verify_proxy(ip, port, proto)
        with found_lock:
            checked_count[0] += 1
            n = checked_count[0]
            if ok:
                valid_count[0] += 1
                if note:
                    line_out = '%s:%d@%s@%s' % (ip, port, proto, note)
                else:
                    line_out = '%s:%d@%s' % (ip, port, proto)
                with open(OUTPUT_FILE, 'a', encoding='utf-8', newline='') as f:
                    f.write(line_out + CRLF)
                log('[+] 仍然有效: %s' % line_out)
            if n % 20 == 0:
                elapsed = time.time() - t0
                log('[verify_existing] 已检查 %d/%d | 有效 %d | %.1f s'
                    % (n, len(proxy_list), valid_count[0], elapsed))

    port_pool = ThreadPoolExecutor(max_workers=TCP_WORKERS * PORT_WORKERS)
    try:
        futures = [port_pool.submit(verify_one, item) for item in proxy_list]
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as ex:
                log('[!] verify_one 异常: %s' % ex)
    finally:
        port_pool.shutdown(wait=False)

    dt = time.time() - t0
    log('=' * 60)
    log('[verify_existing] 验证完成: %d/%d 仍然有效，耗时 %.1f 秒'
        % (valid_count[0], len(proxy_list), dt))

    state = {
        'position': len(proxy_list),
        'done': len(proxy_list),
        'total_ips': len(proxy_list),
        'phase': 'verify_existing',
        'shard_index': 0, 'shard_total': SHARD_TOTAL,
        'started_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'completed': True,
        'completed_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'session': 1,
    }
    save_json(STATE_FILE, state)


# ============ main ============

def main():
    if not os.path.exists(INPUT_FILE):
        log('未找到 %s' % INPUT_FILE)
        sys.exit(1)

    phase_state = load_json(PHASE_FILE) or {
        'current': 'common',
        'common_completed': False,
        'revalidate_completed': False,
        'proxy_completed': False,
        'full_completed': False,
    }
    current_phase = phase_state.get('current', 'common')

    if current_phase == 'verify_existing':
        run_verify_existing_phase()
        return

    all_ranges = load_ip_ranges(INPUT_FILE)
    if not all_ranges:
        log('未读取到有效 IP 范围')
        sys.exit(1)

    PORTS, upstream_file, output_filter_file = get_phase_config(current_phase)

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
                if current_phase == 'revalidate':
                    ip_note_map = {}
                    for s, e, note in all_ranges:
                        if not note:
                            continue
                        for ip_int, _ in ip_list:
                            if s <= ip_int <= e:
                                ip_note_map[ip_int] = note
                    ip_list = [(ip_int, ip_note_map.get(ip_int, ''))
                               for ip_int, _ in ip_list]
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
            f.write('@ 验证: 百度 + 读秀（双验证）' + CRLF)
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
    if current_phase in ('common', 'revalidate'):
        log('  前 12 探针: %s' % PROBE_PORTS_12)
    log('本次起点: IP #%d' % state['position'])
    log('已找到代理: %d' % len(existing))
    log('搜索连接超时: %d s | 验证超时: %d s' % (TCP_TIMEOUT, VERIFY_TIMEOUT))
    log('IP 并发: %d  ×  端口并发: %d  =  全局最大 %d 条连接'
        % (TCP_WORKERS, PORT_WORKERS, TCP_WORKERS * PORT_WORKERS))
    log('验证方式: curl (%s)' % CURL)
    for t in VERIFY_TARGETS:
        log('  验证目标 [%s]: %s | 关键词: %s | 编码: %s'
            % (t['name'], t['url'], t['keywords'], t['encoding']))
    log('成功判定: 全部验证目标通过')
    log('验证协议: %s' % (', '.join(PROTOCOLS)))
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
    revalidated_ips = set()
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
    if current_phase in ('common', 'revalidate'):
        scan_fn = scan_port_common
        short_circuit = True
    else:
        scan_fn = scan_port_full
        short_circuit = False

    def worker():
        while not stop_flag[0]:
            p = next_position()
            if p is None:
                return
            ip_int, note = ip_at_position(p)
            ip = ip_int_to_str(ip_int)

            ip_has_open = False
            ip_has_proxy = False

            futures = []
            for port in PORTS:
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
                if short_circuit and ip_has_open:
                    break

            if current_phase == 'common':
                if ip_has_open:
                    with open_ips_lock:
                        open_ips.add(ip)
            elif current_phase == 'revalidate':
                if ip_has_open:
                    with open_ips_lock:
                        revalidated_ips.add(ip)
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
                        oc = len(open_ips)
                        rc = len(revalidated_ips)
                        pf = len(proxy_found_ips)
                        pm = len(proxy_missing_ips)
                    if current_phase == 'common':
                        extra = '存活 %d' % oc
                    elif current_phase == 'revalidate':
                        extra = '重验存活 %d' % rc
                    elif current_phase == 'proxy':
                        extra = '找到 %d | 待深扫 %d' % (pf, pm)
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

    elif current_phase == 'revalidate' and revalidated_ips:
        try:
            existing_rev = load_ip_set(OPEN_IPS_REVALIDATED_FILE)
            existing_rev.update(revalidated_ips)
            with open(OPEN_IPS_REVALIDATED_FILE, 'w', encoding='utf-8', newline='') as f:
                for ip in sorted(existing_rev):
                    f.write(ip + CRLF)
            log('本 session 重验存活 IP: %d 个' % len(revalidated_ips))
            log('重验存活列表已更新: %s (本 session %d, 累计 %d)'
                % (OPEN_IPS_REVALIDATED_FILE, len(revalidated_ips), len(existing_rev)))
        except Exception as e:
            log('[!] 写重验存活文件失败: %s' % e)

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
