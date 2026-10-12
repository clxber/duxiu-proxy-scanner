# -*- coding: utf-8 -*-
"""
合并 8 个分片结果，判断是否要切 phase / 触发下一轮

判断逻辑：
  common 阶段全部完成：
    ├─ 有结果 → 结束
    ├─ 0 结果 + open_ips 全空 → 结束（无存活 IP，full 无意义）
    └─ 0 结果 + open_ips 有存活 → 切 full
  full 阶段全部完成 → 结束
"""

import os
import sys
import json
import time

SHARD_TOTAL = 8
PHASE_FILE = 'phase.json'
OUTPUT_FILE = 'working_proxies.txt'
CRLF = '\r\n'


def log(msg):
    print(msg, flush=True)


def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def save_json(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def read_shard_results(idx):
    path = 'working_proxies_shard%d.txt' % idx
    if not os.path.exists(path):
        return []
    lines = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.rstrip('\r\n')
            if not line or line.startswith('@') or line.startswith('#'):
                continue
            lines.append(line)
    return lines


def count_open_ips(idx):
    """统计某个分片的存活 IP 数"""
    path = 'open_ips_shard%d.txt' % idx
    if not os.path.exists(path):
        return 0
    n = 0
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def main():
    phase_state = load_json(PHASE_FILE) or {
        'current': 'common',
        'common_completed': False,
        'full_completed': False,
    }
    current_phase = phase_state.get('current', 'common')

    # 检查所有分片是否都完成
    all_done = True
    for i in range(SHARD_TOTAL):
        st = load_json('progress_shard%d.json' % i)
        if not st or not st.get('completed') or st.get('phase') != current_phase:
            all_done = False
            break

    log('阶段: %s' % current_phase)
    log('全部分片完成: %s' % all_done)

    # 统计存活 IP 数
    total_open = 0
    open_per_shard = []
    for i in range(SHARD_TOTAL):
        n = count_open_ips(i)
        open_per_shard.append(n)
        total_open += n
    log('各分片存活 IP: %s' % open_per_shard)
    log('存活 IP 总数: %d' % total_open)

    # 合并所有分片结果到 working_proxies.txt（重建）
    all_lines = []
    seen = set()
    for i in range(SHARD_TOTAL):
        for line in read_shard_results(i):
            if line in seen:
                continue
            seen.add(line)
            all_lines.append(line)

    with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as f:
        f.write('@ 读秀代理扫描结果' + CRLF)
        f.write('@ 格式: ip:port@protocol@归属地' + CRLF)
        f.write('@ 阶段: %s' % current_phase + CRLF)
        f.write('@ 生成时间: %s' % time.strftime('%Y-%m-%d %H:%M:%S') + CRLF)
        f.write('@ 总数: %d' % len(all_lines) + CRLF)
        f.write('@' + '-' * 58 + CRLF)
        for line in all_lines:
            f.write(line + CRLF)

    log('合并结果: %d 条' % len(all_lines))

    # 写 flag 供 workflow 判断
    trigger = 'no'
    if all_done:
        if current_phase == 'common':
            if len(all_lines) > 0:
                log('phase common 完成，有 %d 条结果 → 结束' % len(all_lines))
                phase_state['common_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'no'
            elif total_open == 0:
                log('phase common 完成，0 结果且 0 存活 IP → 结束（IP 全死，full 无意义）')
                phase_state['common_completed'] = True
                phase_state['full_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'no'
            else:
                log('phase common 完成，0 结果但有 %d 个存活 IP → 切换 full'
                    % total_open)
                phase_state['current'] = 'full'
                phase_state['common_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'yes'
        elif current_phase == 'full':
            log('phase full 全部完成 → 结束')
            phase_state['full_completed'] = True
            save_json(PHASE_FILE, phase_state)
            trigger = 'no'

    runner_temp = os.environ.get('RUNNER_TEMP', '/tmp')
    with open(os.path.join(runner_temp, 'trigger.flag'), 'w') as f:
        f.write(trigger)
    log('trigger = %s' % trigger)


if __name__ == '__main__':
    main()
