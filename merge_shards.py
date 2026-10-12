# -*- coding: utf-8 -*-
"""
合并 8 个分片结果，判断阶段推进 / 触发下一轮 / 清理
五阶段：verify_existing → common → revalidate → proxy → full

关键逻辑：
  - verify_existing：**替换** working_proxies.txt（只留仍有效的）
  - 其他阶段：**累积**（旧 + 新，去重）
  - proxy 找到 ≥1 个代理 → 跳过 full
  - 一轮完整结束 → phase.json 重置为 verify_existing（若 working_proxies.txt 非空）或 common
"""

import os
import sys
import json
import time
import glob

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


def read_file_lines(path):
    """从任意文件读非注释行"""
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


def proxy_key(line):
    """'ip:port@proto@note' → 'ip:port@proto'"""
    if '@' not in line:
        return line
    parts = line.split('@')
    if len(parts) >= 2:
        return '%s@%s' % (parts[0], parts[1])
    return line


def count_file_lines(path):
    return len(read_file_lines(path))


def cleanup_shard_files():
    patterns = [
        'progress_shard*.json',
        'open_ips_shard*.txt',
        'open_ips_revalidated_shard*.txt',
        'proxy_missing_shard*.txt',
        'working_proxies_shard*.txt',
    ]
    removed = 0
    for pat in patterns:
        for path in glob.glob(pat):
            try:
                os.remove(path)
                removed += 1
            except Exception as e:
                log('[!] 删除 %s 失败: %s' % (path, e))
    log('已清理 %d 个分片文件' % removed)


def write_output(lines):
    """写 working_proxies.txt"""
    with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='') as f:
        f.write('@ 代理扫描结果' + CRLF)
        f.write('@ 格式: ip:port@protocol@归属地' + CRLF)
        f.write('@ 生成时间: %s' % time.strftime('%Y-%m-%d %H:%M:%S') + CRLF)
        f.write('@ 总数: %d' % len(lines) + CRLF)
        f.write('@' + '-' * 58 + CRLF)
        for line in lines:
            f.write(line + CRLF)


def set_trigger(value):
    runner_temp = os.environ.get('RUNNER_TEMP', '/tmp')
    with open(os.path.join(runner_temp, 'trigger.flag'), 'w') as f:
        f.write(value)


def handle_verify_existing(phase_state):
    """verify_existing 阶段：分片 0 验证结果 → 替换 working_proxies.txt"""
    all_done = True
    missing_shards = []
    for i in range(SHARD_TOTAL):
        st = load_json('progress_shard%d.json' % i)
        if not st or not st.get('completed') or st.get('phase') != 'verify_existing':
            all_done = False
            missing_shards.append(i)

    log('阶段: verify_existing')
    log('全部分片完成: %s' % all_done)
    if not all_done:
        log('未完成分片: %s' % missing_shards)

    shard0_lines = read_shard_results(0)
    log('分片 0 验证结果: %d 个仍然有效' % len(shard0_lines))

    # ★ 替换 working_proxies.txt
    write_output(shard0_lines)
    log('已替换 working_proxies.txt: %d 条' % len(shard0_lines))

    if not all_done:
        log('有分片未完成（被截断），自动触发下一轮续跑')
        set_trigger('yes')
        return

    if len(shard0_lines) > 0:
        log('verify_existing 完成，%d 个代理仍有效 → 结束（保留列表，等手动触发）'
            % len(shard0_lines))
        # 清理 + 重置为 verify_existing（下次用户触发还是先验证）
        cleanup_shard_files()
        save_json(PHASE_FILE, {
            'current': 'verify_existing',
            'common_completed': False,
            'revalidate_completed': False,
            'proxy_completed': False,
            'full_completed': False,
        })
        log('phase.json 已重置为 verify_existing（下次触发仍先验证）')
        set_trigger('no')
    else:
        log('verify_existing 完成，0 个代理仍有效 → 清空并自动进 common')
        # working_proxies.txt 已经被 write_output([]) 清空
        cleanup_shard_files()
        save_json(PHASE_FILE, {
            'current': 'common',
            'common_completed': False,
            'revalidate_completed': False,
            'proxy_completed': False,
            'full_completed': False,
        })
        log('phase.json 已重置为 common（自动触发下一轮）')
        set_trigger('yes')


def main():
    phase_state = load_json(PHASE_FILE) or {
        'current': 'common',
        'common_completed': False,
        'revalidate_completed': False,
        'proxy_completed': False,
        'full_completed': False,
    }
    current_phase = phase_state.get('current', 'common')

    # ★ verify_existing 阶段特殊处理
    if current_phase == 'verify_existing':
        handle_verify_existing(phase_state)
        return

    # ============ 其他阶段的通用逻辑 ============
    all_done = True
    missing_shards = []
    for i in range(SHARD_TOTAL):
        st = load_json('progress_shard%d.json' % i)
        if not st or not st.get('completed') or st.get('phase') != current_phase:
            all_done = False
            missing_shards.append(i)

    log('阶段: %s' % current_phase)
    log('全部分片完成: %s' % all_done)
    if not all_done:
        log('未完成分片: %s' % missing_shards)

    total_open = sum(count_file_lines('open_ips_shard%d.txt' % i)
                     for i in range(SHARD_TOTAL))
    total_rev = sum(count_file_lines('open_ips_revalidated_shard%d.txt' % i)
                    for i in range(SHARD_TOTAL))
    total_missing = sum(count_file_lines('proxy_missing_shard%d.txt' % i)
                        for i in range(SHARD_TOTAL))
    log('存活 IP 总数: %d' % total_open)
    log('重验存活 IP 总数: %d' % total_rev)
    log('待深扫 IP 总数: %d' % total_missing)

    # 合并：读旧的 + 本轮新结果 → 去重
    old_lines = read_file_lines(OUTPUT_FILE)
    new_lines = []
    for i in range(SHARD_TOTAL):
        new_lines.extend(read_shard_results(i))

    # 优先保留新的
    seen = set()
    merged = []
    for line in new_lines:
        k = proxy_key(line)
        if k in seen:
            continue
        seen.add(k)
        merged.append(line)
    for line in old_lines:
        k = proxy_key(line)
        if k in seen:
            continue
        seen.add(k)
        merged.append(line)

    log('本轮分片结果: %d 条 | 旧文件: %d 条 | 合并去重后: %d 条'
        % (len(new_lines), len(old_lines), len(merged)))

    write_output(merged)

    trigger = 'no'
    should_cleanup = False

    if not all_done:
        log('有分片未完成（被截断），自动触发下一轮续跑')
        trigger = 'yes'
    else:
        if current_phase == 'common':
            if total_open == 0:
                log('common 完成，0 存活 IP → 结束（IP 全死）')
                phase_state['common_completed'] = True
                phase_state['revalidate_completed'] = True
                phase_state['proxy_completed'] = True
                phase_state['full_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'no'
                should_cleanup = True
            else:
                log('common 完成，%d 存活 IP → 切 revalidate' % total_open)
                phase_state['current'] = 'revalidate'
                phase_state['common_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'yes'

        elif current_phase == 'revalidate':
            if total_rev == 0:
                log('revalidate 完成，0 重验存活 IP → 结束')
                phase_state['revalidate_completed'] = True
                phase_state['proxy_completed'] = True
                phase_state['full_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'no'
                should_cleanup = True
            else:
                log('revalidate 完成，%d 个重验存活 IP → 切 proxy' % total_rev)
                phase_state['current'] = 'proxy'
                phase_state['revalidate_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'yes'

        elif current_phase == 'proxy':
            # ★ 节约原则：找到 ≥1 个代理就结束
            if len(new_lines) > 0:
                log('proxy 完成，本轮找到 %d 个代理 → 结束（节约原则，跳过 full）'
                    % len(new_lines))
                phase_state['proxy_completed'] = True
                phase_state['full_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'no'
                should_cleanup = True
            else:
                log('proxy 完成，0 代理 → 切 full（深扫剩余 %d 个 IP）'
                    % total_missing)
                phase_state['current'] = 'full'
                phase_state['proxy_completed'] = True
                save_json(PHASE_FILE, phase_state)
                trigger = 'yes'

        elif current_phase == 'full':
            log('full 全部完成 → 结束')
            phase_state['full_completed'] = True
            save_json(PHASE_FILE, phase_state)
            trigger = 'no'
            should_cleanup = True

    # 一轮完整结束 → 清理 + 重置
    if should_cleanup:
        log('=' * 60)
        log('一轮完整结束，清理分片文件...')
        cleanup_shard_files()

        # 根据 working_proxies.txt 是否有内容决定下一轮阶段
        current_count = count_file_lines(OUTPUT_FILE)
        if current_count > 0:
            next_phase = 'verify_existing'
            log('working_proxies.txt 有 %d 个代理，下一轮先做 verify_existing' % current_count)
        else:
            next_phase = 'common'
            log('working_proxies.txt 为空，下一轮从头开始')

        save_json(PHASE_FILE, {
            'current': next_phase,
            'common_completed': False,
            'revalidate_completed': False,
            'proxy_completed': False,
            'full_completed': False,
        })
        log('phase.json 已重置为 %s' % next_phase)

    set_trigger(trigger)
    log('trigger = %s' % trigger)


if __name__ == '__main__':
    main()
