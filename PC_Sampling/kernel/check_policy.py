#!/usr/bin/env python3
"""Apply the test policy in a temporary tree and exercise its actual C branches.

Usage: python3 check_policy.py v6.8 /path/to/linux-source
Does not modify the source tree, build a kernel, or access hardware.
"""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


def function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef uint32_t u32;
typedef uint16_t __le16;
union nvme_result { u32 u32; };
struct device { const char *name; };
struct ops { const char *name; };
struct nvme_ctrl {
    struct device *dev, *device;
    struct ops *ops;
    u32 aen_result;
    int async_event_work;
};
static char *test_no_persistent_error_reset_bdf;
static int resets, queued, traces, warnings;
static void *nvme_wq;
#define le32_to_cpu(x) (x)
#define le16_to_cpu(x) (x)
#define dev_name(d) ((d)->name)
#define dev_warn_ratelimited(...) (++warnings)
#define dev_warn(...) (++warnings)
#define trace_nvme_async_event(...) (++traces)
#define queue_work(...) (++queued)
#define nvme_reset_ctrl(...) (++resets)
#define fallthrough __attribute__((fallthrough))
#define NVME_SC_SUCCESS 0
#define NVME_AER_ERROR 0
#define NVME_AER_SMART 1
#define NVME_AER_NOTICE 2
#define NVME_AER_CSS 6
#define NVME_AER_VS 7
#define NVME_AER_ERROR_PERSIST_INT_ERR 3
static u32 nvme_aer_type(u32 r) { return r & 7; }
static u32 nvme_aer_subtype(u32 r) { return (r >> 8) & 255; }
static bool nvme_handle_aen_notice(struct nvme_ctrl *c, u32 r)
{ (void)c; (void)r; return true; }
'''

TEST = r'''
static void check(char *target, const char *transport, const char *address,
                  u32 event, __le16 status, int want_reset, int want_queue)
{
    struct device d = {address};
    struct ops ops = {transport};
    struct nvme_ctrl c = {.dev=&d, .device=&d, .ops=&ops};
    union nvme_result r = {.u32=event};
    test_no_persistent_error_reset_bdf = target;
    resets = queued = traces = warnings = 0;
    nvme_complete_async_event(&c, status, &r);
    assert(resets == want_reset);
    assert(queued == want_queue);
    assert(traces == (status == 0));
    if (want_queue)
        assert(c.aen_result == event);
    if (!status && !want_reset && event == 0x300)
        assert(warnings == 1);
}
int main(void)
{
    /* Default and other devices retain the upstream reset policy. */
    check(NULL, "pcie", "0000:02:00.0", 0x300, 0, 1, 0);
    check("", "pcie", "0000:02:00.0", 0x300, 0, 1, 0);
    check("0000:02:00.0", "pcie", "0000:03:00.0", 0x300, 0, 1, 0);
    check("0000:02:00.0", "tcp", "0000:02:00.0", 0x300, 0, 1, 0);
    /* Selected device keeps recording the event and rearms AER. */
    check("0000:02:00.0", "pcie", "0000:02:00.0", 0x300, 0, 0, 1);
    /* Other event types and failed completions are unaffected. */
    check("0000:02:00.0", "pcie", "0000:02:00.0", 0x200, 0, 0, 1);
    check("0000:02:00.0", "pcie", "0000:02:00.0", 1, 0, 0, 1);
    check("0000:02:00.0", "pcie", "0000:02:00.0", 0x300, 2, 0, 0);
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version', choices=['v6.8', 'v7.0'])
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    patch = Path(__file__).resolve().parent / (
        f'nvme-persistent-error-test-policy-{args.version}.patch')
    with tempfile.TemporaryDirectory(prefix='nvme-policy-check-') as tmp:
        root = Path(tmp)
        core = root / 'drivers/nvme/host/core.c'
        core.parent.mkdir(parents=True)
        shutil.copyfile(args.source / 'drivers/nvme/host/core.c', core)
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                       cwd=root, check=True)
        source = core.read_text()
        signatures = [
            'static bool nvme_test_keep_running_on_persistent_error(',
            'static void nvme_handle_aer_persistent_error(',
            'void nvme_complete_async_event(',
        ]
        harness = root / 'check.c'
        harness.write_text(PRELUDE + '\n'.join(function(source, s)
                                              for s in signatures) + TEST)
        binary = root / 'check'
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Werror',
                        '-Wno-unused-variable', str(harness), '-o', str(binary)],
                       check=True)
        subprocess.run([str(binary)], check=True)
    print(f'{args.version}: patch applied; 8 policy cases passed (mocked kernel APIs)')


if __name__ == '__main__':
    main()
