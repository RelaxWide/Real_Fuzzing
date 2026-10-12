"""v11.2.1 — PM 슬롯을 '실행 수가 정확히 배수'가 아니라 '예정 실행 수 이상'에서 돌린다.

예전 조건(executions % PM_ROTATE_INTERVAL == 0)은 한 반복에 여러 명령을 실행하는 시퀀스·det 묶음, 워크로드로
빠지는 반복이 배수를 건너뛰면 그 주기 PM 을 통째로 잃었다. 반대로 가드 차단처럼 실행 수가 안 느는 반복이
배수에서 거듭되면 PM 이 연달아 돌았다.
"""
import unittest

from fuzzer_target import FUZZER_FILE, fuzzer as v

N = v.PM_ROTATE_INTERVAL


def run(execs):
    """반복마다의 executions 값 → PM 이 돈 반복의 executions 목록."""
    f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
    f._pm_next_at = 0
    fired = []
    for e in execs:
        f.executions = e
        if f._pm_take_slot():
            fired.append(e)
    return fired


class Schedule(unittest.TestCase):
    def test_first_iteration_and_every_interval(self):
        self.assertEqual(run(range(0, 3 * N + 1)), [0, N, 2 * N, 3 * N])

    def test_skipped_multiple_still_fires_next_iteration(self):
        # 시퀀스로 98 → 103 처럼 배수를 건너뛰어도 그 다음 반복에서 돈다
        execs = list(range(0, N - 1)) + [N + 3, N + 4] + list(range(N + 5, 2 * N + 10))
        fired = run(execs)
        self.assertEqual(fired[:2], [0, N + 3])
        self.assertEqual(fired[2], 2 * N + 3)                 # 예정은 실제로 돈 시점부터 INTERVAL 뒤

    def test_large_jumps_never_starve(self):
        # 반복마다 7개씩 실행해도(배수를 거의 못 밟음) 주기마다 돈다
        execs = list(range(0, 20 * N, 7))
        fired = run(execs)
        self.assertGreaterEqual(len(fired), 19)
        gaps = [b - a for a, b in zip(fired, fired[1:])]
        self.assertTrue(all(N <= g < N + 7 for g in gaps), gaps)

    def test_no_burst_catch_up_and_no_repeat_on_same_count(self):
        self.assertEqual(run([0, 5 * N, 5 * N + 1, 5 * N + 2]), [0, 5 * N])   # 밀린 만큼 연달아 X
        self.assertEqual(run([0, N, N, N, N + 1]), [0, N])                    # 같은 실행 수 반복 X

    def test_main_loop_uses_it(self):
        src = FUZZER_FILE.read_text(encoding='utf-8')
        self.assertIn("and self._pm_take_slot()):", src)
        self.assertNotIn("self.executions % PM_ROTATE_INTERVAL == 0", src)
        self.assertIn("self._pm_next_at = 0", src)


if __name__ == '__main__':
    unittest.main()
