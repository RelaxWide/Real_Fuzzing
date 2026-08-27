#!/usr/bin/env python3
"""sjtag_unlock.py 의 순수 함수·상태머신 단위 테스트 (하드웨어 불필요).

실기 접근이 없는 계층만 검증한다: 서명 도구 출력 파서, 워드 순서, DM AP 매핑,
쓰기 전 검증 게이트, 그리고 mock DAP 로 돌린 인증 상태머신.

    python3 -m unittest -v test_sjtag_unlock.py
"""

import sys
import unittest

import sjtag_unlock as sj
from sjtag_unlock import (SecureJtagError, _parse_words, order_words,
                          read_dmstatus, validate_target, unlock, classify_verdict,
                          valid_timeout, valid_base, EXIT_CONFIG,
                          EXIT_OK, EXIT_VERIFY_WEAK, EXIT_CAUSE_UNPROVEN,
                          ST_ALREADY, ST_OPEN_NO_SOFT_LOCK, ST_AUTHENTICATED,
                          OFF_STATE, OFF_HW_VERSION, OFF_DBG_CONTROL,
                          OFF_REQUEST, OFF_RESPONSE, OFF_CHALLENGE,
                          OFF_CHIP_ID0, OFF_CHIP_ID1, OFF_IDR,
                          AUTH_PASS, SOFT_LOCK, REQUEST_READY, RESPONSE_READY,
                          INVALID_PUBKEY, APBAP3_BASE, APBAP3_IDR_EXPECT,
                          PUBKEY_WORDS, SIG_WORDS, NONCE_WORDS)


class ParseWords(unittest.TestCase):
    def test_plain(self):
        text = "\n".join(f"{i:08X}" for i in range(3))
        self.assertEqual(_parse_words(text, 3), [0, 1, 2])

    def test_0x_prefix_and_blank_lines(self):
        text = "0x00000001\n\n0x000000FF\r\n0x00000010\n"
        self.assertEqual(_parse_words(text, 3), [1, 0xFF, 0x10])

    def test_uppercase_0X_prefix(self):
        self.assertEqual(_parse_words("0XDEADBEEF\n", 1), [0xDEADBEEF])

    def test_label_line_rejected(self):
        # "word 0: 0x12345678" 에서 인덱스 0 을 값으로 잡던 버그를 거부해야 한다
        with self.assertRaises(SecureJtagError):
            _parse_words("word 0: 0x12345678\n", 1)

    def test_wrong_count(self):
        with self.assertRaises(SecureJtagError):
            _parse_words("00000001\n00000002\n", 3)

    def test_nine_digit_rejected(self):
        with self.assertRaises(SecureJtagError):
            _parse_words("0x123456789\n", 1)

    def test_seven_digit_rejected(self):
        with self.assertRaises(SecureJtagError):
            _parse_words("1234567\n", 1)

    def test_secret_not_in_message(self):
        try:
            _parse_words("deadbeefcafebabe extra\n", 1)
        except SecureJtagError as e:
            self.assertNotIn("deadbeef", str(e))


class OrderWords(unittest.TestCase):
    def test_t32_negative_reverses(self):
        w = list(range(34))
        self.assertEqual(order_words(w, "t32-negative"), list(reversed(range(34))))

    def test_stdout_keeps(self):
        w = list(range(34))
        self.assertEqual(order_words(w, "stdout"), w)

    def test_unknown_raises(self):
        with self.assertRaises(ValueError):
            order_words([1], "bogus")


# ── mock DAP: APBAP3 뒤 SJTAG 레지스터 블록을 흉내낸다 ────────────────
class MockDap:
    """mem_read32/mem_write32/ap_read 를 딕셔너리 메모리로 구현.

    on_write(off, val) 훅으로 하드웨어 상태 전이를 흉내낸다(폴링 비트 세우기 등).
    APBAP1/2 의 dmstatus 도 별도 셀로 둔다."""

    def __init__(self, base, idr=APBAP3_IDR_EXPECT, dm_cells=None):
        self.base = base
        self.mem = {}
        self.idr = idr
        self.dm_cells = dm_cells or {}     # (ap_base, addr) -> value
        self.on_write = None
        self.last = {}
        self.writes = []
        self.target_reads = 0              # ap_read + mem_read32 호출 횟수

    def ap_read(self, ap_base, off):
        self.target_reads += 1
        if off == OFF_IDR:
            return self.idr
        return 0x23000002                  # csw_usable 한 임의값

    def mem_read32(self, ap_base, addr):
        self.target_reads += 1
        if ap_base != APBAP3_BASE:
            return self.dm_cells.get((ap_base, addr))
        return self.mem.get(addr)

    def mem_write32(self, ap_base, addr, val):
        self.writes.append((addr, val))
        # STATE 는 command 레지스터다: 쓴 값이 곧 readback 이 아니라, 하드웨어가
        # status 를 돌려준다. 그 전이는 on_write 훅이 정한다(실기 모사).
        if addr != self.base + OFF_STATE:
            self.mem[addr] = val
        if self.on_write:
            self.on_write(addr - self.base, val)
        return True


BASE = 0x40000000


def seed_valid_block(dap):
    dap.mem[BASE + OFF_HW_VERSION] = 0x00010203
    dap.mem[BASE + OFF_STATE] = 0x0


class Validate(unittest.TestCase):
    def test_pass(self):
        d = MockDap(BASE)
        seed_valid_block(d)
        ok, problems, info = validate_target(d, BASE)
        self.assertTrue(ok, problems)

    def test_misaligned_base(self):
        d = MockDap(BASE)
        seed_valid_block(d)
        ok, problems, _ = validate_target(d, BASE + 2)
        self.assertFalse(ok)
        self.assertTrue(any("정렬" in p for p in problems))

    def test_bad_idr(self):
        d = MockDap(BASE, idr=0xDEADBEEF)
        seed_valid_block(d)
        ok, problems, _ = validate_target(d, BASE)
        self.assertFalse(ok)
        self.assertTrue(any("IDR" in p for p in problems))

    def test_default_slave_fingerprint(self):
        d = MockDap(BASE)
        d.mem[BASE + OFF_HW_VERSION] = 0xEAFFFFFE
        d.mem[BASE + OFF_STATE] = 0xEAFFFFFE
        ok, problems, _ = validate_target(d, BASE)
        self.assertFalse(ok)
        self.assertTrue(any("default-slave" in p for p in problems))

    def test_negative_base_rejected_without_reads(self):
        # ★ 음수 base 는 AP/메모리 read 를 한 번도 하지 않고 즉시 거부해야 한다
        d = MockDap(BASE)
        seed_valid_block(d)
        ok, problems, _ = validate_target(d, -4)
        self.assertFalse(ok)
        self.assertEqual(d.target_reads, 0)
        self.assertTrue(any("범위" in p for p in problems))

    def test_base_too_high_rejected_without_reads(self):
        d = MockDap(BASE)
        ok, problems, _ = validate_target(d, 0x100000000)
        self.assertFalse(ok)
        self.assertEqual(d.target_reads, 0)

    def test_base_just_over_max_rejected(self):
        d = MockDap(BASE)
        max_base = 0xFFFFFFFF - sj.OFF_TOP
        ok, _, _ = validate_target(d, max_base + 1)
        self.assertFalse(ok)
        self.assertEqual(d.target_reads, 0)

    def test_base_at_max_allowed_reads_happen(self):
        # 경계값(max_base)은 통과 대상이며 read 가 일어난다
        d = MockDap(BASE)
        max_base = (0xFFFFFFFF - sj.OFF_TOP) & ~0x3   # 정렬 맞춤
        d.mem[max_base + OFF_HW_VERSION] = 0x00010203
        d.mem[max_base + OFF_STATE] = 0x0
        ok, problems, _ = validate_target(d, max_base)
        self.assertTrue(ok, problems)
        self.assertGreater(d.target_reads, 0)

    def test_reads_zero_raises(self):
        d = MockDap(BASE)
        seed_valid_block(d)
        with self.assertRaises(ValueError):
            validate_target(d, BASE, reads=0)


class DmMapping(unittest.TestCase):
    def test_main_uses_apbap1(self):
        addr = sj.CORE_BASE_MAIN + sj.DMSTATUS_OFF
        d = MockDap(BASE, dm_cells={(sj.APBAP1_BASE, addr): 0x00000003})
        raw, tag, alive = read_dmstatus(d, sj.CORE_BASE_MAIN)
        self.assertEqual(raw, 0x3)
        self.assertTrue(alive)

    def test_ncore_uses_apbap2(self):
        addr = sj.CORE_BASE_NCORE + sj.DMSTATUS_OFF
        d = MockDap(BASE, dm_cells={(sj.APBAP2_BASE, addr): 0x00000002})
        raw, tag, alive = read_dmstatus(d, sj.CORE_BASE_NCORE)
        self.assertEqual(raw, 0x2)
        self.assertTrue(alive)

    def test_dead_pattern_not_alive(self):
        addr = sj.CORE_BASE_MAIN + sj.DMSTATUS_OFF
        d = MockDap(BASE, dm_cells={(sj.APBAP1_BASE, addr): 0xEAFFFFFE})
        _, _, alive = read_dmstatus(d, sj.CORE_BASE_MAIN)
        self.assertFalse(alive)

    def test_unknown_core_base(self):
        d = MockDap(BASE)
        raw, tag, alive = read_dmstatus(d, 0xDEAD0000)
        self.assertIsNone(raw)
        self.assertFalse(alive)


class StateMachine(unittest.TestCase):
    """unlock() 를 mock DAP 상태 전이로 돌린다. 서명 도구는 34워드 상수로 대체."""

    def setUp(self):
        # run_tool 을 34워드 반환 stub 으로 교체하고 호출 인자를 기록한다
        self._orig = sj.run_tool
        self.tool_calls = []

        def stub(tool, args, want, label, prefix=()):
            self.tool_calls.append((label, list(args), want, list(prefix)))
            return list(range(want))
        sj.run_tool = stub

    def tearDown(self):
        sj.run_tool = self._orig

    def test_already_unlocked(self):
        d = MockDap(BASE)
        d.mem[BASE + OFF_STATE] = AUTH_PASS
        d.mem[BASE + OFF_HW_VERSION] = 0x1
        r = unlock(d, BASE, "toolpath", "stdout", timeout=1)
        self.assertEqual(r.status, ST_ALREADY)
        self.assertTrue(r.state & AUTH_PASS)
        self.assertEqual(d.writes, [])          # 쓰기 없이 종료

    def test_soft_lock_absent_is_not_authenticated(self):
        # ★ 리뷰 #1: SOFT_LOCK 미설정을 AUTH_PASS/AUTHENTICATED 로 오판하면 안 된다
        d = MockDap(BASE)
        d.mem[BASE + OFF_STATE] = 0x0           # AUTH_PASS 없음, 0x2 쓴 뒤도 SOFT_LOCK 없음
        d.mem[BASE + OFF_HW_VERSION] = 0x1
        r = unlock(d, BASE, "toolpath", "stdout", timeout=1)
        self.assertEqual(r.status, ST_OPEN_NO_SOFT_LOCK)
        self.assertFalse(r.state & AUTH_PASS)   # AUTH_PASS 가 아니어야 한다
        self.assertFalse(r.state & SOFT_LOCK)

    def test_full_flow_reaches_auth_pass(self):
        d = MockDap(BASE)
        d.mem[BASE + OFF_STATE] = SOFT_LOCK     # 잠김
        d.mem[BASE + OFF_HW_VERSION] = 0x1
        for i in range(NONCE_WORDS):
            d.mem[BASE + OFF_CHALLENGE + 4 * i] = 0xA0 + i
        d.mem[BASE + OFF_CHIP_ID0] = 0xC0
        d.mem[BASE + OFF_CHIP_ID1] = 0xC1

        def transition(off, val):
            # STATE 쓰기에 따라 다음 폴링 비트를 세워 준다
            if off == OFF_STATE and val == 0x1:
                d.mem[BASE + OFF_STATE] = SOFT_LOCK | REQUEST_READY
            elif off == OFF_REQUEST + 4 * (PUBKEY_WORDS - 1):
                d.mem[BASE + OFF_STATE] = SOFT_LOCK | RESPONSE_READY
            elif off == sj.OFF_RESP_LV1:
                d.mem[BASE + OFF_STATE] = SOFT_LOCK | AUTH_PASS
        d.on_write = transition

        r = unlock(d, BASE, "toolpath", "stdout", timeout=2)
        self.assertEqual(r.status, ST_AUTHENTICATED)
        self.assertTrue(r.state & AUTH_PASS)
        # 공개키 34 + 서명 34 + response 3 + STATE/DBG 쓰기들
        req_writes = [a for a, _ in d.writes if BASE + OFF_REQUEST <= a < BASE + OFF_REQUEST + 4 * PUBKEY_WORDS]
        self.assertEqual(len(req_writes), PUBKEY_WORDS)

        # 도구 호출: pubkey/sign 각각 정확히 34워드 요구
        by_label = {label: (args, want) for label, args, want, _pfx in self.tool_calls}
        self.assertEqual(by_label["pubkey"][1], PUBKEY_WORDS)
        self.assertEqual(by_label["sign"][1], SIG_WORDS)

        # challenge 인자 순서: no[20]..no[0] = Nonce15..Nonce0, CHIP_ID1, CHIP_ID0, FFFFFFFF×3
        chal = by_label["sign"][0][len(sj.SIGN_FLAGS):]     # 플래그 뒤가 challenge
        self.assertEqual(len(chal), 21)
        self.assertEqual(chal[0], "0x000000AF")             # Nonce[15] = 0xA0+15
        self.assertEqual(chal[15], "0x000000A0")            # Nonce[0]
        self.assertEqual(chal[16], "0x000000C1")            # CHIP_ID1
        self.assertEqual(chal[17], "0x000000C0")            # CHIP_ID0
        self.assertEqual(chal[18:], ["0xFFFFFFFF"] * 3)     # prefix (역순 끝)

        # DOMAIN/LV0/LV1 은 모두 0xFFFFFFFF
        for off in (sj.OFF_RESP_DOMAIN, sj.OFF_RESP_LV0, sj.OFF_RESP_LV1):
            self.assertIn((BASE + off, 0xFFFFFFFF), d.writes)

    def test_invalid_public_key_aborts(self):
        d = MockDap(BASE)
        d.mem[BASE + OFF_STATE] = SOFT_LOCK
        d.mem[BASE + OFF_HW_VERSION] = 0x1

        def transition(off, val):
            if off == OFF_STATE and val == 0x1:
                d.mem[BASE + OFF_STATE] = SOFT_LOCK | REQUEST_READY
            elif off == OFF_REQUEST + 4 * (PUBKEY_WORDS - 1):
                d.mem[BASE + OFF_STATE] = SOFT_LOCK | INVALID_PUBKEY
        d.on_write = transition

        with self.assertRaises(SecureJtagError):
            unlock(d, BASE, "toolpath", "stdout", timeout=2)


# ── MockJL: DP/AP 원시 트랜잭션을 흉내내 실제 MemDap / prepare_session 검증 ──
class MockJL:
    """coresight_read/write(ap=..) 를 최소 구현. DP reg1=CTRL/STAT, AP 는
    (SELECT, idx) 키로 저장. apply_settings 가 부르는 exec/set_* 도 받는다."""

    def __init__(self, ctrl_stat=0x30000000, ap_seed=None, rdbuff_none=False):
        self.cfg_kwargs = []
        self.dp_writes = []
        self.dp_reads = []          # ap=False read 의 reg 순서 기록
        self.ap_writes = []
        self.select = None
        self.ctrl_stat = ctrl_stat
        self.ap = dict(ap_seed or {})
        self.aborts = 0
        self.rdbuff_none = rdbuff_none

    # apply_settings 용
    def exec_command(self, c):
        pass

    def set_tif(self, t):
        pass

    def set_speed(self, s):
        pass

    def coresight_configure(self, **kw):
        self.cfg_kwargs.append(kw)

    def coresight_write(self, reg, val, ap=False):
        if ap:
            self.ap[(self.select, reg)] = val & 0xFFFFFFFF
            self.ap_writes.append((self.select, reg, val & 0xFFFFFFFF))
        else:
            self.dp_writes.append((reg, val))
            if reg == 0 and val == 0x1E:      # ABORT
                self.aborts += 1
            elif reg == 2:                    # SELECT
                self.select = val & 0xFFFFFFFF

    def coresight_read(self, reg, ap=False):
        if ap:
            return self.ap.get((self.select, reg), 0)
        self.dp_reads.append(reg)
        if reg == 3 and self.rdbuff_none:     # RDBUFF read 실패 모사
            return None
        if reg == 1:                          # CTRL/STAT
            return self.ctrl_stat
        return 0                              # RDBUFF 등


class ConfigFailJL(MockJL):
    """명시적(kw 있는) coresight_configure 만 지정 예외로 실패시키고,
    인자없는 fallback 호출은 정상 기록한다."""

    def __init__(self, exc, **kw):
        super().__init__(**kw)
        self.exc = exc

    def coresight_configure(self, **kw):
        if kw:
            raise self.exc
        self.cfg_kwargs.append(kw)            # fallback({}) 이 불리면 기록


class PrepareSession(unittest.TestCase):
    def _link(self, jl):
        lk = sj.Link(core_base=sj.CORE_BASE_MAIN, verbose=False)
        lk.jl = jl
        return lk

    def test_tif_init_true_by_default(self):
        # ★ 회귀: 기본값 자체를 고정한다 — tif_init 인자를 넘기지 않는다.
        #   함수 기본이 False 로 바뀌면 이 테스트가 깨져야 한다.
        jl = MockJL(ctrl_stat=0x30000000)         # CDBGPWRUPACK(bit29) 세워짐
        lk = self._link(jl)
        ack = sj.prepare_session(lk, "dbg-only", "off")
        self.assertTrue(jl.cfg_kwargs[0]["perform_tif_init"])
        self.assertTrue(ack & (1 << 29))
        self.assertTrue(lk.dap_power_ok)

    def test_typeerror_on_falls_back(self):
        # 인자 호환성(TypeError) + tif on → 인자없는 fallback 허용
        jl = ConfigFailJL(TypeError("old api"), ctrl_stat=0x30000000)
        lk = self._link(jl)
        ack = sj.prepare_session(lk, "dbg-only", "on", tif_init=True)
        self.assertTrue(ack & (1 << 29))
        self.assertIn({}, jl.cfg_kwargs)          # 인자없는 fallback 이 불렸다

    def test_typeerror_off_no_fallback(self):
        # TypeError + tif off → fallback 은 switching sequence 를 켜므로 중단
        jl = ConfigFailJL(TypeError("old api"))
        lk = self._link(jl)
        with self.assertRaises(SecureJtagError):
            sj.prepare_session(lk, "dbg-only", "off", tif_init=False)
        self.assertEqual(jl.cfg_kwargs, [])

    def test_runtimeerror_never_falls_back(self):
        # 통신/J-Link 오류(RuntimeError)는 호환성 문제가 아니다 → fallback 금지
        jl = ConfigFailJL(RuntimeError("comm fail"))
        lk = self._link(jl)
        with self.assertRaises(SecureJtagError):
            sj.prepare_session(lk, "dbg-only", "on", tif_init=True)
        self.assertEqual(jl.cfg_kwargs, [])

    def test_fallback_itself_failing_maps_to_config_exit(self):
        # 명시 configure=TypeError(→fallback), 무인자 fallback=RuntimeError 이면
        # 최상위 EXIT_INSUFFICIENT 가 아니라 EXIT_CONFIG 로 분류돼야 한다.
        class FallbackFailJL(MockJL):
            def coresight_configure(self, **kw):
                raise TypeError("old api") if kw else RuntimeError("fallback fail")
        jl = FallbackFailJL(ctrl_stat=0x30000000)
        lk = self._link(jl)
        with self.assertRaises(SecureJtagError) as cm:
            sj.prepare_session(lk, "dbg-only", "on", tif_init=True)
        self.assertEqual(cm.exception.exit_code, EXIT_CONFIG)

    def test_dbg_only_power_request(self):
        jl = MockJL(ctrl_stat=0x30000000)
        lk = self._link(jl)
        sj.prepare_session(lk, "dbg-only", "off", tif_init=True)
        # CDBGPWRUPREQ(0x10000000)만, CSYSPWRUPREQ 는 안 켬
        self.assertIn((1, 0x10000000), jl.dp_writes)
        self.assertNotIn((1, 0x50000000), jl.dp_writes)

    def test_both_power_request(self):
        jl = MockJL(ctrl_stat=0xF0000000)
        lk = self._link(jl)
        sj.prepare_session(lk, "both", "off", tif_init=True)
        self.assertIn((1, 0x50000000), jl.dp_writes)

    def test_no_ack_raises(self):
        jl = MockJL(ctrl_stat=0x00000000)         # ACK 안 뜸
        lk = self._link(jl)
        with self.assertRaises(SecureJtagError):
            sj.prepare_session(lk, "dbg-only", "off", tif_init=True)

    def test_both_requires_csyspwrupack(self):
        # ★ power=both 인데 CDBGPWRUPACK(bit29)만 뜨고 CSYSPWRUPACK(bit31) 없으면 실패
        jl = MockJL(ctrl_stat=0x30000000)         # bit29만
        lk = self._link(jl)
        with self.assertRaises(SecureJtagError):
            sj.prepare_session(lk, "both", "off", tif_init=True)


class VerdictClassification(unittest.TestCase):
    @staticmethod
    def _dm(alive):
        return (0x3 if alive else 0xEAFFFFFE, "tag", alive)

    def test_auth_before_dead_after_alive_ok(self):
        code, lines = classify_verdict(ST_AUTHENTICATED, self._dm(False), self._dm(True))
        self.assertEqual(code, EXIT_OK)
        self.assertIn("강한 증거", " ".join(lines))

    def test_auth_before_alive_cause_unproven(self):
        code, _ = classify_verdict(ST_AUTHENTICATED, self._dm(True), self._dm(True))
        self.assertEqual(code, EXIT_CAUSE_UNPROVEN)

    def test_auth_both_dead_verify_weak(self):
        code, lines = classify_verdict(ST_AUTHENTICATED, self._dm(False), self._dm(False))
        self.assertEqual(code, EXIT_VERIFY_WEAK)
        self.assertIn("AUTH_PASS 는 떴으나", " ".join(lines))

    def test_already_never_claims_causation(self):
        for after in (self._dm(True), self._dm(False)):
            code, lines = classify_verdict(ST_ALREADY, self._dm(False), after)
            joined = " ".join(lines)
            self.assertEqual(code, EXIT_CAUSE_UNPROVEN)
            self.assertNotIn("강한 증거", joined)          # 인과 주장 금지
            self.assertNotIn("AUTH_PASS 는 떴으나", joined)

    def test_open_no_soft_lock_never_claims_auth(self):
        for after in (self._dm(True), self._dm(False)):
            code, lines = classify_verdict(ST_OPEN_NO_SOFT_LOCK, self._dm(False), after)
            joined = " ".join(lines)
            self.assertEqual(code, EXIT_CAUSE_UNPROVEN)
            self.assertNotIn("강한 증거", joined)
            self.assertNotIn("AUTH_PASS 는 떴으나", joined)
            self.assertIn("STATE<=0x2", joined)             # 실제 수행한 것만 명시

    def test_unknown_status_raises(self):
        # 오타/신규 상태를 조용히 오분류하지 않는다
        with self.assertRaises(ValueError):
            classify_verdict("TYPO", self._dm(False), self._dm(True))


class TimeoutValidation(unittest.TestCase):
    def test_rejects_nonpositive_and_nonfinite(self):
        for bad in (float("nan"), float("inf"), float("-inf"), 0, -5, -0.1):
            self.assertFalse(valid_timeout(bad), bad)

    def test_accepts_positive_finite(self):
        for good in (0.5, 1, 60, 3600.0):
            self.assertTrue(valid_timeout(good), good)


class BaseValidation(unittest.TestCase):
    def test_rejects_bad_types(self):
        for bad in ("0x40000000", 4.0, True, False, None):
            ok, _ = valid_base(bad)
            self.assertFalse(ok, bad)

    def test_rejects_range_and_alignment(self):
        for bad in (-4, 0x100000000, 0xFFFFFFFF - sj.OFF_TOP + 1, 0x40000002):
            ok, _ = valid_base(bad)
            self.assertFalse(ok, hex(bad) if bad >= 0 else bad)

    def test_accepts_valid(self):
        ok, reason = valid_base(0x40000000)
        self.assertTrue(ok, reason)


class UnlockGuards(unittest.TestCase):
    def test_nan_timeout_rejected_at_entry(self):
        # 모듈 API 로 직접 호출해도 nan 이 무한폴링 대신 즉시 거부돼야 한다
        d = MockDap(0x40000000)
        with self.assertRaises(SecureJtagError):
            unlock(d, 0x40000000, "tool", "stdout", timeout=float("nan"))
        self.assertEqual(d.target_reads, 0)     # 읽기 전에 막힘


class MainGuards(unittest.TestCase):
    """main() 배선 검증: 잘못된 입력이면 J-Link 를 열기 전에 EXIT_CONFIG."""

    def _run(self, argv):
        created = []

        def boom(*a, **k):
            created.append(1)
            raise AssertionError("Link 가 생성되면 안 된다")

        orig_link, orig_argv = sj.Link, sys.argv
        sj.Link = boom
        sys.argv = ["sjtag_unlock"] + argv
        try:
            return sj.main(), created
        finally:
            sj.Link, sys.argv = orig_link, orig_argv

    def test_bad_timeout_returns_config_without_link(self):
        code, created = self._run(["--base", "0x40000000", "--timeout", "nan"])
        self.assertEqual(code, EXIT_CONFIG)
        self.assertEqual(created, [])

    def test_out_of_range_base_returns_config_without_link(self):
        code, created = self._run(["--base", "0x100000000"])
        self.assertEqual(code, EXIT_CONFIG)
        self.assertEqual(created, [])


class MemWrite(unittest.TestCase):
    """실제 MemDap.mem_write32 를 MockJL 로 검증 (posted-write/sticky 경로)."""

    BASE = 0xB000             # mock AP 베이스 (실주소 아님 — 값 무관)
    ADDR = 0x40000004

    def _dap(self, ctrl_stat):
        # CSW 를 usable 값으로 seed (select = (BASE+0xD00)&~0xF)
        sel = (self.BASE + 0xD00) & 0xFFFFFFF0
        jl = MockJL(ctrl_stat=ctrl_stat, ap_seed={(sel, 0): 0x23000002})
        return sj.MemDap(jl), jl

    def test_clean_write_ok(self):
        dap, jl = self._dap(0x30000000)           # 오류비트 없음
        self.assertTrue(dap.mem_write32(self.BASE, self.ADDR, 0x2))
        self.assertEqual(jl.aborts, 0)

    def test_rdbuff_flush_before_ctrl_stat(self):
        # ★ RDBUFF(reg3) read 를 CTRL/STAT(reg1) 앞에서 반드시 한다.
        #   이 순서가 깨지거나 RDBUFF read 를 지우면 실패해야 한다.
        dap, jl = self._dap(0x30000000)
        dap.mem_write32(self.BASE, self.ADDR, 0x2)
        self.assertEqual(jl.dp_reads, [3, 1])     # RDBUFF 먼저, 그다음 CTRL/STAT

    def test_rdbuff_read_none_fails(self):
        # RDBUFF read 가 None(flush 실패)이면 CTRL/STAT 이 정상이어도 write 실패
        dap, jl = self._dap(0x30000000)
        jl.rdbuff_none = True
        self.assertFalse(dap.mem_write32(self.BASE, self.ADDR, 0x2))
        self.assertEqual(jl.dp_reads, [3])        # CTRL/STAT 까지 안 감(단락)
        self.assertIn('why', dap.last)

    def test_stickyerr_fails_and_aborts(self):
        dap, jl = self._dap(0x30000000 | (1 << 5))   # STICKYERR
        self.assertFalse(dap.mem_write32(self.BASE, self.ADDR, 0x2))
        self.assertGreaterEqual(jl.aborts, 1)         # ABORT 호출됨
        self.assertIsNone(dap._select)                # SELECT 캐시 초기화됨

    def test_wdataerr_fails(self):
        dap, jl = self._dap(0x30000000 | (1 << 7))   # WDATAERR
        self.assertFalse(dap.mem_write32(self.BASE, self.ADDR, 0x2))

    def test_stickyorun_fails(self):
        dap, jl = self._dap(0x30000000 | (1 << 1))   # STICKYORUN
        self.assertFalse(dap.mem_write32(self.BASE, self.ADDR, 0x2))


if __name__ == "__main__":
    unittest.main()
