"""NVMe 시드 템플릿 — pc_sampling_fuzzer가 import해서 사용한다.

각 명령어별 CDW 조합 목록. 변이(mutation)의 시작점이 되는 정상 명령어 집합.
시드를 추가/제거할 때는 이 파일만 수정하면 된다.
"""

import struct

# CDW12 Protection/Access 비트 (NVMe 2.0 기준)
_FUA       = 1 << 31   # Force Unit Access
_LR        = 1 << 30   # Limited Retry
_PRACT     = 1 << 29   # Protection Info Action (insert/strip)
_PRCHK_ALL = (1 << 26) | (1 << 27) | (1 << 28)  # 3-bit PRCHK 전체 set
_PRINFO_ALL = _PRACT | _PRCHK_ALL                # PRACT + PRCHK 전체
_DEAC      = 1 << 25   # WriteZeroes: deallocate after zeroing

SEED_TEMPLATES = {
    # Identify — CDW10[7:0]=CNS, CDW10[31:16]=CNTID
    "Identify": [
        # CNS=0x01(Controller): NSID는 Reserved → nsid_override=0
        dict(cdw10=0x0001, nsid_override=0),
        dict(cdw10=0x0000),
        dict(cdw10=0x0002, nsid_override=0),
        dict(cdw10=0x0003),
        dict(cdw10=0x0004),
        dict(cdw10=0x0005),
        dict(cdw10=0x0006, nsid_override=0),
        dict(cdw10=0x0007, nsid_override=0),
        dict(cdw10=0x0008, nsid_override=0),
        dict(cdw10=0x0009, nsid_override=0),
        dict(cdw10=0x001C),
        dict(cdw10=0x001D),
        # CNTID 필드 포함 (CNS=0x06/0x07에서 특정 컨트롤러 조회)
        dict(cdw10=(0x0001 << 16) | 0x0006, nsid_override=0),
        # 미지원 CNS — 에러 경로 탐색
        dict(cdw10=0x00FF, nsid_override=0),
    ],

    # GetLogPage — CDW10[7:0]=LID, CDW10[26:16]=NUMDL, CDW10[15]=RAE
    #              CDW10[12:8]=LSP, CDW11[15:0]=NUMDH
    #              CDW12=LPOL (Log Page Offset Lower dword)
    #              CDW13=LPOU (Log Page Offset Upper dword)
    "GetLogPage": [
        dict(cdw10=(0x0F << 16) | 0x01, nsid_override=0),
        dict(cdw10=(0x7F << 16) | 0x02, nsid_override=0),
        dict(cdw10=(0x0F << 16) | 0x03, nsid_override=0),
        dict(cdw10=(0xFF << 16) | 0x04, nsid_override=0xFFFFFFFF),
        dict(cdw10=(0xFF << 16) | 0x05, nsid_override=0),
        dict(cdw10=(0x8F << 16) | 0x06, nsid_override=0),
        dict(cdw10=(0x1FF << 16) | 0x07, nsid_override=0),
        dict(cdw10=(0x1FF << 16) | 0x08, nsid_override=0),
        dict(cdw10=(0x7F << 16) | 0x09),
        dict(cdw10=(0x1FF << 16) | 0x0A, nsid_override=0),
        dict(cdw10=(0x7F << 16) | 0x0B),
        dict(cdw10=(0xFFF << 16) | 0x0C, nsid_override=0),
        dict(cdw10=(0xFF << 16) | 0x0D, nsid_override=0),
        dict(cdw10=(0xFF << 16) | 0x0E, nsid_override=0),
        dict(cdw10=(0xFF << 16) | 0x0F, nsid_override=0),
        dict(cdw10=(0xFF << 16) | 0x10, nsid_override=0),
        dict(cdw10=(0xFF << 16) | 0x11, nsid_override=0),
        dict(cdw10=(0xFF << 16) | 0x12, nsid_override=0),
        dict(cdw10=(0x1FF << 16) | 0x13, nsid_override=0),
        dict(cdw10=(0xFF << 16) | 0x70, nsid_override=0),
        dict(cdw10=(0xFF << 16) | 0x80),
        dict(cdw10=(0xFF << 16) | 0x81, nsid_override=0),
        dict(cdw10=(0x7F << 16) | (1 << 15) | 0x02, nsid_override=0),
        # LPOL 오프셋 (CDW12) — 큰 로그의 중간부터 읽기
        dict(cdw10=(0x7F << 16) | 0x02, cdw12=0x200, nsid_override=0),
        dict(cdw10=(0xFFF << 16) | 0x0C, cdw11=0x0001, nsid_override=0),
        dict(cdw10=(0xFF << 16) | 0xFF, nsid_override=0),
    ],

    # GetFeatures — CDW10[7:0]=FID, CDW10[9:8]=SEL (current/default/saved/supported)
    "GetFeatures": [
        dict(cdw10=0x01),
        dict(cdw10=0x02),
        dict(cdw10=0x03),
        dict(cdw10=0x04),
        dict(cdw10=0x05),
        dict(cdw10=0x06),
        dict(cdw10=0x07),
        dict(cdw10=0x08),
        dict(cdw10=0x09),
        dict(cdw10=0x0A),
        dict(cdw10=0x0B),
        dict(cdw10=0x0C),
        dict(cdw10=0x0D),
        dict(cdw10=0x0E),
        dict(cdw10=0x0F),
        dict(cdw10=0x10),
        dict(cdw10=0x11),
        dict(cdw10=0x12),
        dict(cdw10=0x7E),
        dict(cdw10=0x7F),
        dict(cdw10=0x80),
        # SEL=1 (default value) 변형
        dict(cdw10=(1 << 8) | 0x06),
        dict(cdw10=(1 << 8) | 0x02),
        # SEL=2 (saved) 변형
        dict(cdw10=(2 << 8) | 0x06),
        # SEL=3 (supported capabilities) 변형
        dict(cdw10=(3 << 8) | 0x06),
        # 미지원 FID — 에러 경로
        dict(cdw10=0xFF),
    ],

    # SetFeatures — CDW10[7:0]=FID, CDW10[31]=SV (Save), CDW11=dword value
    "SetFeatures": [
        # FID=0x01: Arbitration — controller-scoped → NSID=0
        dict(cdw10=0x01, cdw11=0x00000003, nsid_override=0),
        # FID=0x02: Power Management — controller-scoped → NSID=0
        dict(cdw10=0x02, cdw11=0x00000000, nsid_override=0),
        # PS1~PS4 제외: --pm 플래그가 PS 퍼징 + PS0 복구를 담당.
        # standalone 시드로 PS 진입하면 다음 명령까지 wake-up latency 발생.
        # FID=0x04: Temperature Threshold — controller-scoped → NSID=0
        dict(cdw10=0x04, cdw11=0x0000012C, nsid_override=0),
        dict(cdw10=0x04, cdw11=0x00010050, nsid_override=0),
        dict(cdw10=0x04, cdw11=0x000107FF, nsid_override=0),
        # FID=0x05: Error Recovery — namespace-scoped → NSID=1 (default)
        dict(cdw10=0x05, cdw11=0x00000000),
        # FID=0x06: Volatile Write Cache — controller-scoped → NSID=0
        dict(cdw10=0x06, cdw11=0x00000001, nsid_override=0),
        dict(cdw10=0x06, cdw11=0x00000000, nsid_override=0),
        # FID=0x07: Number of Queues — controller-scoped → NSID=0
        dict(cdw10=0x07, cdw11=0x00010001, nsid_override=0),
        # FID=0x08: Interrupt Coalescing — controller-scoped → NSID=0
        dict(cdw10=0x08, cdw11=0x00000000, nsid_override=0),
        dict(cdw10=0x08, cdw11=0x00000A04, nsid_override=0),
        # FID=0x0B: Async Event Configuration — controller-scoped → NSID=0
        dict(cdw10=0x0B, cdw11=0x00000000, nsid_override=0),
        dict(cdw10=0x0B, cdw11=0x000000FF, nsid_override=0),
        # FID=0x0E: Timestamp — controller-scoped → NSID=0
        # CDW11+CDW12 = 48-bit timestamp (ms since epoch)
        dict(cdw10=0x0E, cdw11=0x00000000, nsid_override=0),
        # FID=0x10: Host Controlled Thermal Management — controller-scoped → NSID=0
        dict(cdw10=0x10, cdw11=0x00000003, nsid_override=0),
        # FID=0x0C: Autonomous Power State Transition (APST) — controller-scoped → NSID=0
        # Entry[3:0]=ITPS(Idle Trans PS), Entry[31:8]=ITP(×100ms, 0=disable)
        dict(cdw10=0x0C, cdw11=0x00000000, data=b'\x00' * 256, nsid_override=0),
        dict(cdw10=0x0C, cdw11=0x00000001, data=b'\x00' * 256, nsid_override=0),
        # APST table: entry[0] ITP=10(1s) ITPS=3, entry[1] ITP=100(10s) ITPS=4
        dict(cdw10=0x0C, cdw11=0x00000001,
             data=(
                 (10 << 8 | 3).to_bytes(4, 'little') + b'\x00' * 4 +   # entry0: 1s→PS3
                 (100 << 8 | 4).to_bytes(4, 'little') + b'\x00' * 4 +  # entry1: 10s→PS4
                 b'\x00' * 240
             ),
             nsid_override=0),
        # FID=0x0D: Host Memory Buffer (HMB) — controller-scoped → NSID=0
        dict(cdw10=0x0D, cdw11=0x00000000, nsid_override=0),
        dict(cdw10=0x0D, cdw11=0x00000002, nsid_override=0),
        # FID=0x0F: Keep Alive Timer — controller-scoped → NSID=0
        # CDW11=KATO (ms, 0=disable)
        dict(cdw10=0x0F, cdw11=0x00000000, nsid_override=0),
        dict(cdw10=0x0F, cdw11=0x00001388, nsid_override=0),
        dict(cdw10=0x0F, cdw11=0xFFFFFFFF, nsid_override=0),
        # FID=0x11: Non-Operational Power State Config — controller-scoped → NSID=0
        dict(cdw10=0x11, cdw11=0x00000000, nsid_override=0),
        dict(cdw10=0x11, cdw11=0x00000001, nsid_override=0),
        # FID=0x12: Read Recovery Level — controller-scoped → NSID=0
        dict(cdw10=0x12, cdw11=0x00000000, nsid_override=0),
        dict(cdw10=0x12, cdw11=0x0000000F, nsid_override=0),
        # SV=1 변형 (설정값 저장) — controller-scoped → NSID=0
        dict(cdw10=(1 << 31) | 0x06, cdw11=0x00000001, nsid_override=0),
    ],

    # Read — CDW10=SLBA[31:0], CDW11=SLBA[63:32], CDW12[15:0]=NLB
    #         CDW12[29]=PRACT, CDW12[30]=LR, CDW12[31]=FUA
    #         CDW13[15:0]=DSPEC (Streams ID), CDW14=ILBRT, CDW15=LBAT/LBATM
    "Read": [
        dict(cdw10=0,     cdw11=0, cdw12=0),
        dict(cdw10=1,     cdw11=0, cdw12=0),
        dict(cdw10=0,     cdw11=0, cdw12=7),
        dict(cdw10=0,     cdw11=0, cdw12=31),
        dict(cdw10=0,     cdw11=0, cdw12=127),
        dict(cdw10=0,     cdw11=0, cdw12=255),
        dict(cdw10=0,     cdw11=0, cdw12=0xFFFF),
        dict(cdw10=500,   cdw11=0, cdw12=0),
        dict(cdw10=1000,  cdw11=0, cdw12=0),
        dict(cdw10=5000,  cdw11=0, cdw12=0),
        dict(cdw10=10000, cdw11=0, cdw12=0),
        dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0),
        dict(cdw10=0xFFFF0000, cdw11=0xFFFFFFFF, cdw12=0),
        dict(cdw10=0, cdw11=0, cdw12=_PRACT),
        dict(cdw10=0, cdw11=0, cdw12=_LR),
        dict(cdw10=0, cdw11=0, cdw12=_FUA),
        dict(cdw10=0, cdw11=0, cdw12=_PRINFO_ALL),
        dict(cdw10=0, cdw11=0, cdw12=_FUA | _LR),
        dict(cdw10=0, cdw11=0, cdw12=_PRCHK_ALL),
        dict(cdw10=0, cdw11=0, cdw12=_PRINFO_ALL, cdw14=0xDEADBEEF, cdw15=0xFFFF0000),
        dict(cdw10=0, cdw11=0, cdw12=_PRACT, cdw14=0x00000001, cdw15=0x00010001),
        dict(cdw10=0, cdw11=0, cdw12=(1 << 30), cdw13=0x0001),
        dict(cdw10=0, cdw11=0, cdw12=(1 << 30), cdw13=0x0002),
    ],

    # Write — CDW10=SLBA[31:0], CDW11=SLBA[63:32], CDW12[15:0]=NLB
    #          CDW12[29]=PRACT, CDW12[30]=LR, CDW12[31]=FUA
    #          CDW13[15:0]=DSPEC, CDW14=ILBRT, CDW15=LBAT/LBATM
    "Write": [
        dict(cdw10=0,     cdw11=0, cdw12=0, data=b'\x00' * 512),
        dict(cdw10=0,     cdw11=0, cdw12=0, data=b'\xAA' * 512),
        dict(cdw10=0,     cdw11=0, cdw12=0, data=b'\xFF' * 512),
        dict(cdw10=0,     cdw11=0, cdw12=0, data=bytes(range(256)) * 2),
        dict(cdw10=0, cdw11=0, cdw12=7,   data=b'\x00' * (8   * 512)),
        dict(cdw10=0, cdw11=0, cdw12=31,  data=b'\x00' * (32  * 512)),
        dict(cdw10=0, cdw11=0, cdw12=127, data=b'\x00' * (128 * 512)),
        dict(cdw10=0, cdw11=0, cdw12=255, data=b'\x00' * (256 * 512)),
        dict(cdw10=500,   cdw11=0, cdw12=0, data=b'\x00' * 512),
        dict(cdw10=1000,  cdw11=0, cdw12=0, data=b'\x00' * 512),
        dict(cdw10=5000,  cdw11=0, cdw12=0, data=b'\x00' * 512),
        dict(cdw10=10000, cdw11=0, cdw12=0, data=b'\x00' * 512),
        dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0, data=b'\x00' * 512),
        dict(cdw10=0xFFFF0000, cdw11=0xFFFFFFFF, cdw12=0, data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=_PRACT,    data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=_LR,       data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=_FUA,      data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=_PRINFO_ALL, data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=_FUA | _LR, data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=_PRINFO_ALL,
             cdw14=0xDEADBEEF, cdw15=0xFFFF0000, data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=(1 << 30), cdw13=0x0001, data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=0, cdw13=0x4, data=b'\x00' * 512),  # IDR (Random)
        dict(cdw10=0, cdw11=0, cdw12=0, cdw13=0x8, data=b'\x00' * 512),  # IDW (Incompressible)
    ],

    # WriteZeroes — CDW10=SLBA[31:0], CDW11=SLBA[63:32], CDW12[15:0]=NLB
    #                CDW12[25]=DEAC, CDW12[29]=PRACT, CDW12[30]=LR, CDW12[31]=FUA
    #                (데이터 전송 없음 — DMA 없이 펌웨어가 직접 0 기록)
    "WriteZeroes": [
        dict(cdw10=0,     cdw11=0, cdw12=0),
        dict(cdw10=0,     cdw11=0, cdw12=7),
        dict(cdw10=0,     cdw11=0, cdw12=255),
        dict(cdw10=0,     cdw11=0, cdw12=0xFFFF),
        dict(cdw10=0,     cdw11=0, cdw12=_DEAC),
        dict(cdw10=0,     cdw11=0, cdw12=_FUA),
        dict(cdw10=0,     cdw11=0, cdw12=_DEAC | _FUA),
        dict(cdw10=500,   cdw11=0, cdw12=0),
        dict(cdw10=5000,  cdw11=0, cdw12=0),
        dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0),
    ],

    # Compare — Read처럼 LBA에서 읽어 호스트 버퍼와 비교
    #            CDW10=SLBA[31:0], CDW11=SLBA[63:32], CDW12[15:0]=NLB
    "Compare": [
        dict(cdw10=0,     cdw11=0, cdw12=0, data=b'\x00' * 512),
        dict(cdw10=0,     cdw11=0, cdw12=0, data=b'\xFF' * 512),
        dict(cdw10=0,     cdw11=0, cdw12=0, data=b'\xAA' * 512),
        dict(cdw10=0,     cdw11=0, cdw12=7, data=b'\x00' * (8  * 512)),
        dict(cdw10=0,     cdw11=0, cdw12=31, data=b'\x00' * (32 * 512)),
        dict(cdw10=500,   cdw11=0, cdw12=0, data=b'\x00' * 512),
        dict(cdw10=5000,  cdw11=0, cdw12=0, data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=_FUA,      data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=_LR,       data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=_FUA | _LR, data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=_PRINFO_ALL, data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=_PRCHK_ALL,  data=b'\x00' * 512),
        dict(cdw10=0, cdw11=0, cdw12=_PRINFO_ALL,
             cdw14=0xDEADBEEF, cdw15=0xFFFF0000, data=b'\x00' * 512),
        dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0, data=b'\x00' * 512),
    ],

    # WriteUncorrectable — LBA를 uncorrectable 상태로 마킹 (에러 주입)
    #                       CDW10=SLBA[31:0], CDW11=SLBA[63:32], CDW12[15:0]=NLB
    #                       데이터 전송 없음
    "WriteUncorrectable": [
        dict(cdw10=0,    cdw11=0, cdw12=0),
        dict(cdw10=0,    cdw11=0, cdw12=7),
        dict(cdw10=0,    cdw11=0, cdw12=0xFFFF),
        dict(cdw10=500,  cdw11=0, cdw12=0),
        dict(cdw10=5000, cdw11=0, cdw12=0),
        dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0),
    ],

    # Verify — LBA 읽기 후 CRC/PI 검증 (데이터 호스트 반환 없음)
    #           CDW12[29]=PRACT, CDW12[28:26]=PRCHK, CDW12[30]=LR
    "Verify": [
        dict(cdw10=0,    cdw11=0, cdw12=0),
        dict(cdw10=0,    cdw11=0, cdw12=7),
        dict(cdw10=0,    cdw11=0, cdw12=255),
        dict(cdw10=0,    cdw11=0, cdw12=0xFFFF),
        dict(cdw10=0,    cdw11=0, cdw12=_PRINFO_ALL),
        dict(cdw10=0,    cdw11=0, cdw12=_LR),
        dict(cdw10=0,    cdw11=0, cdw12=_PRCHK_ALL),
        dict(cdw10=0,    cdw11=0, cdw12=_PRACT | _LR, cdw14=0xDEADBEEF),
        dict(cdw10=500,  cdw11=0, cdw12=0),
        dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0),
    ],

    # DeviceSelfTest — CDW10[3:0]=STC (Self-test Code)
    #                   0x1=Short, 0x2=Extended, 0xE=Vendor, 0xF=Abort
    #                   명령은 즉시 반환, 테스트는 백그라운드 실행
    "DeviceSelfTest": [
        dict(cdw10=0x01, nsid_override=0),
        dict(cdw10=0x02, nsid_override=0),
        dict(cdw10=0x0E, nsid_override=0),
        dict(cdw10=0x0F, nsid_override=0),
        # NSID=1 (NS-scope self-test) — 일부 구현에서 NS별 테스트 지원
        dict(cdw10=0x01),
        # 미지원 STC — 에러 경로
        dict(cdw10=0x03, nsid_override=0),
    ],

    # SecuritySend — CDW10[31:24]=SECP, CDW10[23:8]=SPSP, CDW10[7:0]=NSSF
    #                 CDW11=TL (Transfer Length, bytes)
    #                 데이터: 호스트→SSD
    "SecuritySend": [
        # SECP=0x00: Security Protocol Information (Protocol List)
        dict(cdw10=(0x00 << 24), cdw11=512, data=b'\x00' * 512),
        # SECP=0x01: TCG (NVMe에서 가장 일반적)
        dict(cdw10=(0x01 << 24) | (0x0001 << 8), cdw11=512, data=b'\x00' * 512),
        dict(cdw10=(0x01 << 24) | (0x0007 << 8), cdw11=512, data=b'\x00' * 512),
        # SECP=0x02: IEEE 1667 (USB-style storage authentication)
        dict(cdw10=(0x02 << 24), cdw11=512, data=b'\x00' * 512),
        # SECP=0xEA: NVMe-specific Security
        dict(cdw10=(0xEA << 24), cdw11=512, data=b'\x00' * 512),
        # SECP=0xEF: ATA Security (SATA 이식 제품 일부 구현)
        dict(cdw10=(0xEF << 24), cdw11=0, data=b''),
        # 미지원 SECP — 에러 경로
        dict(cdw10=(0xFF << 24), cdw11=512, data=b'\x00' * 512),
    ],

    # SecurityReceive — CDW10[31:24]=SECP, CDW10[23:8]=SPSP, CDW10[7:0]=NSSF
    #                    CDW11=AL (Allocation Length, bytes)
    #                    데이터: SSD→호스트 (data_len = CDW11 by _send_nvme_command)
    "SecurityReceive": [
        # SECP=0x00: Protocol list 조회 — 지원 프로토콜 목록
        dict(cdw10=(0x00 << 24), cdw11=512),
        # SECP=0x01: TCG
        dict(cdw10=(0x01 << 24) | (0x0001 << 8), cdw11=512),
        dict(cdw10=(0x01 << 24) | (0x0001 << 8), cdw11=4096),
        # SECP=0x02: IEEE 1667
        dict(cdw10=(0x02 << 24), cdw11=512),
        # SECP=0xEA: NVMe-specific
        dict(cdw10=(0xEA << 24), cdw11=512),
        # AL=0 — 크기 0 조회 (지원 여부 확인용)
        dict(cdw10=(0x01 << 24), cdw11=0),
        # 미지원 SECP
        dict(cdw10=(0xFF << 24), cdw11=512),
    ],

    # GetLBAStatus — CDW10=SLBA[31:0], CDW11=SLBA[63:32]
    #                 CDW12=MNDW (Max Number of Dwords, 0-based)
    #                 CDW13[15:0]=RL (Range Length), CDW13[31:16]=ATYPE
    #                   ATYPE=0: All LBAs, 1: Allocated, 2: Unallocated
    "GetLBAStatus": [
        dict(cdw10=0, cdw11=0, cdw12=0xFF, cdw13=(0x0000 << 16) | 0x0010),
        dict(cdw10=0, cdw11=0, cdw12=0xFF, cdw13=(0x0001 << 16) | 0x0010),
        dict(cdw10=0, cdw11=0, cdw12=0xFF, cdw13=(0x0002 << 16) | 0x0010),
        dict(cdw10=0, cdw11=0, cdw12=0xFF, cdw13=(0x0001 << 16) | 0xFFFF),
        dict(cdw10=5000, cdw11=0, cdw12=0xFF, cdw13=(0x0001 << 16) | 0x0010),
        dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0xFF, cdw13=0x0010),
    ],

    # FWDownload — CDW10=NUMD (0-based dwords), CDW11=OFST (dword offset)
    # NUMD = (32768 / 4) - 1 = 0x1FFF, 기본 -x 32768 와 동일
    "FWDownload": [
        dict(cdw10=0x1FFF, cdw11=0, data=b'\x00' * 32768),
    ],

    # FWCommit — CDW10[2:0]=CA (Commit Action), CDW10[5:3]=FS (Firmware Slot)
    #             CA=0: replace, no activate
    #             CA=1: replace, activate on next reset
    #             CA=2: replace + activate on next reset (w/ reset)
    #             CA=3: activate without replace (existing slot)
    #             CA=5: replace + activate immediately (NVMe 1.3+)
    "FWCommit": [
        dict(cdw10=0x00),
        dict(cdw10=0x01),
        dict(cdw10=0x09),
        dict(cdw10=0x02),
        dict(cdw10=0x03),
        dict(cdw10=0x05),
        dict(cdw10=0x0D),
    ],

    # FormatNVM — SES=0(비파괴)만 유지.
    # SES=1(user data erase)/SES=2(crypto erase)는 즉시 전체 미디어 소거 시작 → 제외.
    "FormatNVM": [
        dict(cdw10=0x0000),
    ],

    # Sanitize — SANACT=4(Exit Failure Mode)만 허용.
    # 1=Block Erase / 2=Overwrite / 3=Crypto Erase는 즉시 전체 소거 시작.
    # 4=Exit Failure: sanitize failure 상태 해제 (비파괴, 미진입 시 오류 반환)
    "Sanitize": [
        dict(cdw10=0x04, nsid_override=0),  # SANACT=100: Exit Failure Mode
        dict(cdw10=0x05, nsid_override=0),  # SANACT=101: Exit Media Verification State (NVMe 2.2)
    ],

    # TelemetryHostInitiated — GetLogPage LID=0x07
    "TelemetryHostInitiated": [
        dict(cdw10=(0x1FF << 16) | 0x07, nsid_override=0),
        dict(cdw10=(0x1FF << 16) | (1 << 8) | 0x07, nsid_override=0),
    ],

    # Flush — 파라미터 없음
    "Flush": [
        dict(),
    ],

    # DatasetManagement — CDW10[7:0]=NR (Number of Ranges, 0-based)
    #                      CDW11[2]=AD (Attribute Deallocate)
    #                      CDW11[0]=IDR, CDW11[1]=IDW (access hints)
    #                      data: 16B per range (Context Attrs + LBA Count + SLBA)
    "DatasetManagement": [
        # Range Entry 구조 (16B): [Context Attrs 4B][LBA Count 4B][SLBA 8B]
        # AD=1: TRIM (deallocate) — 가장 일반적인 용도
        dict(cdw10=0, cdw11=0x04, data=struct.pack('<IIQ', 0, 8, 0)),
        dict(cdw10=0, cdw11=0x04, data=struct.pack('<IIQ', 0, 256, 0)),
        dict(cdw10=0, cdw11=0x04, data=struct.pack('<IIQ', 0, 8, 500)),
        # IDR=1: Sequential Read access hint
        dict(cdw10=0, cdw11=0x01, data=struct.pack('<IIQ', 0, 8, 0)),
        # IDW=1: Sequential Write access hint
        dict(cdw10=0, cdw11=0x02, data=struct.pack('<IIQ', 0, 8, 0)),
        # NR=1 (2 ranges): AD=1
        dict(cdw10=1, cdw11=0x04,
             data=struct.pack('<IIQ', 0, 8, 0) + struct.pack('<IIQ', 0, 8, 100)),
        # NR=max (256 ranges): AD=1 — 범위 최대치
        dict(cdw10=0xFF, cdw11=0x04, data=struct.pack('<IIQ', 0, 1, 0) * 256),
    ],

    # NamespaceManagement — SEL=0 (Create only; SEL=1 Delete is excluded) (Admin 0x0D)
    #                         CDW10[3:0]=SEL, CDW11[31:24]=CSI
    "NamespaceManagement": [
        dict(cdw10=0x0, cdw11=(0x00 << 24), data=b'\x00' * 4096, nsid_override=0),  # SEL=0, CSI=NVM
    ],

    # Abort — CDW10[15:0]=SQID, CDW10[31:16]=CID (Admin 0x08)
    "Abort": [
        dict(cdw10=0, nsid_override=0),
        dict(cdw10=(0x0001 << 16) | 0x0001, nsid_override=0),
    ],

    # NamespaceAttachment — SEL=0 (Attach only; SEL=1 Detach is excluded) (Admin 0x15)
    "NamespaceAttachment": [
        dict(cdw10=0x0, nsid_override=0),
    ],

    # KeepAlive — no CDW parameters (Admin 0x18)
    "KeepAlive": [
        dict(nsid_override=0),
    ],

    # DirectiveSend — CDW10=NUMD, CDW11[7:0]=DOPER, CDW11[15:8]=DTYPE (Admin 0x19)
    "DirectiveSend": [
        dict(cdw10=0x7F, cdw11=(0x01 << 8) | 0x00, data=b'\x00' * 512, nsid_override=0),
    ],

    # DirectiveReceive — CDW10=NUMD, CDW11[7:0]=DOPER, CDW11[15:8]=DTYPE (Admin 0x1A)
    "DirectiveReceive": [
        dict(cdw10=0x7F, cdw11=(0x01 << 8) | 0x01, nsid_override=0),
    ],

    # VirtMgmt — CDW10[3:0]=ACT, CDW10[6:5]=RT (Admin 0x1C)
    "VirtMgmt": [
        dict(cdw10=0x01, nsid_override=0),  # ACT=1
        dict(cdw10=0x07, nsid_override=0),  # ACT=7
    ],

    # CapacityMgmt — CDW10[7:0]=OP, CDW10[31:16]=EGID (Admin 0x20)
    "CapacityMgmt": [
        dict(cdw10=0x00, nsid_override=0),  # OP=0: Query
    ],

    # Lockdown — PRHBT=0 only (Admin 0x24)
    "Lockdown": [
        dict(cdw10=0x0000, nsid_override=0),
    ],

    # MigrationSend — CDW10=NUMD, CDW11[1:0]=SEQIND (Admin 0x41)
    "MigrationSend": [
        dict(cdw10=0x7F, cdw11=0x00, data=b'\x00' * 512, nsid_override=0),
    ],

    # MigrationReceive — CDW10=NUMD (Admin 0x42)
    "MigrationReceive": [
        dict(cdw10=0x7F, cdw11=0x00, nsid_override=0),
    ],

    # ControllerDataQueue — CDW10[3:0]=OP (Admin 0x45)
    "ControllerDataQueue": [
        dict(cdw10=0x01, nsid_override=0),
    ],

    # Copy (IO 0x19) — CDW10/11=SDLBA, CDW12[7:4]=DF, CDW12[11:8]=NR
    #                   data: Source Range Entry list (32B per entry for Format 0h)
    "Copy": [
        # Format 0h, NR=0 (1 range), src SLBA=0, NLB=1 → dst SLBA=0
        dict(cdw10=0, cdw11=0, cdw12=0x00,
             data=struct.pack('<QHH', 0, 1, 0) + b'\x00' * 20),
    ],

    # ReservationRegister (IO 0x0D) — CDW10[2:0]=RREGA, CDW10[3]=IEKEY, CDW10[31:30]=CPTPL
    #                                   data: 16B (CRKEY 8B + NRKEY 8B)
    "ReservationRegister": [
        dict(cdw10=0x00, data=b'\x00' * 16),  # RREGA=0: Register
        dict(cdw10=0x01, data=b'\x00' * 16),  # RREGA=1: Unregister
    ],

    # ReservationReport (IO 0x0E) — CDW10=NUMD, CDW11[0]=EDS
    "ReservationReport": [
        dict(cdw10=0xFF, cdw11=0),
        dict(cdw10=0xFF, cdw11=1),  # EDS=1: Extended Data Structure
    ],

    # ReservationAcquire (IO 0x11) — CDW10[2:0]=RACQA, CDW10[15:8]=RTYPE
    #                                  data: 16B (CRKEY 8B + PRKEY 8B)
    "ReservationAcquire": [
        dict(cdw10=0x00, data=b'\x00' * 16),  # RACQA=0: Acquire
    ],

    # ReservationRelease (IO 0x15) — CDW10[2:0]=RRELA, CDW10[15:8]=RTYPE
    #                                  data: 8B (CRKEY)
    "ReservationRelease": [
        dict(cdw10=0x00, data=b'\x00' * 8),  # RRELA=0: Release
    ],

    # Cancel (IO 0x18) — CDW10[15:0]=SQID, CDW10[31:16]=CID, CDW11[3:0]=CA
    "Cancel": [
        dict(cdw10=0, cdw11=0),   # CA=0: Single command
        dict(cdw10=0, cdw11=2),   # CA=2: All in namespace
    ],

    # IOMgmtReceive (IO 0x12) — CDW10=NUMD, CDW11[7:0]=MO
    "IOMgmtReceive": [
        dict(cdw10=0xFF, cdw11=0x00),  # MO=0: RUH Status
    ],

    # IOMgmtSend (IO 0x1D) — CDW10=NUMD, CDW11[7:0]=MO
    "IOMgmtSend": [
        dict(cdw10=0x7F, cdw11=0x01, data=b'\x00' * 512),  # MO=1: RUH Update
    ],
}
