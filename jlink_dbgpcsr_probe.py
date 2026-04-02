import pylink
import time

# 앞선 J-Link 로그에서 확인된 Cortex-R8의 Debug Base 주소
DEBUG_BASE = 0x80030000

# ARMv7-R Debug 레지스터 오프셋
DBGDIDR       = DEBUG_BASE + 0x000  # Debug ID Register
DBGPCSR       = DEBUG_BASE + 0x084  # PC Sampling Register
DBGDSCR       = DEBUG_BASE + 0x088  # Debug Status and Control Register
DBGOSLAR      = DEBUG_BASE + 0x300  # OS Lock Access Register
DBGOSLSR      = DEBUG_BASE + 0x304  # OS Lock Status Register
DBGAUTHSTATUS = DEBUG_BASE + 0xFB8  # Authentication Status

jlink = pylink.JLink()
jlink.open()
jlink.set_tif(pylink.enums.JLinkInterfaces.SWD)

# 멀티 AP 환경이므로 첫 번째 Cortex-R8이 물린 AP[0] 또는 AP[1] 선택 
# (로그의 구조에 따라 CORESIGHT_SetIndexAPBAPToUse = 1 로 바꿔야 할 수도 있음)
jlink.exec_command("CORESIGHT_SetIndexAPBAPToUse = 0")
jlink.connect("Cortex-R8", speed=4000)

try:
    # 1. Debug Block ID 확인
    didr = jlink.memory_read32(DBGDIDR, 1)[0]
    print(f"[+] Debug ID (DBGDIDR): 0x{didr:08X} (제대로 된 값이 나와야 함)")

    # 2. 권한 확인 (NIDEN 비침투적 디버그 권한)
    auth = jlink.memory_read32(DBGAUTHSTATUS, 1)[0]
    print(f"[+] Auth Status (DBGAUTHSTATUS): 0x{auth:08X}")

    # 3. OS Lock 상태 확인 및 해제
    oslsr = jlink.memory_read32(DBGOSLSR, 1)[0]
    if oslsr & 1:
        print("[-] OS Lock이 걸려 있습니다. 해제를 시도합니다...")
        jlink.memory_write32(DBGOSLAR, [0xC5ACCE55])
        time.sleep(0.01)
        if jlink.memory_read32(DBGOSLSR, 1)[0] & 1:
            print("[!] OS Lock 해제 실패")
        else:
            print("[+] OS Lock 해제 성공!")
    else:
        print("[+] OS Lock이 걸려있지 않습니다.")

    # 4. CPU 상태 확인
    dscr = jlink.memory_read32(DBGDSCR, 1)[0]
    is_halted = (dscr & (1 << 0)) != 0
    print(f"[+] CPU Halted: {is_halted}")
    
    if is_halted:
        print("[-] CPU가 정지 상태입니다. PC 샘플링 테스트를 위해 CPU를 실행합니다.")
        jlink.go()
        time.sleep(0.1)

    # 5. DBGPCSR 실시간 샘플링 테스트
    print("\n[+] DBGPCSR 실시간 PC 샘플링 테스트 시작...")
    samples = set()
    for i in range(20):
        # 코어를 멈추지 않고 메모리 매핑된 레지스터에서 직접 읽음
        pc = jlink.memory_read32(DBGPCSR, 1)[0]
        samples.add(pc)
        print(f"    Sample {i+1:02d}: 0x{pc:08X}")
        time.sleep(0.01)

    unique_pcs = len(samples)
    print(f"\n[결과] 고유한 PC 값 {unique_pcs}개 수집됨.")
    if unique_pcs > 1 and 0x00000000 not in samples and 0xFFFFFFFF not in samples:
        print("🎉 DBGPCSR 샘플링이 정상적으로 지원됩니다! 무중단 멀티코어 퍼징이 가능합니다.")
    else:
        print("❌ PC 값이 변하지 않거나 비정상입니다. 하드웨어적으로 NIDEN이 차단되었을 확률이 높습니다.")

except Exception as e:
    print(f"[!] 에러 발생: {e}")

finally:
    jlink.close()
