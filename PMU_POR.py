#!/usr/bin/env python3
import os
import time
import subprocess
import sys

# ================= 설정값 =================
# lspci 명령어로 확인한 대상 SSD의 BDF (Bus:Device.Function)
NVME_BDF = "0000:01:00.0" 

# PMU 전원 인가 후 SSD 펌웨어 부팅 대기 시간 (초)
# 펌웨어 초기화 시간에 맞춰 넉넉하게 설정하세요.
BOOT_DELAY = 5             
# ==========================================

def remove_nvme(bdf):
    print(f"[+] OS에서 NVMe 장치({bdf}) 논리적 제거 중...")
    remove_path = f"/sys/bus/pci/devices/{bdf}/remove"
    
    if os.path.exists(remove_path):
        try:
            with open(remove_path, 'w') as f:
                f.write("1")
            print("    -> 제거 완료")
        except IOError as e:
            print(f"    -> [오류] 장치 제거 실패: {e}")
    else:
        print("    -> 이미 제거되었거나 경로를 찾을 수 없습니다. (Link Down 상태일 수 있음)")

def pmu_power_cycle():
    print("[+] PMU 보드를 통한 전원 재인가 (Power Cycle) 수행 중...")
    
    # TODO: 사용 중인 PMU 장비에 맞는 통신 코드로 교체하세요.
    # [예시 1] 시리얼 통신 기반의 자체 제작 릴레이 보드 (PySerial 사용)
    # import serial
    # with serial.Serial('/dev/ttyUSB0', 115200) as ser:
    #     ser.write(b"POWER_OFF\n")
    #     time.sleep(1)
    #     ser.write(b"POWER_ON\n")
    
    # [예시 2] Quarch 등 네트워크 기반 PMU (REST API 또는 Telnet)
    # import requests
    # requests.post("http://192.168.1.100/api/power/off")
    # time.sleep(1)
    # requests.post("http://192.168.1.100/api/power/on")
    
    time.sleep(1) # PMU 스위칭 시간 대기
    print("    -> 물리적 Power Cycle 완료")

def rescan_pcie():
    print("[+] PCIe 버스 재스캔 중...")
    rescan_path = "/sys/bus/pci/rescan"
    try:
        with open(rescan_path, 'w') as f:
            f.write("1")
        print("    -> 재스캔 명령 전송 완료")
    except IOError as e:
        print(f"    -> [오류] 재스캔 실패: {e}")

def verify_recovery(bdf):
    print("[+] 장치 복구 확인 중...")
    if os.path.exists(f"/sys/bus/pci/devices/{bdf}"):
        print(f"    -> 성공! PCIe 장치({bdf})가 다시 인식되었습니다.")
        
        # NVMe 드라이버가 정상 로드되었는지 lspci로 추가 확인
        result = subprocess.run(['lspci', '-s', bdf], capture_output=True, text=True)
        print(f"    -> {result.stdout.strip()}")
        return True
    else:
        print(f"    -> [실패] 장치 인식 불가. 펌웨어가 여전히 hang 상태이거나 JTAG Breakpoint에 걸려있을 수 있습니다.")
        return False

def main():
    if os.geteuid() != 0:
        print("[!] /sys/bus/pci 제어를 위해 root 권한(sudo)으로 실행해주세요.")
        sys.exit(1)

    print("=== SSD Power Recovery Automation ===")
    
    # 1. 논리적 연결 해제
    remove_nvme(NVME_BDF)
    time.sleep(1) # OS 드라이버 Unbind 안정화 대기
    
    # 2. PMU 전원 제어
    pmu_power_cycle()
    
    # 3. 펌웨어 부팅 대기
    print(f"[+] 펌웨어 부팅 대기 ({BOOT_DELAY}초)...")
    time.sleep(BOOT_DELAY)
    
    # 4. PCIe 재스캔 및 드라이버 로드
    rescan_pcie()
    time.sleep(2) # OS가 NVMe 네임스페이스를 할당할 시간 대기
    
    # 5. 결과 검증
    success = verify_recovery(NVME_BDF)
    
    # Fuzzing 프레임워크 등에 Exit Code로 결과 전달
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
