import sys
import os
import pylink
import time
import traceback
import logging
import re
import argparse  # 추가됨 (인자 파싱용)

# =============================================================================
# 기존 코드 영역 (건드리지 않음)
# =============================================================================

logger = logging.getLogger(__name__)

def save_cpu_reg(para):
    # (기존 코드 생략 - 너무 길어서 핵심 로직만 유지한다고 가정하고 복붙하세요)
    # 실제 파일에서는 기존 jlink_dump.py의 모든 함수(save_cpu_reg, get_cpu_reg_info 등)가 여기 있어야 합니다.
    pass 

# ... (기존 jlink_dump.py의 모든 클래스/함수들이 여기 들어있다고 가정) ...
# ... (JLINKRW 클래스, dump_core_mem, dump_doorbell 등등 전부 그대로 유지) ...

# =============================================================================
# [추가됨] CoreSight 스캔 로직 (새로 추가한 부분)
# =============================================================================
def scan_coresight_rom_table(jlink_obj, rom_base=0x80020000):
    logger.info(">>> BRUTE FORCE SCAN MODE ACTIVATED <<<")
    valid_components = []
    
    # 검색 범위 설정: 0x80000000 ~ 0x80080000 (512KB 구간)
    # 대부분의 CoreSight 블록은 코어 디버그 베이스 근처에 몰려 있음
    start_addr = 0x80000000
    end_addr   = 0x80060000 # 범위 조정 가능
    step       = 0x1000     # 4KB 단위

    logger.info(f"Scanning range: 0x{start_addr:08X} - 0x{end_addr:08X}")

    current_addr = start_addr
    while current_addr < end_addr:
        try:
            # 1. CIDR (Component ID) 체크 - 가장 빠르고 안전함
            # Offset 0xFF0 읽기
            cidr = jlink_obj.memory_read32(current_addr + 0xFF0, 4)
            
            # 유효한 CoreSight Preamble인지 확인 (0xB105F00D 등)
            # 보통 cidr[3]은 0xB1, cidr[2]는 0x05 ... 형태임
            # 여기서는 단순히 "모두 0이 아닌지"만 체크
            if cidr[0] == 0 and cidr[1] == 0 and cidr[2] == 0 and cidr[3] == 0:
                current_addr += step
                continue

            # 2. PIDR (Part Number) 읽기
            pidr = jlink_obj.memory_read32(current_addr + 0xFE0, 4)
            part_num = (pidr[0] & 0xFF) | ((pidr[1] & 0x0F) << 8)
            
            # 3. 이름 식별
            comp_name = "Unknown"
            if part_num == 0x961: comp_name = "TMC-ETB (Trace Buffer)"    # ★★★
            elif part_num == 0x9E8: comp_name = "TMC-ETR"                 # ★★★
            elif part_num == 0x95D: comp_name = "ETMv4 (Trace Source)"    # ★★★
            elif part_num == 0x925: comp_name = "ETMv3"
            elif part_num == 0x906: comp_name = "CTI"
            elif part_num == 0x100: comp_name = "Cortex-R"
            elif part_num == 0x4C7: comp_name = "Debug"
            
            logger.info(f"[!] HIT at 0x{current_addr:08X} | Part: 0x{part_num:03X} | Name: {comp_name}")
            
            valid_components.append({
                "base": current_addr, "part": part_num, "name": comp_name
            })
            
        except Exception:
            # 읽기 실패 시 무시하고 다음 블록으로
            pass
            
        current_addr += step

    return valid_components


# =============================================================================
# [수정됨] Main 실행부 (스캔 모드 분기 추가)
# =============================================================================

# 기존 jlink_dump.py에 있던 jlinkattachcore, getsnapshotoffset 등 함수들은 그대로 유지되어야 함

def main_scan_mode(jlink_sn):
    """ 스캔 모드 전용 실행 함수 """
    global jlink
    try:
        jlink = pylink.JLink()
        logger.info("Connecting to target (Scan Mode)...")
        
        # 기존 툴의 연결 함수 재사용 (Core 0, Reconnect True)
        # jlinkattachcore가 파일 상단에 정의되어 있어야 함
        if not jlinkattachcore(core=0, sn=jlink_sn, reopen=True, reconnect=True):
            logger.error("Failed to connect!")
            return 1
            
        # 스캔 수행
        comps = scan_coresight_rom_table(jlink, 0x80020000)
        
        print("\n" + "="*60)
        print(" SCAN RESULTS & J-LINK COMMANDS")
        print("="*60)
        
        etb_list = [c for c in comps if c['part'] in [0x961, 0x9E8]]
        etm_list = [c for c in comps if c['part'] in [0x95D, 0x925]]
        
        if not comps:
            print("[!] No components found.")
        else:
            for c in etb_list:
                print(f"CORESIGHT_SetETBBaseAddr = 0x{c['base']:08X} ForceUnlock = 1")
            for c in etm_list:
                print(f"CORESIGHT_SetETMBaseAddr = 0x{c['base']:08X} ForceUnlock = 1")
                
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        return 1
    finally:
        if jlink and jlink.connected(): jlink.close()
    return 0

# 기존 main 함수 (이름 변경 없음, 로직 유지)
def main(layoutcfginput, jlinksn, dumpfilepath):
    # ... (기존 jlink_dump.py의 main 함수 내용 그대로) ...
    pass

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
    
    # [핵심] 인자가 'scan'으로 시작하면 스캔 모드로 분기, 아니면 기존 덤프 모드 실행
    if len(sys.argv) > 1 and sys.argv[1] == 'scan':
        # 사용법: python jlink_dump.py scan [SN]
        sn = sys.argv[2] if len(sys.argv) > 2 else None
        sys.exit(main_scan_mode(sn))
    else:
        # 기존 덤프 모드 실행 (인자 처리 로직은 기존 코드에 맞춰야 함)
        # 예시: 원래 코드가 sys.argv를 직접 파싱했다면 그 로직 유지
        # 여기서는 기존 main 호출 예시만 남김
        pass 
        # (원래 파일의 if __name__ == "__main__": 아래 내용을 여기에 넣으세요)

def main(layoutcfginput, jlinksn, dumpfilepath):
    # [수정됨] SCAN 모드 강제 실행
    if os.environ.get('SCAN_MODE') == '1':
        logging.basicConfig(level=logging.INFO)
        logger.info(">>> SCAN MODE ACTIVATED <<<")
        
        try:
            # 1. J-Link 연결 (직접 수행)
            global jlink
            jlink = pylink.JLink()
            
            # (1) Open
            if jlinksn is not None:
                jlink.open(serial_no=jlinksn)
            else:
                jlink.open()
                
            # (2) Connect (Core 0 기준)
            # 기존 jlinkattachcore 함수 내용을 보면 'Cortex-R8', 'auto', verbose=True로 연결함
            logger.info("Connecting to Cortex-R8...")
            jlink.connect(chip_name='Cortex-R8', speed='auto', verbose=True)
            
            if not jlink.connected():
                logger.error("Failed to connect to target.")
                return 1
                
            logger.info("Connected successfully.")

            # 2. 스캔 수행
            # scan_coresight_rom_table 함수는 파일 어딘가에 정의되어 있어야 함
            # 만약 정의되지 않았다는 에러가 나면, 이 함수 정의를 파일 맨 위(import 직후)로 옮기세요.
            comps = scan_coresight_rom_table(jlink, 0x80020000)
            
            # 3. 결과 출력
            print("\n" + "="*60)
            print(" SCAN RESULT")
            print("="*60)
            
            etb = [c for c in comps if c['part'] in [0x961, 0x9E8]]
            etm = [c for c in comps if c['part'] in [0x95D, 0x925]]
            
            if not comps: print("No components found.")
            else:
                for c in comps: 
                    print(f"[{c['id']}] {c['name']} (0x{c['base']:X})")
            
            if etb: print(f"\n[Command] CORESIGHT_SetETBBaseAddr = 0x{etb[0]['base']:X} ForceUnlock = 1")
            if etm: print(f"[Command] CORESIGHT_SetETMBaseAddr = 0x{etm[0]['base']:X} ForceUnlock = 1")
            
            # 4. 강제 종료
            return 0
            
        except Exception as e:
            logger.error(f"Scan Error: {e}")
            import traceback
            traceback.print_exc()
            return 1
    
    # ... (기존 main 로직 계속) ...

    # ---------------------------------------------------------
    # 기존 코드 (원래 덤프 로직)
    # ---------------------------------------------------------
