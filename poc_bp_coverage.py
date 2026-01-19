import pylink
import time
import logging
import sys
from collections import Counter

# =============================================================================
# [설정] J-Link DLL 경로 (본인 환경에 맞게 수정 필수)
# =============================================================================
JLINK_DLL_PATH = r"C:\Program Files\SEGGER\JLink\JLink_x64.dll"
# JLINK_DLL_PATH = r"C:\Program Files (x86)\SEGGER\JLink\JLinkARM.dll"

# =============================================================================
# [로깅 설정] 핵심 정보만 출력하도록 설정
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Pylink 내부 로그는 시끄러우므로 끔
logging.getLogger("pylink").setLevel(logging.WARNING)

def run_poc():
    # 1. J-Link 라이브러리 로드 & 연결
    try:
        lib = pylink.Library(dllpath=JLINK_DLL_PATH)
        jlink = pylink.JLink(lib=lib)
    except Exception as e:
        logger.error(f"DLL Load Failed: {e}")
        logger.info("Trying default library load...")
        try:
            jlink = pylink.JLink()
        except:
            logger.error("Failed to load J-Link DLL. Check path.")
            return

    try:
        logger.info(">>> J-Link PoC Started <<<")
        jlink.open()
        
        # verbose=False로 설정하여 불필요한 J-Link 로그 제거
        jlink.connect('Cortex-R8', speed='auto', verbose=False)
        
        if not jlink.connected():
            logger.error("Connection failed.")
            return
            
        logger.info(f"Connected to {jlink.core_name()} (SN: {jlink.serial_number})")

        # 2. 핫스팟 찾기 (PC 샘플링)
        logger.info("[-] Sampling PC to find Hotspot (Collecting 20 samples)...")
        
        pc_samples = []
        for i in range(20):
            jlink.halt()
            pc = jlink.register_read(15)
            pc_samples.append(pc)
            jlink.restart()
            time.sleep(0.05)
            
        # 가장 많이 관측된 주소 분석
        counter = Counter(pc_samples)
        most_common_pc, count = counter.most_common(1)[0]
        
        if most_common_pc == 0:
            logger.error("FATAL: PC read as 0. CPU might be in Reset.")
            return
            
        logger.info(f"[-] Hotspot Found: 0x{most_common_pc:08X} (Frequency: {count}/20)")
        logger.info(f"    Samples: {[hex(x) for x in pc_samples[:5]]} ...")

        # 3. BP 설치
        logger.info(f"[-] Setting Breakpoint at 0x{most_common_pc:08X}")
        jlink.breakpoint_set(most_common_pc)
        
        # 4. Hit 테스트 (루프)
        logger.info("[-] Running execution loop for Hit test...")
        
        hit_total = 0
        max_retries = 20  # 최대 시도 횟수
        
        for i in range(1, max_retries + 1):
            jlink.restart()
            
            # 0.5초 대기 (Hit 감지)
            start_t = time.time()
            halted = False
            while time.time() - start_t < 0.5:
                if jlink.halted():
                    halted = True
                    break
                time.sleep(0.01)
            
            if halted:
                curr_pc = jlink.register_read(15)
                # PC가 BP 근처인지 확인 (±4 바이트 허용)
                if abs(curr_pc - most_common_pc) <= 4:
                    hit_total += 1
                    logger.info(f"[+] HIT #{hit_total} Success! (PC=0x{curr_pc:08X})")
                    
                    # BP 탈출: Step 1회
                    jlink.step()
                    
                    if hit_total >= 5:
                        logger.info(">>> PoC COMPLETE: Captured 5 Hits successfully. <<<")
                        break
                else:
                    logger.warning(f"[?] Stopped at unexpected PC: 0x{curr_pc:08X}")
                    jlink.restart()
            else:
                # 타임아웃 로그는 5번에 1번만 출력 (도배 방지)
                if i % 5 == 0:
                    logger.info(f"    (Still running... Attempt {i}/{max_retries})")
                
                # 강제로 멈춰서 상태 재설정
                jlink.halt()
        
        if hit_total == 0:
            logger.warning("[-] No hits captured. CPU might be stuck in a different loop.")

    except KeyboardInterrupt:
        logger.info("[!] Stopped by user.")
    except Exception as e:
        logger.error(f"[!] Error: {e}")
    finally:
        try:
            logger.info("[-] Cleaning up...")
            jlink.breakpoint_clear_all()
            jlink.close()
        except:
            pass
        logger.info(">>> Disconnected <<<")

if __name__ == "__main__":
    run_poc()
