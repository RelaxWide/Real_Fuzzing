import pylink
import time
import logging
from collections import Counter

# DLL 경로 설정
JLINK_DLL_PATH = r"C:\Program Files\SEGGER\JLink\JLink_x64.dll"

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)
logging.getLogger("pylink").setLevel(logging.WARNING)

def run_poc():
    try:
        lib = pylink.Library(dllpath=JLINK_DLL_PATH)
        jlink = pylink.JLink(lib=lib)
    except:
        jlink = pylink.JLink()

    try:
        logger.info(">>> Connecting... <<<")
        jlink.open()
        jlink.connect('Cortex-R8', speed='auto', verbose=False)
        
        # ---------------------------------------------------------
        # 1. 스마트 부팅 대기 (Smart Boot Wait)
        # ---------------------------------------------------------
        logger.info("[-] Waiting for Firmware Boot (Valid PC check)...")
        
        booted = False
        max_wait = 30 # 최대 30초 대기
        
        for i in range(max_wait * 2): # 0.5초 단위
            if not jlink.halted():
                jlink.halt()
                
            pc = jlink.register_read(15)
            
            # 유효한 PC 기준: 0이 아니고, 너무 낮은 주소(벡터 테이블)가 아님
            # 보통 펌웨어 메인 루프는 0x10000 이후에 있음 (덤프툴 로그: 0x17448)
            if pc > 0x1000:
                logger.info(f"[-] Boot Detected! PC=0x{pc:08X}")
                booted = True
                break
            
            # 아직 부팅 중이면 다시 실행
            jlink.restart()
            time.sleep(0.5)
            
        if not booted:
            logger.error("FATAL: Firmware did not boot in time.")
            return

        # ---------------------------------------------------------
        # 2. 핫스팟 샘플링 (부팅 완료 후)
        # ---------------------------------------------------------
        logger.info("[-] Sampling Hotspots (Collecting 50 samples)...")
        pc_samples = []
        for _ in range(50):
            jlink.halt()
            pc_samples.append(jlink.register_read(15))
            jlink.restart()
            time.sleep(0.02)
            
        counter = Counter(pc_samples)
        top_pc, count = counter.most_common(1)[0]
        logger.info(f"[-] Target Hotspot: 0x{top_pc:08X} (Freq: {count}/50)")

        # ---------------------------------------------------------
        # 3. BP 설치 & Hit 테스트
        # ---------------------------------------------------------
        target_bps = {top_pc, top_pc - 4, top_pc + 4} # 그물망
        logger.info(f"[-] Setting BPs at: {[hex(x) for x in target_bps]}")
        
        for bp in target_bps:
            try: jlink.breakpoint_set(bp)
            except: pass
            
        hit_total = 0
        jlink.step() # 캐시 플러시용 스텝
        
        for i in range(1, 21):
            jlink.restart()
            
            # Hit 대기
            start_t = time.time()
            while time.time() - start_t < 1.0:
                if jlink.halted(): break
                time.sleep(0.01)
                
            if jlink.halted():
                curr_pc = jlink.register_read(15)
                # BP 근처에서 멈췄는지 확인
                if any(abs(curr_pc - bp) <= 4 for bp in target_bps):
                    hit_total += 1
                    logger.info(f"[+] HIT #{hit_total} (PC=0x{curr_pc:08X})")
                    jlink.step()
                    if hit_total >= 5:
                        logger.info(">>> SUCCESS: PoC Complete! <<<")
                        break
                else:
                    jlink.restart() # 딴데서 멈추면 무시하고 계속
            else:
                jlink.halt()

        if hit_total == 0:
            logger.warning("[-] No hits. (Try increasing wait time or check BP limit)")

    except KeyboardInterrupt:
        logger.info("Stopped.")
    finally:
        try:
            jlink.breakpoint_clear_all()
            jlink.close()
        except: pass

if __name__ == "__main__":
    run_poc()
