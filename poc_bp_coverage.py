import pylink
import time
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def run_bp_poc():
    # 1. J-Link 연결 (기존 덤프툴 설정과 동일하게)
    jlink = pylink.JLink()
    jlink.open()
    logger.info("[*] Connecting to Cortex-R8...")
    jlink.connect('Cortex-R8', speed='auto', verbose=True)
    
    if not jlink.connected():
        logger.error("[!] Connection failed.")
        return

    try:
        # 2. 현재 상태 확인 및 Halt
        logger.info("[*] Halting CPU to check status...")
        jlink.halt()
        time.sleep(0.1)
        
        # PC(R15) 읽기
        pc = jlink.register_read(15)
        logger.info(f"[*] Current PC: 0x{pc:08X}")
        
        if pc == 0:
            logger.warning("[!] PC is 0. CPU might be in Reset or BootROM. Running for 1 sec...")
            jlink.restart() # 또는 jlink.reset()
            time.sleep(1.0) # 부팅 대기
            jlink.halt()
            pc = jlink.register_read(15)
            logger.info(f"[*] PC after wait: 0x{pc:08X}")

        # 3. PoC 목표: "현재 PC + 알파" 위치들에 BP 걸어보기
        # (실제 퍼징에선 함수 시작점들을 걸겠지만, 지금은 테스트용으로 현재 PC 주변 명령어들에 검)
        # 예: 현재 실행 흐름상 곧 지나갈 것이 확실한 주소들 (Instruction Step으로 찾음)
        
        target_bps = []
        
        # Step을 몇 번 해서 '미래의 주소'를 수집
        logger.info("[*] Stepping to find valid BP addresses...")
        for _ in range(5):
            jlink.step()
            curr_pc = jlink.register_read(15)
            target_bps.append(curr_pc)
            logger.info(f"    -> Found execution path: 0x{curr_pc:08X}")
            
        logger.info(f"[*] Collected {len(target_bps)} BP candidates: {[hex(x) for x in target_bps]}")

        # 4. Breakpoint 설치 테스트
        logger.info("[*] Setting Breakpoints...")
        for bp_addr in target_bps:
            jlink.breakpoint_set(bp_addr)
        
        # 5. 실행 및 Hit 확인 루프
        logger.info("[*] Running execution loop (Press Ctrl+C to stop)...")
        
        # 다시 처음 수집했던 위치 근처로 가기 위해 리셋하거나, 그냥 루프 돌림
        # 여기선 간단히 'Go' -> 'Hit' 확인 반복
        
        hit_count = 0
        start_time = time.time()
        
        while True:
            # CPU 실행
            jlink.restart() # 실제 런타임에선 jlink.restart()가 Go 역할을 함 (Resume)
            
            # BP에 걸릴 때까지 대기 (최대 1초)
            # 만약 타겟이 멈췄다면 BP Hit임
            timeout = 1.0
            t_start = time.time()
            while time.time() - t_start < timeout:
                if jlink.halted():
                    break
                time.sleep(0.001) # Busy wait 방지
            
            if jlink.halted():
                hit_pc = jlink.register_read(15)
                # PC가 우리가 건 BP 리스트 안에 있는지 확인
                # (ARM은 PC값이 +4/+8 차이날 수 있으니 근사치 체크 혹은 정확히 체크)
                # J-Link는 멈춘 주소를 정확히 줌
                
                if hit_pc in target_bps:
                    hit_count += 1
                    logger.info(f"[+] BP HIT! PC=0x{hit_pc:08X} (Total Hits: {hit_count})")
                    
                    # 다시 실행하기 위해 Step 한번 해주고 (BP 탈출)
                    jlink.step()
                else:
                    # BP가 아닌 다른 이유로 멈춤?
                    logger.info(f"[?] Halted at 0x{hit_pc:08X} (Not in BP list)")
                    jlink.step()
            else:
                logger.info("[-] Timeout (No BP hit). Target is running...")
                # 다시 Halt 걸고 상태 확인
                jlink.halt()

            # 10번 Hit면 성공 종료
            if hit_count >= 10:
                logger.info("[*] PoC SUCCESS: Captured 10 BP hits!")
                break
                
    except KeyboardInterrupt:
        logger.info("[!] Stopped by user.")
    except Exception as e:
        logger.error(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 정리: BP 모두 해제
        logger.info("[*] Cleaning up BPs...")
        for bp_addr in target_bps:
            try:
                jlink.breakpoint_clear(bp_addr)
            except:
                pass
        jlink.close()
        logger.info("[*] Disconnected.")

if __name__ == "__main__":
    run_bp_poc()
