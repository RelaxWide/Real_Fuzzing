# @language jython
# @category Bridge

import sys
import os

# [중요] 여기에 site-packages 경로 넣기 (r"..." 사용 추천)
# 예: r"C:\Users\...\site-packages"
SITE_PKG = r"C:\Users\User\AppData\Local\Programs\Python\Python39\Lib\site-packages"

if SITE_PKG not in sys.path:
    sys.path.append(SITE_PKG)

try:
    # ghidra_bridge 대신 jfx_bridge를 직접 사용
    import jfx_bridge.bridge as bridge
    import jfx_bridge.server as server
    
    print("Starting Bridge Server...")
    # 백그라운드에서 실행
    server.run_server(background=True)
    print("Bridge Server Running!")

except ImportError:
    print("[Error] jfx_bridge not found!")
    print("Check your site-packages path: " + SITE_PKG)
except Exception as e:
    print("[Error] " + str(e))
