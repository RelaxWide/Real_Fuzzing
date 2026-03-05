# NVMe Connection for SSD Fuzzing
# Sends fuzz data via NVMe CLI admin-passthru command

from __future__ import annotations

import configparser
import logging as log
import subprocess
import time

from GDBFuzz.connections.ConnectionBaseClass import ConnectionBaseClass


class NVMeConnection(ConnectionBaseClass):
    """
    NVMe CLI를 통해 SSD에 퍼징 데이터를 전송하는 Connection 클래스
    """

    def connect(self, SUTConnection_config: configparser.SectionProxy) -> None:
        """설정 파일에서 NVMe 장치 정보 읽기"""
        self.device = SUTConnection_config.get('device', '/dev/nvme0')
        self.opcode = SUTConnection_config.get('opcode', '0xC0')
        self.namespace = SUTConnection_config.get('namespace', '1')
        self.timeout_ms = SUTConnection_config.get('timeout', '5000')
        self.input_file = '/tmp/nvme_fuzz_input'

        log.info(f"NVMe Connection initialized: device={self.device}, opcode={self.opcode}")

    def wait_for_input_request(self) -> None:
        """SSD가 입력을 받을 준비가 될 때까지 대기 (NVMe는 항상 준비됨)"""
        # NVMe는 항상 커맨드를 받을 수 있으므로 짧은 딜레이만
        time.sleep(0.01)

    def send_input(self, fuzz_input: bytes) -> None:
        """NVMe CLI를 통해 퍼징 데이터 전송"""

        if len(fuzz_input) == 0:
            log.debug("Empty input, skipping")
            return

        # 입력 데이터를 파일에 저장
        with open(self.input_file, 'wb') as f:
            f.write(fuzz_input)

        # NVMe admin-passthru 명령 구성
        cmd = [
            'nvme', 'admin-passthru',
            self.device,
            '--opcode=' + self.opcode,
            '--input-file=' + self.input_file,
            '--data-len=' + str(len(fuzz_input)),
            '--timeout=' + self.timeout_ms,
            '-r'  # read response
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=10
            )
            log.debug(f"NVMe command sent: {len(fuzz_input)} bytes, opcode={self.opcode}")

            if result.returncode != 0:
                log.debug(f"NVMe command returned: {result.returncode}")

        except subprocess.TimeoutExpired:
            log.warning("NVMe command timeout")
        except Exception as e:
            log.warning(f"NVMe command error: {e}")

    def disconnect(self) -> None:
        """연결 해제 (NVMe는 특별한 해제 필요 없음)"""
        log.info("NVMe Connection disconnected")
