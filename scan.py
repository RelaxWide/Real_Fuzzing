# pcsr_sample.tcl — Core 1/2 PCSR 누적 샘플링
# 사용법: openocd -f r8_pcsr.cfg -f pcsr_test.tcl
#
# 출력: /tmp/pcsr_dump.txt
# 포맷: <코어번호> <PC hex>
# 예:   1 0x00001620
#       2 0x00001628

# 디버그 전원 활성화 (Core 0=bit0, Core 1=bit8, Core 2=bit16)
set pwr [r8.axi read_memory 0x30313f30 32 1]
r8.axi write_memory 0x30313f30 32 [expr {[lindex $pwr 0] | 0x00010101}]

# PCSR 주소 (CoreBase + 0x084, APB-AP 경유)
set core1_pcsr 0x80032084
set core2_pcsr 0x80034084

set samples 500
set out [open "/tmp/pcsr_dump.txt" a]

for {set i 0} {$i < $samples} {incr i} {
    set pc1 [lindex [r8.abp read_memory $core1_pcsr 32 1] 0]
    set pc2 [lindex [r8.abp read_memory $core2_pcsr 32 1] 0]
    # Thumb 모드: bit0 제거
    set pc1 [expr {$pc1 & 0xFFFFFFFE}]
    set pc2 [expr {$pc2 & 0xFFFFFFFE}]
    puts $out "1 [format 0x%08x $pc1]"
    puts $out "2 [format 0x%08x $pc2]"
}

close $out
echo "샘플링 완료: $samples 개 → /tmp/pcsr_dump.txt"
shutdown
