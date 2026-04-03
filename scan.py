set pwr [r8.axi read_memory 0x30313f30 32 1]
r8.axi write_memory 0x30313f30 32 [expr {[lindex $pwr 0] | 0x00010101}]
set pc1 [r8.apb read_memory 0x80032084 32 1]
set pc2 [r8.apb read_memory 0x80034084 32 1]
echo "Core 1 PCSR: $pc1"
echo "Core 2 PCSR: $pc2"
shutdown
