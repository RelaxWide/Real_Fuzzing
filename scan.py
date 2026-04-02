import pylink

  jl = pylink.JLink()                                                                                                                                                                      
  jl.open()
  jl.set_tif(pylink.enums.JLinkInterfaces.JTAG)                                                                                                                                            
  jl.connect("Cortex-R8", speed=4000)                       

  # Core 1 디버그 활성화 (JLinkScript의 _WriteViaAP 동등)                                                                                                                                  
  jl.exec_command("CORESIGHT_SetIndexAXIAPToUse = 1")
  val = jl.memory_read32(0x30313f30, 1)[0]                                                                                                                                                 
  jl.memory_write32(0x30313f30, [val | 0x00000100])  # Core 1 bit                                                                                                                          
  jl.exec_command("CORESIGHT_SetIndexAPBAPToUse = 0")                                                                                                                                      
                                                                                                                                                                                           
  # Core 0 PC                                                                                                                                                                              
  jl.exec_command("CORESIGHT_CoreBaseAddr = 0x80030000")                                                                                                                                   
  jl.halt()                                                                                                                                                                                
  pc0 = jl.register_read(15)
  jl.go()                                                                                                                                                                                  
  print(f"Core 0 PC: {pc0:#010x}")                          
                                                                                                                                                                                           
  # Core 1 PC
  jl.exec_command("CORESIGHT_CoreBaseAddr = 0x80032000")                                                                                                                                   
  jl.halt()                                                 
  pc1 = jl.register_read(15)
  jl.go()
  print(f"Core 1 PC: {pc1:#010x}")
                                                                                                                                                                                           
  # Core 2 PC
  jl.exec_command("CORESIGHT_CoreBaseAddr = 0x80034000")                                                                                                                                   
  jl.halt()                                                 
  pc2 = jl.register_read(15)
  jl.go()                                                                                                                                                                                  
  print(f"Core 2 PC: {pc2:#010x}")
                                                                                                                                                                                           
  # Core 0으로 복귀                                         
  jl.exec_command("CORESIGHT_CoreBaseAddr = 0x80030000")
  jl.close() 
