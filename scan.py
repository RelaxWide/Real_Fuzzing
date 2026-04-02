import pylink

  jl = pylink.JLink()                                                                                                                                                                      
  jl.open()
  jl.set_tif(pylink.enums.JLinkInterfaces.SWD)                                                                                                                                            
  jl.connect("Cortex-R8", speed=4000)                       

  # Core 0
  jl.halt()                                                                                                                                                                                
  pc0 = jl.register_read(15)                                
  jl.go()
  print(f"Core 0 PC: {pc0:#010x}")

  # Core 1 (전원 활성화 없이 CoreBaseAddr만 전환)                                                                                                                                          
  jl.exec_command("CORESIGHT_CoreBaseAddr = 0x80032000")
  jl.halt()                                                                                                                                                                                
  pc1 = jl.register_read(15)                                
  jl.go()                                                                                                                                                                                  
  print(f"Core 1 PC: {pc1:#010x}")                          
                                                                                                                                                                                           
  jl.exec_command("CORESIGHT_CoreBaseAddr = 0x80030000")
  jl.close()
                                                                                                                                                                                           
  # Core 0으로 복귀                                         
  jl.exec_command("CORESIGHT_CoreBaseAddr = 0x80030000")
  jl.close() 
