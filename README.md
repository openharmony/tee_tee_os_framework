# Contribution for tee_tee_os_framework #

tee_os_framework mainly contains the framework codes of tee, which is responsible for the management of the whole life cycle of TA, the processing of CA and TA interactive information and the management of drivers. In addition, it also provides core services such as encryption, decryption and secure storage. The specific module introduction is as followed.

### 1. The specific module introduction of tee_os_framework ###
<table>
<th>Name of module</th>
<th>Functions</th>
<tr>
<td> gtask </td><td>TA lifetime control, create and destroy TA process, commication manager, session manager and agent manager of CA2TA, process error information for TA</td>
</tr><tr>
<td> teesmcmgr</td><td>dispatch smc command, including CA commands, system suspend and resume command, idle state management</td>
</tr><tr>
<td> tarunner</td><td> load,analysis and relocate the elf file of TA/drivers/services</td>
</tr><tr>
<td> drvmgr</td><td>management lifetime of drivers, including the create and destroy of drivers, interface permission control, driver process rights management, drivers access control, process incorrect state of drivers</td>
</tr><tr>
<td> permission service</td><td>permission management of SEC file</td>
</tr><tr>
<td> ssa</td><td>secure storage functions</td>
</tr><tr>
<td> huk service</td><td> hardware root key access control</td>
</tr><tr>
<td> teemiscdrv</td><td>base driver, get shared information from bootloader</td>
</tr><tr>
<td> cryptomgr</td><td>the framework code of encrypt/decrypt drivers </td>
</tr><tr>
<td> TEE base API</td><td>base interfaces of TA development, including encrypt/decrypt, secure storage, secure timer and GP interface of TA2TA</td>
</tr><tr>
<td> TEE driver API</td><td>interfaces for driver develepment, including interrupt, IO and DMA</td>
</tr><tr>
<td> sample</td><td>sample code for TEE load(teeloader) and sample code for ATF-TEE adapt code(tee_atf)</td>
</tr><tr>
<td> test</td><td>tee test suit </td>
</tr>

</table>

### 二、tee_os_framework code directories ###
```
base/tee/tee_os_framework
├── framework
│   ├── gtask
│   ├── teesmcmgr
│   ├── drvmgr
│   └── tarunner
├── lib
│   ├── drvlib                    # libs for drvmgr and drivers
│   ├── syslib                    # libs for TEE internal services
│   └── teelib                    # libs for TA and services
├── drivers
│   ├── tee_misc_drv
│   ├── include
│   └── crypto_mgr
├── service
│   ├── permission_service
│   ├── huk_service
│   └── ssa
├── config
│   ├── release_config            # release config macros
│   └── debug_config              # debug config macros
├── build
├── test
└── sample
```
