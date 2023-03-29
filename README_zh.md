<<<<<<< HEAD
# tee_tee_os_framework仓介绍<a name="ZH-CN_TOPIC_0000001148528849"></a>

-   [简介](#section11660541593)
-   [目录结构](#section161941989596)
-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

tee_tee_os_framework仓二级目录结构如下：

<a name="table2977131081412"></a>
<table><thead align="left"><tr id="row7977610131417"><th class="cellrowborder" valign="top" width="50%" id="mcps1.2.3.1.1"><p id="p18792459121314"><a name="p18792459121314"></a><a name="p18792459121314"></a>二级目录</p>
</th>
<th class="cellrowborder" valign="top" width="50%" id="mcps1.2.3.1.2"><p id="p77921459191317"><a name="p77921459191317"></a><a name="p77921459191317"></a>描述</p>
</th>

<tr id="row6978161091412"><td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.1 "><p id="p64006181102"><a name="p64006181102"></a><a name="p64006181102"></a>sample</p>
</td>
<td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.2 "><p id="p7456843192018"><a name="p7456843192018"></a><a name="p7456843192018"></a>实例代码，包括teeloader和teed两部分</p>
</td>
</tr>

<tr id="row6978201031415"><td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.1 "><p id="p1978910485104"><a name="p1978910485104"></a><a name="p1978910485104"></a>test</p>
</td>
<td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.2 "><p id="p1059035912204"><a name="p1059035912204"></a><a name="p1059035912204"></a>测试相关代码</p>
</td>
</tr>
</tbody>
</table>

sample目录下包括teeloader和teed两部分，仅作示例代码，实际未使用。
-  teeloader

    用于加载TEE侧安全镜像到RAM（Random Access Memory）。

-  teed

    作为适配在ATF（Arm Trusted Firmware）中的模块，提供可信执行环境（Trusted Execution Environment，TEE）与富执行环境（Rich Execution Environment，REE）切换的服务。

test目录下放置测试相关代码，用于测试TEE可信执行环境子系统基础能力。

## 目录结构<a name="section161941989596"></a>

```
base/tee/tee_os_framework
│ 
├── sample                              # 示例代码
│   │  
│   ├── teeloader                       # teeloader示例代码
│   │  
│   └── teed                            # teed示例代码
│ 
└── test                                # 测试相关代码
```

## 相关仓<a name="section1371113476307"></a>

**tee子系统**

**tee_os_framework**
=======
# tee_tee_os_framework仓介绍 #

tee_os_framework部件主要包含TEE的框架部分，负责TA整个生命周期的管理、CA与TA交互信息的处理以及驱动的管理。除此以外，还提供了加解密、安全存储等核心服务，下面是具体的模块介绍。

### 一、tee_os_framework部件模块划分 ###
<table>
<th>子模块名称</th>
<th>模块职责</th>
<tr>
<td> gtask </td><td>TA进程的生命周期管理，实现TA进程的创建销毁，CA跟TA交互的通信管理、会话管理、Agent交互管理，TA进程异常状态处理</td>
</tr><tr>
<td> teesmcmgr</td><td>smc命令消息分发管理，包括CA命令、系统的休眠唤醒命令分发，idle状态管理等</td>
</tr><tr>
<td> tarunner</td><td>TA/驱动/服务二进制elf文件加载解析重定位</td>
</tr><tr>
<td> drvmgr</td><td>驱动进程的生命周期管理，包括驱动进程的创建及销毁、驱动接口访问控制、驱动进程权限控制，驱动访问管理，驱动进程异常状态处理</td>
</tr><tr>
<td> permission service</td><td>SEC文件验签、权限控制等操作</td>
</tr><tr>
<td> ssa</td><td>安全存储操作</td>
</tr><tr>
<td> huk service</td><td>硬件根秘钥访问控制管理</td>
</tr><tr>
<td> teemiscdrv</td><td>基础驱动，获取bootloader传入的共享内存信息</td>
</tr><tr>
<td> cryptomgr</td><td>提供加解密驱动框架 </td>
</tr><tr>
<td> TEE基础API</td><td>提供TA开发的API接口支持，包括加解密、安全存储、安全时间及TA2TA GP接口等</td>
</tr><tr>
<td> TEE驱动API</td><td>提供驱动开发的API接口支持，包括中断、IO、dma操作等</td>
</tr><tr>
<td> sample</td><td>提供加载tee的示例代码teeloader和atf tee适配示例代码tee_atf</td>
</tr><tr>
<td> test</td><td>提供tee测试套件 </td>
</tr>

</table>

### 二、tee_os_framework部件代码目录结构 ###
```
base/tee/tee_os_framework
├── framework
│   ├── gtask
│   ├── teesmcmgr
│   ├── drvmgr
│   └── tarunner
├── lib
│   ├── drvlib                    # 给驱动和drvmgr提供的lib库
│   ├── syslib                    # 只给TEE内部服务使用的lib库
│   └── teelib                    # 给TA、服务提供的lib库
├── drivers
│   ├── tee_misc_drv
│   ├── include
│   └── crypto_mgr
├── service
│   ├── permission_service
│   ├── huk_service
│   └── ssa
├── config
│   ├── release_config            # release配置信息，特性宏等
│   └── debug_config              # debug配置信息，特性宏等
├── build
├── test
└── sample
```
>>>>>>> 9bafdc531cdcd40b97af6453c73e28a1b27424a7
