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
