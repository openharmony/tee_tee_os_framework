# TEE Test介绍

- [TEE Test介绍](#TEE-test介绍)
  - [简介](#简介)
  - [重要目录说明](#重要目录说明)
  - [如何编译](#如何编译)
  - [测试执行](#测试执行)
  - [参考仓](#参考仓)

## 简介

此目录下为TEE的测试套件代码，用于功能测试和兼容性测试。
TEE 测试套件REE侧是基于Open Harmony的hcpptest编写。测试框架可参考XTS子系统简介。

## 重要目录说明

|  目录   |  说明  |
|  ----  |  ----  |
| driver  | 驱动相关代码 |
| ca  | REE相关代码，即测试用例定义部分 |
| ta  | TEE相关代码 |
| utils  | 测试公共代码 |

## 如何编译

    # 跟随系统编译:
    hb build --gn-args build_xts=true

## 测试执行
注意，测试时CA运行的绝对路径要与测试TA中AddCaller_CA_exec指定的CA运行绝对路径保持一致，本例以TA中指定的CA名称为tee_test_store为例来介绍测试命令。实际测试时可以指定为其他名称。

当前系统默认编出的CA名为tee_client.bin，TA中指定的CA绝对路径为/system/bin/tee_test_store，测试时需要将CA重命名为tee_test_store并放在/system/bin下，再以绝对路径名称运行（也可以修改TA中指定的CA绝对路径为当前系统实际运行的绝对路径，重新编译TA）。

### TEE sdk兼容性测试

1. 执行全部用例 
   进入被测试系统命令行窗口，输入："/system/bin/tee_test_store"

2. 执行部分用例
   参考hcpptest框架提供的命令。

## 参考仓
    - xts_acts
