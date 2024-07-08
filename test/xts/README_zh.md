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
| ca  | REE侧相关测试代码，即测试用例定义部分 |
| ta  | TEE侧相关测试代码 |
| utils  | 测试公共代码 |

## 如何编译
### CA编译
    # 跟随系统编译:
    hb build --gn-args build_xts=true

    # 对于rk3568系统：
    先将ca目录下的tee目录拷贝到test/xts/acts目录下，然后在test/xts/acts/test_packages.gni文件中添加配置tee目录，再执行下面编译命令
    cd test/xts/acts
    /build.sh product_name=rk3568 system_size=standard target_subsystem=tee
    编译出的CA在out/rk3568/suites/acts/acts/testcases目录下。

### TA编译
    将测试TA源码放到SDK目录中，参考demo TA的编译，源码和配置文件使用待编译的TA即可。

## 测试执行
注意，测试时CA运行的绝对路径要与测试TA中AddCaller_CA_exec指定的CA运行绝对路径保持一致，本例以TA中指定的CA名称为tee_test_client_api_vendor为例来介绍测试命令。
测试TA（sec文件）放到与测试CA同级目录下，可以均放在/vendor/bin/目录下。

### TEE sdk兼容性测试

1. 执行全部用例 
   进入被测试系统命令行窗口，输入："/vendor/bin/tee_test_client_api_vendor"

2. 执行部分用例
   参考hcpptest框架提供的命令。支持使用通配符*，例如 /vendor/bin/tee_test_client_api_vendor --gtest_filter=*TeeBasicTestFram.InvokeCommand*

3. 当前已有的tee xts 测试CA 列表:
/vendor/bin/tee_test_client_api_vendor
/system/bin/tee_test_client_api_system
/vendor/bin/tee_test_tcf_api
/vendor/bin/tee_test_time_api
/vendor/bin/tee_test_arithmetic_api
/vendor/bin/tee_test_trusted_storage_api
/vendor/bin/tee_test_crypto_api
/vendor/bin/tee_test_device_api
## 参考仓
    - xts_acts
