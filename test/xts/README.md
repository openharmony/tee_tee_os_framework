# TEE Test

## Introduce

This is the test suit for the functional and compatible test of TEE.

TEE test suit is based on Open Harmony hcpptest framework, which can refer to the XTS subsystem.

## Important Folders

|  Folder   |  Introduce  |
|  ----  |  ----  |
| driver  | driver related code |
| ca  | REE related test code，which is the testcase definition. |
| ta  | TEE related test code |
| utils  | test AW and public code |

## Build
### Build CA 

    # build with the system:
    hb build --gn-args build_xts=true

    # For rk3568：
    First, copy the tee directory from the ca directory to the test/xts/acts directory, then add the configuration tee directory to the test/xts/acts/test_packages.gni file, and execute the  following compile command
    cd test/xts/acts
    /build.sh product_name=rk3568 system_size=standard target_subsystem=tee
    The compiled CA in "out/rk3568/suites/acts/acts/testcases"。
### Build TA 


## Test Execution
Note: The absolute path for running the CA during the test must be the same as the absolute path for running the CA specified by AddCaller_CA func in the test TA. In this example, the CA named tee_test_client_api_vendor in the TA is used as an example to describe the test command. You can specify another name in the actual test.

Place the test TA (sec file) in the same level directory as the test CA, and both can be placed in the/vendor/bin/directory.

### TEE SDK compatibility test
1. Execute all test cases.
Enter the command line window of the tested system, Enter "/vendor/bin/tee_test_client_api_vendor"

2. Execute some test cases.
For details, see the commands provided by the hcpptest framework.  
Supports the use of wildcard characters "*", for example /vendor/bin/tee_test_client_api_vendor --gtest_filter=*TeeBasicTestFram.InvokeCommand*

3. Current exist tee xts test CA list:
/vendor/bin/tee_test_client_api_vendor
/system/bin/tee_test_client_api_system
/vendor/bin/tee_test_tcf_api
/vendor/bin/tee_test_time_api
/vendor/bin/tee_test_arithmetic_api
/vendor/bin/tee_test_trusted_storage_api
/vendor/bin/tee_test_crypto_api
/vendor/bin/tee_test_device_api

## Reference
    - xts_acts
