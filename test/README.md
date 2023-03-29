# TEE Test

- [TEE Test](#TEE-test)
  - [Introduce](#introduce)
  - [Important Folders](#important-folders)
  - [Build](#build)
  - [Test Execution](#Test Execution)
  - [Reference](#Reference)

## Introduce

This is the test suit for the functional and compatible test of TEE.

TEE test suit is based on Open Harmony hcpptest framework, which can refer to the XTS subsystem.

## Important Folders

|  Folder   |  Introduce  |
|  ----  |  ----  |
| driver  | driver related code |
| ca  | REE related code，which is the testcase definition. |
| ta  | TEE related code |
| utils  | test AW and public code |

## Build

    # build with the system:
    hb build --gn-args build_xts=true

## Test Execution
Note: The absolute path for running the CA during the test must be the same as the absolute path for running the CA specified by AddCaller_CA_exec func in the test TA. In this example, the CA named tee_test_store in the TA is used as an example to describe the test command. You can specify another name in the actual test.

By default, the CA compiled by the system is named tee_client.bin, and the absolute path of the CA specified in the TA is /system/bin/tee_test_store. During the test, you need to rename the CA tee_test_store and place it in /system/bin. Run with the absolute path name. (You can also change the absolute path of the CA specified in the TA to the actual absolute path of the current system and recompile the TA.)

### TEE SDK compatibility test
1. Execute all test cases.
Enter the command line window of the tested system, Enter "/system/bin/tee_test_store"

2. Execute some test cases.
For details, see the commands provided by the hcpptest framework.


## Reference
    - xts_acts
