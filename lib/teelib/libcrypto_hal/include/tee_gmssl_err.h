/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef TEE_GMSSL_ERR_H
#define TEE_GMSSL_ERR_H

/*
 * define gmssl lib reasons err code:
 * Delete the prefix TEE_ERR_GMSSL_ or TEE_ERR_SM2_ or TEE_ERR_SM4_, which is the error
 * code name in the open-source library.
 */
/* for gmssl common err */
#define TEE_ERR_SM2_ERR_R_MALLOC_FAILURE                            0x80020041
#define TEE_ERR_SM2_ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED               0x80020042
#define TEE_ERR_SM2_ERR_R_PASSED_NULL_PARAMETER                     0x80020043
#define TEE_ERR_SM2_ERR_R_INTERNAL_ERROR                            0x80020044
#define TEE_ERR_SM2_ERR_R_DISABLED                                  0x80020045
#define TEE_ERR_SM2_ERR_R_INIT_FAIL                                 0x80020046
#define TEE_ERR_SM2_ERR_R_PASSED_INVALID_ARGUMENT                   0x80020007

/* for sm2 ec lib err */
#define TEE_ERR_SM2_EC_R_ASN1_ERROR                                 0x80020064
#define TEE_ERR_SM2_EC_R_BAD_SIGNATURE                              0x80020065
#define TEE_ERR_SM2_EC_R_BIGNUM_OUT_OF_RANGE                        0x80020066
#define TEE_ERR_SM2_EC_R_BUFFER_TOO_SMALL                           0x80020067
#define TEE_ERR_SM2_EC_R_CMAC_FINAL_FAILURE                         0x80020068
#define TEE_ERR_SM2_EC_R_CMAC_INIT_FAILURE                          0x80020069
#define TEE_ERR_SM2_EC_R_CMAC_UPDATE_FAILURE                        0x8002006a
#define TEE_ERR_SM2_EC_R_COORDINATES_OUT_OF_RANGE                   0x8002006b
#define TEE_ERR_SM2_EC_R_CURVE_DOES_NOT_SUPPORT_ECDH                0x8002006c
#define TEE_ERR_SM2_EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING             0x8002006d
#define TEE_ERR_SM2_EC_R_D2I_ECPKPARAMETERS_FAILURE                 0x8002006e
#define TEE_ERR_SM2_EC_R_DECODE_ERROR                               0x8002006f
#define TEE_ERR_SM2_EC_R_DECRYPT_FAILED                             0x80020070
#define TEE_ERR_SM2_EC_R_DISCRIMINANT_IS_ZERO                       0x80020071
#define TEE_ERR_SM2_EC_R_ECDH_FAILED                                0x80020072
#define TEE_ERR_SM2_EC_R_ECDH_FAILURE                               0x80020073
#define TEE_ERR_SM2_EC_R_ECIES_DECRYPT_FAILED                       0x80020074
#define TEE_ERR_SM2_EC_R_ECIES_DECRYPT_INIT_FAILURE                 0x80020075
#define TEE_ERR_SM2_EC_R_ECIES_ENCRYPT_FAILED                       0x80020076
#define TEE_ERR_SM2_EC_R_ECIES_VERIFY_MAC_FAILURE                   0x80020077
#define TEE_ERR_SM2_EC_R_EC_GROUP_NEW_BY_NAME_FAILURE               0x80020078
#define TEE_ERR_SM2_EC_R_ENCODE_ERROR                               0x800200c6
#define TEE_ERR_SM2_EC_R_ENCRYPT_FAILED                             0x80020079
#define TEE_ERR_SM2_EC_R_ENCRYPT_FAILURE                            0x8002007a
#define TEE_ERR_SM2_EC_R_ERROR                                      0x8002007b
#define TEE_ERR_SM2_EC_R_FIELD_TOO_LARGE                            0x8002007c
#define TEE_ERR_SM2_EC_R_GEN_MAC_FAILED                             0x8002007d
#define TEE_ERR_SM2_EC_R_GET_PUBLIC_KEY_DATA_FAILURE                0x8002007e
#define TEE_ERR_SM2_EC_R_GET_TYPE1CURVE_ZETA_FAILURE                0x8002007f
#define TEE_ERR_SM2_EC_R_GF2M_NOT_SUPPORTED                         0x80020080
#define TEE_ERR_SM2_EC_R_GROUP2PKPARAMETERS_FAILURE                 0x80020081
#define TEE_ERR_SM2_EC_R_GROUP_MISMATCH                             0x800200c7
#define TEE_ERR_SM2_EC_R_HMAC_FAILURE                               0x80020082
#define TEE_ERR_SM2_EC_R_I2D_ECPKPARAMETERS_FAILURE                 0x80020083
#define TEE_ERR_SM2_EC_R_INCOMPATIBLE_OBJECTS                       0x80020084
#define TEE_ERR_SM2_EC_R_INVALID_ARGUMENT                           0x80020085
#define TEE_ERR_SM2_EC_R_INVALID_COMPRESSED_POINT                   0x80020086
#define TEE_ERR_SM2_EC_R_INVALID_COMPRESSION_BIT                    0x80020087
#define TEE_ERR_SM2_EC_R_INVALID_CURVE                              0x80020088
#define TEE_ERR_SM2_EC_R_INVALID_DIGEST                             0x80020089
#define TEE_ERR_SM2_EC_R_INVALID_DIGEST_ALGOR                       0x8002008a
#define TEE_ERR_SM2_EC_R_INVALID_DIGEST_TYPE                        0x8002008b
#define TEE_ERR_SM2_EC_R_INVALID_ECIES_CIPHERTEXT                   0x8002008c
#define TEE_ERR_SM2_EC_R_INVALID_ECIES_PARAMETERS                   0x8002008d
#define TEE_ERR_SM2_EC_R_INVALID_ECIES_PARAMS                       0x8002008e
#define TEE_ERR_SM2_EC_R_INVALID_EC_ENCRYPT_PARAM                   0x8002008f
#define TEE_ERR_SM2_EC_R_INVALID_EC_SCHEME                          0x80020090
#define TEE_ERR_SM2_EC_R_INVALID_ENCODING                           0x80020091
#define TEE_ERR_SM2_EC_R_INVALID_ENC_PARAM                          0x80020092
#define TEE_ERR_SM2_EC_R_INVALID_ENC_TYPE                           0x80020093
#define TEE_ERR_SM2_EC_R_INVALID_FIELD                              0x80020094
#define TEE_ERR_SM2_EC_R_INVALID_FORM                               0x80020095
#define TEE_ERR_SM2_EC_R_INVALID_GROUP_ORDER                        0x80020096
#define TEE_ERR_SM2_EC_R_INVALID_ID_LENGTH                          0x80020097
#define TEE_ERR_SM2_EC_R_INVALID_INPUT_LENGTH                       0x80020098
#define TEE_ERR_SM2_EC_R_INVALID_KDF_MD                             0x80020099
#define TEE_ERR_SM2_EC_R_INVALID_KEY                                0x8002009a
#define TEE_ERR_SM2_EC_R_INVALID_MD                                 0x8002009b
#define TEE_ERR_SM2_EC_R_INVALID_OUTPUT_LENGTH                      0x8002009c
#define TEE_ERR_SM2_EC_R_INVALID_PEER_KEY                           0x8002009d
#define TEE_ERR_SM2_EC_R_INVALID_PENTANOMIAL_BASIS                  0x8002009e
#define TEE_ERR_SM2_EC_R_INVALID_PRIVATE_KEY                        0x8002009f
#define TEE_ERR_SM2_EC_R_INVALID_SIGNER_ID                          0x800200a0
#define TEE_ERR_SM2_EC_R_INVALID_SM2_ID                             0x800200a1
#define TEE_ERR_SM2_EC_R_INVALID_SM2_KAP_CHECKSUM_LENGTH            0x800200a2
#define TEE_ERR_SM2_EC_R_INVALID_SM2_KAP_CHECKSUM_VALUE             0x800200a3
#define TEE_ERR_SM2_EC_R_INVALID_TRINOMIAL_BASIS                    0x800200a4
#define TEE_ERR_SM2_EC_R_INVALID_TYPE1CURVE                         0x800200a5
#define TEE_ERR_SM2_EC_R_INVALID_TYPE1_CURVE                        0x800200a6
#define TEE_ERR_SM2_EC_R_INVLID_TYPE1CURVE                          0x800200a7
#define TEE_ERR_SM2_EC_R_KDF_PARAMETER_ERROR                        0x800200a8
#define TEE_ERR_SM2_EC_R_KEYS_NOT_SET                               0x800200a9
#define TEE_ERR_SM2_EC_R_MISSING_PARAMETERS                         0x800200aa
#define TEE_ERR_SM2_EC_R_MISSING_PRIVATE_KEY                        0x800200ab
#define TEE_ERR_SM2_EC_R_NEED_NEW_SETUP_VALUES                      0x800200ac
#define TEE_ERR_SM2_EC_R_NOT_A_NIST_PRIME                           0x800200ad
#define TEE_ERR_SM2_EC_R_NOT_IMPLEMENTED                            0x800200ae
#define TEE_ERR_SM2_EC_R_NOT_INITIALIZED                            0x800200af
#define TEE_ERR_SM2_EC_R_NO_PARAMETERS_SET                          0x800200b0
#define TEE_ERR_SM2_EC_R_NO_PRIVATE_VALUE                           0x800200b1
#define TEE_ERR_SM2_EC_R_OPERATION_NOT_SUPPORTED                    0x800200b2
#define TEE_ERR_SM2_EC_R_PASSED_NULL_PARAMETER                      0x800200b3
#define TEE_ERR_SM2_EC_R_PEER_KEY_ERROR                             0x800200b4
#define TEE_ERR_SM2_EC_R_PKPARAMETERS2GROUP_FAILURE                 0x800200b5
#define TEE_ERR_SM2_EC_R_POINT_ARITHMETIC_FAILURE                   0x800200b6
#define TEE_ERR_SM2_EC_R_POINT_AT_INFINITY                          0x800200b7
#define TEE_ERR_SM2_EC_R_POINT_IS_NOT_ON_CURVE                      0x800200b8
#define TEE_ERR_SM2_EC_R_RANDOM_NUMBER_GENERATION_FAILED            0x800200b9
#define TEE_ERR_SM2_EC_R_SHARED_INFO_ERROR                          0x800200ba
#define TEE_ERR_SM2_EC_R_SLOT_FULL                                  0x800200bb
#define TEE_ERR_SM2_EC_R_SM2_DECRYPT_FAILED                         0x800200bc
#define TEE_ERR_SM2_EC_R_SM2_ENCRYPT_FAILED                         0x800200bd
#define TEE_ERR_SM2_EC_R_SM2_KAP_NOT_INITED                         0x800200be
#define TEE_ERR_SM2_EC_R_UNDEFINED_GENERATOR                        0x800200bf
#define TEE_ERR_SM2_EC_R_UNDEFINED_ORDER                            0x800200c0
#define TEE_ERR_SM2_EC_R_UNKNOWN_GROUP                              0x800200c1
#define TEE_ERR_SM2_EC_R_UNKNOWN_ORDER                              0x800200c2
#define TEE_ERR_SM2_EC_R_UNSUPPORTED_FIELD                          0x800200c3
#define TEE_ERR_SM2_EC_R_WRONG_CURVE_PARAMETERS                     0x800200c4
#define TEE_ERR_SM2_EC_R_WRONG_ORDER                                0x800200c5

#define TEE_ERR_SM4_ERR_R_MALLOC_FAILURE                            0x80021041
#define TEE_ERR_SM4_ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED               0x80021042
#define TEE_ERR_SM4_ERR_R_PASSED_NULL_PARAMETER                     0x80021043
#define TEE_ERR_SM4_ERR_R_INTERNAL_ERROR                            0x80021044
#define TEE_ERR_SM4_ERR_R_DISABLED                                  0x80021045
#define TEE_ERR_SM4_ERR_R_INIT_FAIL                                 0x80021046
#define TEE_ERR_SM4_ERR_R_PASSED_INVALID_ARGUMENT                   0x80021007

/* for sm4 evp lib err */
#define TEE_ERR_SM4_EVP_R_AES_KEY_SETUP_FAILED                      0x8002108f
#define TEE_ERR_SM4_EVP_R_BAD_DECRYPT                               0x80021064
#define TEE_ERR_SM4_EVP_R_BUFFER_TOO_SMALL                          0x8002109b
#define TEE_ERR_SM4_EVP_R_CAMELLIA_KEY_SETUP_FAILED                 0x8002109d
#define TEE_ERR_SM4_EVP_R_CIPHER_PARAMETER_ERROR                    0x8002107a
#define TEE_ERR_SM4_EVP_R_COMMAND_NOT_SUPPORTED                     0x80021093
#define TEE_ERR_SM4_EVP_R_COPY_ERROR                                0x800210ad
#define TEE_ERR_SM4_EVP_R_CTRL_NOT_IMPLEMENTED                      0x80021084
#define TEE_ERR_SM4_EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED            0x80021085
#define TEE_ERR_SM4_EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH         0x8002108a
#define TEE_ERR_SM4_EVP_R_DECODE_ERROR                              0x80021072
#define TEE_ERR_SM4_EVP_R_DIFFERENT_KEY_TYPES                       0x80021065
#define TEE_ERR_SM4_EVP_R_DIFFERENT_PARAMETERS                      0x80021099
#define TEE_ERR_SM4_EVP_R_ERROR_LOADING_SECTION                     0x800210a5
#define TEE_ERR_SM4_EVP_R_ERROR_SETTING_FIPS_MODE                   0x800210a6
#define TEE_ERR_SM4_EVP_R_EXPECTING_AN_HMAC_KEY                     0x800210ae
#define TEE_ERR_SM4_EVP_R_EXPECTING_AN_RSA_KEY                      0x8002107f
#define TEE_ERR_SM4_EVP_R_EXPECTING_A_DH_KEY                        0x80021080
#define TEE_ERR_SM4_EVP_R_EXPECTING_A_DSA_KEY                       0x80021081
#define TEE_ERR_SM4_EVP_R_EXPECTING_A_EC_KEY                        0x8002108e
#define TEE_ERR_SM4_EVP_R_EXPECTING_A_PAILLIER                      0x800210b0
#define TEE_ERR_SM4_EVP_R_FIPS_MODE_NOT_SUPPORTED                   0x800210a7
#define TEE_ERR_SM4_EVP_R_ILLEGAL_SCRYPT_PARAMETERS                 0x800210ab
#define TEE_ERR_SM4_EVP_R_INITIALIZATION_ERROR                      0x80021086
#define TEE_ERR_SM4_EVP_R_INPUT_NOT_INITIALIZED                     0x8002106f
#define TEE_ERR_SM4_EVP_R_INVALID_DIGEST                            0x80021098
#define TEE_ERR_SM4_EVP_R_INVALID_FIPS_MODE                         0x800210a8
#define TEE_ERR_SM4_EVP_R_INVALID_INPUT_LENGTH                      0x800210a4
#define TEE_ERR_SM4_EVP_R_INVALID_KEY                               0x800210a3
#define TEE_ERR_SM4_EVP_R_INVALID_KEY_LENGTH                        0x80021082
#define TEE_ERR_SM4_EVP_R_INVALID_OPERATION                         0x80021094
#define TEE_ERR_SM4_EVP_R_KEYGEN_FAILURE                            0x80021078
#define TEE_ERR_SM4_EVP_R_MEMORY_LIMIT_EXCEEDED                     0x800210ac
#define TEE_ERR_SM4_EVP_R_MESSAGE_DIGEST_IS_NULL                    0x8002109f
#define TEE_ERR_SM4_EVP_R_METHOD_NOT_SUPPORTED                      0x80021090
#define TEE_ERR_SM4_EVP_R_MISSING_PARAMETERS                        0x80021067
#define TEE_ERR_SM4_EVP_R_NO_AVAIABLE_DIGEST                        0x800210b2
#define TEE_ERR_SM4_EVP_R_NO_CIPHER_SET                             0x80021083
#define TEE_ERR_SM4_EVP_R_NO_DEFAULT_DIGEST                         0x8002109e
#define TEE_ERR_SM4_EVP_R_NO_DIGEST_SET                             0x8002108b
#define TEE_ERR_SM4_EVP_R_NO_KEY_SET                                0x8002109a
#define TEE_ERR_SM4_EVP_R_NO_OPERATION_SET                          0x80021095
#define TEE_ERR_SM4_EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE  0x80021096
#define TEE_ERR_SM4_EVP_R_OPERATON_NOT_INITIALIZED                  0x80021097
#define TEE_ERR_SM4_EVP_R_PARTIALLY_OVERLAPPING                     0x800210a2
#define TEE_ERR_SM4_EVP_R_PRIVATE_KEY_DECODE_ERROR                  0x80021091
#define TEE_ERR_SM4_EVP_R_PRIVATE_KEY_ENCODE_ERROR                  0x80021092
#define TEE_ERR_SM4_EVP_R_PUBLIC_KEY_NOT_RSA                        0x8002106a
#define TEE_ERR_SM4_EVP_R_PUBLIC_KEY_NOT_RSA_OR_EC                  0x800210b1
#define TEE_ERR_SM4_EVP_R_RSA_PUBLIC_ENCRYPT_FAILED                 0x800210af
#define TEE_ERR_SM4_EVP_R_UNKNOWN_CIPHER                            0x800210a0
#define TEE_ERR_SM4_EVP_R_UNKNOWN_DIGEST                            0x800210a1
#define TEE_ERR_SM4_EVP_R_UNKNOWN_OPTION                            0x800210a9
#define TEE_ERR_SM4_EVP_R_UNKNOWN_PBE_ALGORITHM                     0x80021079
#define TEE_ERR_SM4_EVP_R_UNSUPPORTED_ALGORITHM                     0x8002109c
#define TEE_ERR_SM4_EVP_R_UNSUPPORTED_CIPHER                        0x8002106b
#define TEE_ERR_SM4_EVP_R_UNSUPPORTED_KEYLENGTH                     0x8002107b
#define TEE_ERR_SM4_EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION       0x8002107c
#define TEE_ERR_SM4_EVP_R_UNSUPPORTED_KEY_SIZE                      0x8002106c
#define TEE_ERR_SM4_EVP_R_UNSUPPORTED_NUMBER_OF_ROUNDS              0x80021087
#define TEE_ERR_SM4_EVP_R_UNSUPPORTED_PRF                           0x8002107d
#define TEE_ERR_SM4_EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM         0x80021076
#define TEE_ERR_SM4_EVP_R_UNSUPPORTED_SALT_TYPE                     0x8002107e
#define TEE_ERR_SM4_EVP_R_WRAP_MODE_NOT_ALLOWED                     0x800210aa
#define TEE_ERR_SM4_EVP_R_WRONG_FINAL_BLOCK_LENGTH                  0x8002106d

#endif
