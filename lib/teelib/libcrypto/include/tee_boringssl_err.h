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

#ifndef TEE_BORINGSSL_ERR_H
#define TEE_BORINGSSL_ERR_H

/*
 * define boringssl lib reasons err code:
 * Delete the prefix TEE_ERR_, which is the error code name in the open-source library.
 */
/* for common lib err */
#define TEE_ERR_R_MALLOC_FAILURE                                0x80022041
#define TEE_ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED                   0x80022042
#define TEE_ERR_R_PASSED_NULL_PARAMETER                         0x80022043
#define TEE_ERR_R_INTERNAL_ERROR                                0x80022044
#define TEE_ERR_R_OVERFLOW                                      0x80022045

/* for bn lib err */
#define TEE_ERR_BN_R_ARG2_LT_ARG3                               0x80023064
#define TEE_ERR_BN_R_BAD_RECIPROCAL                             0x80023065
#define TEE_ERR_BN_R_BIGNUM_TOO_LONG                            0x80023066
#define TEE_ERR_BN_R_BITS_TOO_SMALL                             0x80023067
#define TEE_ERR_BN_R_CALLED_WITH_EVEN_MODULUS                   0x80023068
#define TEE_ERR_BN_R_DIV_BY_ZERO                                0x80023069
#define TEE_ERR_BN_R_EXPAND_ON_STATIC_BIGNUM_DATA               0x8002306a
#define TEE_ERR_BN_R_INPUT_NOT_REDUCED                          0x8002306b
#define TEE_ERR_BN_R_INVALID_RANGE                              0x8002306c
#define TEE_ERR_BN_R_NEGATIVE_NUMBER                            0x8002306d
#define TEE_ERR_BN_R_NOT_A_SQUARE                               0x8002306e
#define TEE_ERR_BN_R_NOT_INITIALIZED                            0x8002306f
#define TEE_ERR_BN_R_NO_INVERSE                                 0x80023070
#define TEE_ERR_BN_R_PRIVATE_KEY_TOO_LARGE                      0x80023071
#define TEE_ERR_BN_R_P_IS_NOT_PRIME                             0x80023072
#define TEE_ERR_BN_R_TOO_MANY_ITERATIONS                        0x80023073
#define TEE_ERR_BN_R_TOO_MANY_TEMPORARY_VARIABLES               0x80023074
#define TEE_ERR_BN_R_BAD_ENCODING                               0x80023075
#define TEE_ERR_BN_R_ENCODE_ERROR                               0x80023076
#define TEE_ERR_BN_R_INVALID_INPUT                              0x80023077

/* for rsa lib err */
#define TEE_ERR_RSA_R_BAD_ENCODING                              0x80024064
#define TEE_ERR_RSA_R_BAD_E_VALUE                               0x80024065
#define TEE_ERR_RSA_R_BAD_FIXED_HEADER_DECRYPT                  0x80024066
#define TEE_ERR_RSA_R_BAD_PAD_BYTE_COUNT                        0x80024067
#define TEE_ERR_RSA_R_BAD_RSA_PARAMETERS                        0x80024068
#define TEE_ERR_RSA_R_BAD_SIGNATURE                             0x80024069
#define TEE_ERR_RSA_R_BAD_VERSION                               0x8002406a
#define TEE_ERR_RSA_R_BLOCK_TYPE_IS_NOT_01                      0x8002406b
#define TEE_ERR_RSA_R_BN_NOT_INITIALIZED                        0x8002406c
#define TEE_ERR_RSA_R_CANNOT_RECOVER_MULTI_PRIME_KEY            0x8002406d
#define TEE_ERR_RSA_R_CRT_PARAMS_ALREADY_GIVEN                  0x8002406e
#define TEE_ERR_RSA_R_CRT_VALUES_INCORRECT                      0x8002406f
#define TEE_ERR_RSA_R_DATA_LEN_NOT_EQUAL_TO_MOD_LEN             0x80024070
#define TEE_ERR_RSA_R_DATA_TOO_LARGE                            0x80024071
#define TEE_ERR_RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE               0x80024072
#define TEE_ERR_RSA_R_DATA_TOO_LARGE_FOR_MODULUS                0x80024073
#define TEE_ERR_RSA_R_DATA_TOO_SMALL                            0x80024074
#define TEE_ERR_RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE               0x80024075
#define TEE_ERR_RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY                0x80024076
#define TEE_ERR_RSA_R_D_E_NOT_CONGRUENT_TO_1                    0x80024077
#define TEE_ERR_RSA_R_EMPTY_PUBLIC_KEY                          0x80024078
#define TEE_ERR_RSA_R_ENCODE_ERROR                              0x80024079
#define TEE_ERR_RSA_R_FIRST_OCTET_INVALID                       0x8002407a
#define TEE_ERR_RSA_R_INCONSISTENT_SET_OF_CRT_VALUES            0x8002407b
#define TEE_ERR_RSA_R_INTERNAL_ERROR                            0x8002407c
#define TEE_ERR_RSA_R_INVALID_MESSAGE_LENGTH                    0x8002407d
#define TEE_ERR_RSA_R_KEY_SIZE_TOO_SMALL                        0x8002407e
#define TEE_ERR_RSA_R_LAST_OCTET_INVALID                        0x8002407f
#define TEE_ERR_RSA_R_MODULUS_TOO_LARGE                         0x80024080
#define TEE_ERR_RSA_R_MUST_HAVE_AT_LEAST_TWO_PRIMES             0x80024081
#define TEE_ERR_RSA_R_NO_PUBLIC_EXPONENT                        0x80024082
#define TEE_ERR_RSA_R_NULL_BEFORE_BLOCK_MISSING                 0x80024083
#define TEE_ERR_RSA_R_N_NOT_EQUAL_P_Q                           0x80024084
#define TEE_ERR_RSA_R_OAEP_DECODING_ERROR                       0x80024085
#define TEE_ERR_RSA_R_ONLY_ONE_OF_P_Q_GIVEN                     0x80024086
#define TEE_ERR_RSA_R_OUTPUT_BUFFER_TOO_SMALL                   0x80024087
#define TEE_ERR_RSA_R_PADDING_CHECK_FAILED                      0x80024088
#define TEE_ERR_RSA_R_PKCS_DECODING_ERROR                       0x80024089
#define TEE_ERR_RSA_R_SLEN_CHECK_FAILED                         0x8002408a
#define TEE_ERR_RSA_R_SLEN_RECOVERY_FAILED                      0x8002408b
#define TEE_ERR_RSA_R_TOO_LONG                                  0x8002408c
#define TEE_ERR_RSA_R_TOO_MANY_ITERATIONS                       0x8002408d
#define TEE_ERR_RSA_R_UNKNOWN_ALGORITHM_TYPE                    0x8002408e
#define TEE_ERR_RSA_R_UNKNOWN_PADDING_TYPE                      0x8002408f
#define TEE_ERR_RSA_R_VALUE_MISSING                             0x80024090
#define TEE_ERR_RSA_R_WRONG_SIGNATURE_LENGTH                    0x80024091
#define TEE_ERR_RSA_R_PUBLIC_KEY_VALIDATION_FAILED              0x80024092
#define TEE_ERR_RSA_R_D_OUT_OF_RANGE                            0x80024093
#define TEE_ERR_RSA_R_BLOCK_TYPE_IS_NOT_02                      0x80024094

/* for evp lib err */
#define TEE_ERR_EVP_R_BUFFER_TOO_SMALL                          0x80025064
#define TEE_ERR_EVP_R_COMMAND_NOT_SUPPORTED                     0x80025065
#define TEE_ERR_EVP_R_DECODE_ERROR                              0x80025066
#define TEE_ERR_EVP_R_DIFFERENT_KEY_TYPES                       0x80025067
#define TEE_ERR_EVP_R_DIFFERENT_PARAMETERS                      0x80025068
#define TEE_ERR_EVP_R_ENCODE_ERROR                              0x80025069
#define TEE_ERR_EVP_R_EXPECTING_AN_EC_KEY_KEY                   0x8002506a
#define TEE_ERR_EVP_R_EXPECTING_AN_RSA_KEY                      0x8002506b
#define TEE_ERR_EVP_R_EXPECTING_A_DSA_KEY                       0x8002506c
#define TEE_ERR_EVP_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE       0x8002506d
#define TEE_ERR_EVP_R_INVALID_DIGEST_LENGTH                     0x8002506e
#define TEE_ERR_EVP_R_INVALID_DIGEST_TYPE                       0x8002506f
#define TEE_ERR_EVP_R_INVALID_KEYBITS                           0x80025070
#define TEE_ERR_EVP_R_INVALID_MGF1_MD                           0x80025071
#define TEE_ERR_EVP_R_INVALID_OPERATION                         0x80025072
#define TEE_ERR_EVP_R_INVALID_PADDING_MODE                      0x80025073
#define TEE_ERR_EVP_R_INVALID_PSS_SALTLEN                       0x80025074
#define TEE_ERR_EVP_R_KEYS_NOT_SET                              0x80025075
#define TEE_ERR_EVP_R_MISSING_PARAMETERS                        0x80025076
#define TEE_ERR_EVP_R_NO_DEFAULT_DIGEST                         0x80025077
#define TEE_ERR_EVP_R_NO_KEY_SET                                0x80025078
#define TEE_ERR_EVP_R_NO_MDC2_SUPPORT                           0x80025079
#define TEE_ERR_EVP_R_NO_NID_FOR_CURVE                          0x8002507a
#define TEE_ERR_EVP_R_NO_OPERATION_SET                          0x8002507b
#define TEE_ERR_EVP_R_NO_PARAMETERS_SET                         0x8002507c
#define TEE_ERR_EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE  0x8002507d
#define TEE_ERR_EVP_R_OPERATON_NOT_INITIALIZED                  0x8002507e
#define TEE_ERR_EVP_R_UNKNOWN_PUBLIC_KEY_TYPE                   0x8002507f
#define TEE_ERR_EVP_R_UNSUPPORTED_ALGORITHM                     0x80025080
#define TEE_ERR_EVP_R_UNSUPPORTED_PUBLIC_KEY_TYPE               0x80025081
#define TEE_ERR_EVP_R_NOT_A_PRIVATE_KEY                         0x80025082
#define TEE_ERR_EVP_R_INVALID_SIGNATURE                         0x80025083
#define TEE_ERR_EVP_R_MEMORY_LIMIT_EXCEEDED                     0x80025084
#define TEE_ERR_EVP_R_INVALID_PARAMETERS                        0x80025085
#define TEE_ERR_EVP_R_INVALID_PEER_KEY                          0x80025086
#define TEE_ERR_EVP_R_NOT_XOF_OR_INVALID_LENGTH                 0x80025087

/* for pem lib err */
#define TEE_ERR_PEM_R_BAD_BASE64_DECODE                         0x80026064
#define TEE_ERR_PEM_R_BAD_DECRYPT                               0x80026065
#define TEE_ERR_PEM_R_BAD_END_LINE                              0x80026066
#define TEE_ERR_PEM_R_BAD_IV_CHARS                              0x80026067
#define TEE_ERR_PEM_R_BAD_PASSWORD_READ                         0x80026068
#define TEE_ERR_PEM_R_CIPHER_IS_NULL                            0x80026069
#define TEE_ERR_PEM_R_ERROR_CONVERTING_PRIVATE_KEY              0x8002606a
#define TEE_ERR_PEM_R_NOT_DEK_INFO                              0x8002606b
#define TEE_ERR_PEM_R_NOT_ENCRYPTED                             0x8002606c
#define TEE_ERR_PEM_R_NOT_PROC_TYPE                             0x8002606d
#define TEE_ERR_PEM_R_NO_START_LINE                             0x8002606e
#define TEE_ERR_PEM_R_READ_KEY                                  0x8002606f
#define TEE_ERR_PEM_R_SHORT_HEADER                              0x80026070
#define TEE_ERR_PEM_R_UNSUPPORTED_CIPHER                        0x80026071
#define TEE_ERR_PEM_R_UNSUPPORTED_ENCRYPTION                    0x80026072

/* for x509 lib err */
#define TEE_ERR_X509_R_AKID_MISMATCH                            0x80027064
#define TEE_ERR_X509_R_BAD_PKCS7_VERSION                        0x80027065
#define TEE_ERR_X509_R_BAD_X509_FILETYPE                        0x80027066
#define TEE_ERR_X509_R_BASE64_DECODE_ERROR                      0x80027067
#define TEE_ERR_X509_R_CANT_CHECK_DH_KEY                        0x80027068
#define TEE_ERR_X509_R_CERT_ALREADY_IN_HASH_TABLE               0x80027069
#define TEE_ERR_X509_R_CRL_ALREADY_DELTA                        0x8002706a
#define TEE_ERR_X509_R_CRL_VERIFY_FAILURE                       0x8002706b
#define TEE_ERR_X509_R_IDP_MISMATCH                             0x8002706c
#define TEE_ERR_X509_R_INVALID_BIT_STRING_BITS_LEFT             0x8002706d
#define TEE_ERR_X509_R_INVALID_DIRECTORY                        0x8002706e
#define TEE_ERR_X509_R_INVALID_FIELD_NAME                       0x8002706f
#define TEE_ERR_X509_R_INVALID_PSS_PARAMETERS                   0x80027070
#define TEE_ERR_X509_R_INVALID_TRUST                            0x80027071
#define TEE_ERR_X509_R_ISSUER_MISMATCH                          0x80027072
#define TEE_ERR_X509_R_KEY_TYPE_MISMATCH                        0x80027073
#define TEE_ERR_X509_R_KEY_VALUES_MISMATCH                      0x80027074
#define TEE_ERR_X509_R_LOADING_CERT_DIR                         0x80027075
#define TEE_ERR_X509_R_LOADING_DEFAULTS                         0x80027076
#define TEE_ERR_X509_R_NEWER_CRL_NOT_NEWER                      0x80027077
#define TEE_ERR_X509_R_NOT_PKCS7_SIGNED_DATA                    0x80027078
#define TEE_ERR_X509_R_NO_CERTIFICATES_INCLUDED                 0x80027079
#define TEE_ERR_X509_R_NO_CERT_SET_FOR_US_TO_VERIFY             0x8002707a
#define TEE_ERR_X509_R_NO_CRLS_INCLUDED                         0x8002707b
#define TEE_ERR_X509_R_NO_CRL_NUMBER                            0x8002707c
#define TEE_ERR_X509_R_PUBLIC_KEY_DECODE_ERROR                  0x8002707d
#define TEE_ERR_X509_R_PUBLIC_KEY_ENCODE_ERROR                  0x8002707e
#define TEE_ERR_X509_R_SHOULD_RETRY                             0x8002707f
#define TEE_ERR_X509_R_UNKNOWN_KEY_TYPE                         0x80027080
#define TEE_ERR_X509_R_UNKNOWN_NID                              0x80027081
#define TEE_ERR_X509_R_UNKNOWN_PURPOSE_ID                       0x80027082
#define TEE_ERR_X509_R_UNKNOWN_TRUST_ID                         0x80027083
#define TEE_ERR_X509_R_UNSUPPORTED_ALGORITHM                    0x80027084
#define TEE_ERR_X509_R_WRONG_LOOKUP_TYPE                        0x80027085
#define TEE_ERR_X509_R_WRONG_TYPE                               0x80027086
#define TEE_ERR_X509_R_NAME_TOO_LONG                            0x80027087
#define TEE_ERR_X509_R_INVALID_PARAMETER                        0x80027088
#define TEE_ERR_X509_R_SIGNATURE_ALGORITHM_MISMATCH             0x80027089

/* for asn1 lib err */
#define TEE_ERR_ASN1_R_ASN1_LENGTH_MISMATCH                     0x80028064
#define TEE_ERR_ASN1_R_AUX_ERROR                                0x80028065
#define TEE_ERR_ASN1_R_BAD_GET_ASN1_OBJECT_CALL                 0x80028066
#define TEE_ERR_ASN1_R_BAD_OBJECT_HEADER                        0x80028067
#define TEE_ERR_ASN1_R_BMPSTRING_IS_WRONG_LENGTH                0x80028068
#define TEE_ERR_ASN1_R_BN_LIB                                   0x80028069
#define TEE_ERR_ASN1_R_BOOLEAN_IS_WRONG_LENGTH                  0x8002806a
#define TEE_ERR_ASN1_R_BUFFER_TOO_SMALL                         0x8002806b
#define TEE_ERR_ASN1_R_CONTEXT_NOT_INITIALISED                  0x8002806c
#define TEE_ERR_ASN1_R_DECODE_ERROR                             0x8002806d
#define TEE_ERR_ASN1_R_DEPTH_EXCEEDED                           0x8002806e
#define TEE_ERR_ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED        0x8002806f
#define TEE_ERR_ASN1_R_ENCODE_ERROR                             0x80028070
#define TEE_ERR_ASN1_R_ERROR_GETTING_TIME                       0x80028071
#define TEE_ERR_ASN1_R_EXPECTING_AN_ASN1_SEQUENCE               0x80028072
#define TEE_ERR_ASN1_R_EXPECTING_AN_INTEGER                     0x80028073
#define TEE_ERR_ASN1_R_EXPECTING_AN_OBJECT                      0x80028074
#define TEE_ERR_ASN1_R_EXPECTING_A_BOOLEAN                      0x80028075
#define TEE_ERR_ASN1_R_EXPECTING_A_TIME                         0x80028076
#define TEE_ERR_ASN1_R_EXPLICIT_LENGTH_MISMATCH                 0x80028077
#define TEE_ERR_ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED             0x80028078
#define TEE_ERR_ASN1_R_FIELD_MISSING                            0x80028079
#define TEE_ERR_ASN1_R_FIRST_NUM_TOO_LARGE                      0x8002807a
#define TEE_ERR_ASN1_R_HEADER_TOO_LONG                          0x8002807b
#define TEE_ERR_ASN1_R_ILLEGAL_BITSTRING_FORMAT                 0x8002807c
#define TEE_ERR_ASN1_R_ILLEGAL_BOOLEAN                          0x8002807d
#define TEE_ERR_ASN1_R_ILLEGAL_CHARACTERS                       0x8002807e
#define TEE_ERR_ASN1_R_ILLEGAL_FORMAT                           0x8002807f
#define TEE_ERR_ASN1_R_ILLEGAL_HEX                              0x80028080
#define TEE_ERR_ASN1_R_ILLEGAL_IMPLICIT_TAG                     0x80028081
#define TEE_ERR_ASN1_R_ILLEGAL_INTEGER                          0x80028082
#define TEE_ERR_ASN1_R_ILLEGAL_NESTED_TAGGING                   0x80028083
#define TEE_ERR_ASN1_R_ILLEGAL_NULL                             0x80028084
#define TEE_ERR_ASN1_R_ILLEGAL_NULL_VALUE                       0x80028085
#define TEE_ERR_ASN1_R_ILLEGAL_OBJECT                           0x80028086
#define TEE_ERR_ASN1_R_ILLEGAL_OPTIONAL_ANY                     0x80028087
#define TEE_ERR_ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE         0x80028088
#define TEE_ERR_ASN1_R_ILLEGAL_TAGGED_ANY                       0x80028089
#define TEE_ERR_ASN1_R_ILLEGAL_TIME_VALUE                       0x8002808a
#define TEE_ERR_ASN1_R_INTEGER_NOT_ASCII_FORMAT                 0x8002808b
#define TEE_ERR_ASN1_R_INTEGER_TOO_LARGE_FOR_LONG               0x8002808c
#define TEE_ERR_ASN1_R_INVALID_BIT_STRING_BITS_LEFT             0x8002808d
#define TEE_ERR_ASN1_R_INVALID_BMPSTRING                        0x8002808e
#define TEE_ERR_ASN1_R_INVALID_DIGIT                            0x8002808f
#define TEE_ERR_ASN1_R_INVALID_MODIFIER                         0x80028090
#define TEE_ERR_ASN1_R_INVALID_NUMBER                           0x80028091
#define TEE_ERR_ASN1_R_INVALID_OBJECT_ENCODING                  0x80028092
#define TEE_ERR_ASN1_R_INVALID_SEPARATOR                        0x80028093
#define TEE_ERR_ASN1_R_INVALID_TIME_FORMAT                      0x80028094
#define TEE_ERR_ASN1_R_INVALID_UNIVERSALSTRING                  0x80028095
#define TEE_ERR_ASN1_R_INVALID_UTF8STRING                       0x80028096
#define TEE_ERR_ASN1_R_LIST_ERROR                               0x80028097
#define TEE_ERR_ASN1_R_MISSING_ASN1_EOS                         0x80028098
#define TEE_ERR_ASN1_R_MISSING_EOC                              0x80028099
#define TEE_ERR_ASN1_R_MISSING_SECOND_NUMBER                    0x8002809a
#define TEE_ERR_ASN1_R_MISSING_VALUE                            0x8002809b
#define TEE_ERR_ASN1_R_MSTRING_NOT_UNIVERSAL                    0x8002809c
#define TEE_ERR_ASN1_R_MSTRING_WRONG_TAG                        0x8002809d
#define TEE_ERR_ASN1_R_NESTED_ASN1_ERROR                        0x8002809e
#define TEE_ERR_ASN1_R_NESTED_ASN1_STRING                       0x8002809f
#define TEE_ERR_ASN1_R_NON_HEX_CHARACTERS                       0x800280a0
#define TEE_ERR_ASN1_R_NOT_ASCII_FORMAT                         0x800280a1
#define TEE_ERR_ASN1_R_NOT_ENOUGH_DATA                          0x800280a2
#define TEE_ERR_ASN1_R_NO_MATCHING_CHOICE_TYPE                  0x800280a3
#define TEE_ERR_ASN1_R_NULL_IS_WRONG_LENGTH                     0x800280a4
#define TEE_ERR_ASN1_R_OBJECT_NOT_ASCII_FORMAT                  0x800280a5
#define TEE_ERR_ASN1_R_ODD_NUMBER_OF_CHARS                      0x800280a6
#define TEE_ERR_ASN1_R_SECOND_NUMBER_TOO_LARGE                  0x800280a7
#define TEE_ERR_ASN1_R_SEQUENCE_LENGTH_MISMATCH                 0x800280a8
#define TEE_ERR_ASN1_R_SEQUENCE_NOT_CONSTRUCTED                 0x800280a9
#define TEE_ERR_ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG             0x800280aa
#define TEE_ERR_ASN1_R_SHORT_LINE                               0x800280ab
#define TEE_ERR_ASN1_R_STREAMING_NOT_SUPPORTED                  0x800280ac
#define TEE_ERR_ASN1_R_STRING_TOO_LONG                          0x800280ad
#define TEE_ERR_ASN1_R_STRING_TOO_SHORT                         0x800280ae
#define TEE_ERR_ASN1_R_TAG_VALUE_TOO_HIGH                       0x800280af
#define TEE_ERR_ASN1_R_TIME_NOT_ASCII_FORMAT                    0x800280b0
#define TEE_ERR_ASN1_R_TOO_LONG                                 0x800280b1
#define TEE_ERR_ASN1_R_TYPE_NOT_CONSTRUCTED                     0x800280b2
#define TEE_ERR_ASN1_R_TYPE_NOT_PRIMITIVE                       0x800280b3
#define TEE_ERR_ASN1_R_UNEXPECTED_EOC                           0x800280b4
#define TEE_ERR_ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH          0x800280b5
#define TEE_ERR_ASN1_R_UNKNOWN_FORMAT                           0x800280b6
#define TEE_ERR_ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM         0x800280b7
#define TEE_ERR_ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM              0x800280b8
#define TEE_ERR_ASN1_R_UNKNOWN_TAG                              0x800280b9
#define TEE_ERR_ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE          0x800280ba
#define TEE_ERR_ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE              0x800280bb
#define TEE_ERR_ASN1_R_UNSUPPORTED_TYPE                         0x800280bc
#define TEE_ERR_ASN1_R_WRONG_PUBLIC_KEY_TYPE                    0x800280bd
#define TEE_ERR_ASN1_R_WRONG_TAG                                0x800280be
#define TEE_ERR_ASN1_R_WRONG_TYPE                               0x800280bf
#define TEE_ERR_ASN1_R_NESTED_TOO_DEEP                          0x800280c0

/* for ec lib err */
#define TEE_ERR_EC_R_BUFFER_TOO_SMALL                           0x8002a064
#define TEE_ERR_EC_R_COORDINATES_OUT_OF_RANGE                   0x8002a065
#define TEE_ERR_EC_R_D2I_ECPKPARAMETERS_FAILURE                 0x8002a066
#define TEE_ERR_EC_R_EC_GROUP_NEW_BY_NAME_FAILURE               0x8002a067
#define TEE_ERR_EC_R_GROUP2PKPARAMETERS_FAILURE                 0x8002a068
#define TEE_ERR_EC_R_I2D_ECPKPARAMETERS_FAILURE                 0x8002a069
#define TEE_ERR_EC_R_INCOMPATIBLE_OBJECTS                       0x8002a06a
#define TEE_ERR_EC_R_INVALID_COMPRESSED_POINT                   0x8002a06b
#define TEE_ERR_EC_R_INVALID_COMPRESSION_BIT                    0x8002a06c
#define TEE_ERR_EC_R_INVALID_ENCODING                           0x8002a06d
#define TEE_ERR_EC_R_INVALID_FIELD                              0x8002a06e
#define TEE_ERR_EC_R_INVALID_FORM                               0x8002a06f
#define TEE_ERR_EC_R_INVALID_GROUP_ORDER                        0x8002a070
#define TEE_ERR_EC_R_INVALID_PRIVATE_KEY                        0x8002a071
#define TEE_ERR_EC_R_MISSING_PARAMETERS                         0x8002a072
#define TEE_ERR_EC_R_MISSING_PRIVATE_KEY                        0x8002a073
#define TEE_ERR_EC_R_NON_NAMED_CURVE                            0x8002a074
#define TEE_ERR_EC_R_NOT_INITIALIZED                            0x8002a075
#define TEE_ERR_EC_R_PKPARAMETERS2GROUP_FAILURE                 0x8002a076
#define TEE_ERR_EC_R_POINT_AT_INFINITY                          0x8002a077
#define TEE_ERR_EC_R_POINT_IS_NOT_ON_CURVE                      0x8002a078
#define TEE_ERR_EC_R_SLOT_FULL                                  0x8002a079
#define TEE_ERR_EC_R_UNDEFINED_GENERATOR                        0x8002a07a
#define TEE_ERR_EC_R_UNKNOWN_GROUP                              0x8002a07b
#define TEE_ERR_EC_R_UNKNOWN_ORDER                              0x8002a07c
#define TEE_ERR_EC_R_WRONG_ORDER                                0x8002a07d
#define TEE_ERR_EC_R_BIGNUM_OUT_OF_RANGE                        0x8002a07e
#define TEE_ERR_EC_R_WRONG_CURVE_PARAMETERS                     0x8002a07f
#define TEE_ERR_EC_R_DECODE_ERROR                               0x8002a080
#define TEE_ERR_EC_R_ENCODE_ERROR                               0x8002a081
#define TEE_ERR_EC_R_GROUP_MISMATCH                             0x8002a082
#define TEE_ERR_EC_R_INVALID_COFACTOR                           0x8002a083
#define TEE_ERR_EC_R_PUBLIC_KEY_VALIDATION_FAILED               0x8002a084
#define TEE_ERR_EC_R_INVALID_SCALAR                             0x8002a085

/* for pkcs7 lib err */
#define TEE_ERR_PKCS7_R_BAD_PKCS7_VERSION                       0x8002b064
#define TEE_ERR_PKCS7_R_NOT_PKCS7_SIGNED_DATA                   0x8002b065
#define TEE_ERR_PKCS7_R_NO_CERTIFICATES_INCLUDED                0x8002b066
#define TEE_ERR_PKCS7_R_NO_CRLS_INCLUDED                        0x8002b067

#endif