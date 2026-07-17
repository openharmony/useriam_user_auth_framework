/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "hdf_base.h"
#include "hdi_type_convert.h"
#include "iam_common_defines.h"
#include "hdi_type_aliases.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class HdiTypeConvertTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

// ---- HdfCodeToResult -------------------------------------------------------

HWTEST_F(HdiTypeConvertTest, HdfCodeToResult_PositivePassesThrough, TestSize.Level0)
{
    // Driver business ResultCodes (>= 0) pass through unchanged.
    EXPECT_EQ(HdfCodeToResult(0), 0);
    EXPECT_EQ(HdfCodeToResult(1), 1);
    EXPECT_EQ(HdfCodeToResult(SUCCESS), SUCCESS);
}

HWTEST_F(HdiTypeConvertTest, HdfCodeToResult_HdfErrorsMapped, TestSize.Level0)
{
    EXPECT_EQ(HdfCodeToResult(HDF_ERR_INVALID_PARAM), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(HdfCodeToResult(HDF_ERR_NOT_SUPPORT), ResultCode::TYPE_NOT_SUPPORT);
    EXPECT_EQ(HdfCodeToResult(HDF_ERR_TIMEOUT), ResultCode::TIMEOUT);
    EXPECT_EQ(HdfCodeToResult(HDF_ERR_DEVICE_BUSY), ResultCode::BUSY);
    EXPECT_EQ(HdfCodeToResult(HDF_ERR_NOPERM), ResultCode::CHECK_PERMISSION_FAILED);
}

HWTEST_F(HdiTypeConvertTest, HdfCodeToResult_UnknownHdfCodeDefaultsGeneralError, TestSize.Level0)
{
    EXPECT_EQ(HdfCodeToResult(-1), ResultCode::GENERAL_ERROR);
    EXPECT_EQ(HdfCodeToResult(-999), ResultCode::GENERAL_ERROR);
    EXPECT_EQ(HdfCodeToResult(INT32_MIN), ResultCode::GENERAL_ERROR);
}

// ---- V4_0 round-trip tests -------------------------------------------------

HWTEST_F(HdiTypeConvertTest, ExecutorRegisterInfoRoundTrip, TestSize.Level0)
{
    CoAuthInterface::ExecutorRegisterInfo eng = {};
    eng.authType = AuthType::PIN;
    eng.executorRole = ExecutorRole::COLLECTOR;
    eng.executorSensorHint = 42;
    eng.executorMatcher = 100;
    eng.esl = ExecutorSecureLevel::ESL1;
    eng.maxTemplateAcl = 0xDEAD;
    eng.publicKey = {0x01, 0x02, 0x03};
    eng.deviceUdid = "test-udid";
    eng.signedRemoteExecutorInfo = {0xAA, 0xBB};

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.authType, static_cast<int32_t>(AuthType::PIN));
    EXPECT_EQ(hdi.executorRole, static_cast<int32_t>(ExecutorRole::COLLECTOR));
    EXPECT_EQ(hdi.executorSensorHint, 42U);
    EXPECT_EQ(hdi.executorMatcher, 100U);
    EXPECT_EQ(hdi.esl, static_cast<int32_t>(ExecutorSecureLevel::ESL1));
    EXPECT_EQ(hdi.maxTemplateAcl, 0xDEADU);
    EXPECT_EQ(hdi.publicKey, eng.publicKey);
    EXPECT_EQ(hdi.deviceUdid, "test-udid");
    EXPECT_EQ(hdi.signedRemoteExecutorInfo, eng.signedRemoteExecutorInfo);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.authType, eng.authType);
    EXPECT_EQ(back.executorRole, eng.executorRole);
    EXPECT_EQ(back.executorSensorHint, eng.executorSensorHint);
    EXPECT_EQ(back.executorMatcher, eng.executorMatcher);
    EXPECT_EQ(back.esl, eng.esl);
    EXPECT_EQ(back.maxTemplateAcl, eng.maxTemplateAcl);
    EXPECT_EQ(back.publicKey, eng.publicKey);
    EXPECT_EQ(back.deviceUdid, eng.deviceUdid);
    EXPECT_EQ(back.signedRemoteExecutorInfo, eng.signedRemoteExecutorInfo);
}

HWTEST_F(HdiTypeConvertTest, ExecutorSendMsgRoundTrip, TestSize.Level0)
{
    EngExecutorSendMsg eng;
    eng.executorIndex = 7;
    eng.commandId = 42;
    eng.msg = {0x10, 0x20, 0x30, 0x40};

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.executorIndex, 7U);
    EXPECT_EQ(hdi.commandId, 42);
    EXPECT_EQ(hdi.msg, eng.msg);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.executorIndex, eng.executorIndex);
    EXPECT_EQ(back.commandId, eng.commandId);
    EXPECT_EQ(back.msg, eng.msg);
}

HWTEST_F(HdiTypeConvertTest, AuthResultInfoRoundTrip, TestSize.Level0)
{
    EngAuthResultInfo eng;
    eng.result = SUCCESS;
    eng.lockoutDuration = 30;
    eng.remainAttempts = 5;

    EngExecutorSendMsg msg;
    msg.executorIndex = 1;
    msg.commandId = 99;
    msg.msg = {0x01};
    eng.msgs.push_back(msg);
    msg.executorIndex = 2;
    eng.msgs.push_back(msg);

    eng.token = {0xAB, 0xCD};
    eng.rootSecret = {0x11, 0x22, 0x33};
    eng.userId = 100;
    eng.credentialId = 5000;
    eng.pinExpiredInfo = 1234567890L;
    eng.remoteAuthResultMsg = {0xDE, 0xAD};
    eng.reEnrollFlag = true;

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.result, SUCCESS);
    EXPECT_EQ(hdi.lockoutDuration, 30);
    EXPECT_EQ(hdi.remainAttempts, 5);
    EXPECT_EQ(hdi.msgs.size(), 2U);
    EXPECT_EQ(hdi.msgs[0].executorIndex, 1U);
    EXPECT_EQ(hdi.msgs[1].executorIndex, 2U);
    EXPECT_EQ(hdi.token, eng.token);
    EXPECT_EQ(hdi.rootSecret, eng.rootSecret);
    EXPECT_EQ(hdi.userId, 100);
    EXPECT_EQ(hdi.credentialId, 5000U);
    EXPECT_EQ(hdi.pinExpiredInfo, 1234567890L);
    EXPECT_EQ(hdi.remoteAuthResultMsg, eng.remoteAuthResultMsg);
    EXPECT_EQ(hdi.reEnrollFlag, true);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.result, eng.result);
    EXPECT_EQ(back.lockoutDuration, eng.lockoutDuration);
    EXPECT_EQ(back.remainAttempts, eng.remainAttempts);
    EXPECT_EQ(back.msgs.size(), eng.msgs.size());
    EXPECT_EQ(back.msgs[0].executorIndex, eng.msgs[0].executorIndex);
    EXPECT_EQ(back.msgs[0].commandId, eng.msgs[0].commandId);
    EXPECT_EQ(back.token, eng.token);
    EXPECT_EQ(back.rootSecret, eng.rootSecret);
    EXPECT_EQ(back.userId, eng.userId);
    EXPECT_EQ(back.credentialId, eng.credentialId);
    EXPECT_EQ(back.pinExpiredInfo, eng.pinExpiredInfo);
    EXPECT_EQ(back.remoteAuthResultMsg, eng.remoteAuthResultMsg);
    EXPECT_EQ(back.reEnrollFlag, eng.reEnrollFlag);
}

HWTEST_F(HdiTypeConvertTest, IdentifyResultInfoRoundTrip, TestSize.Level0)
{
    EngIdentifyResultInfo eng;
    eng.result = SUCCESS;
    eng.userId = 42;
    eng.token = {0x01, 0x02, 0x03, 0x04};

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.result, SUCCESS);
    EXPECT_EQ(hdi.userId, 42);
    EXPECT_EQ(hdi.token, eng.token);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.result, eng.result);
    EXPECT_EQ(back.userId, eng.userId);
    EXPECT_EQ(back.token, eng.token);
}

HWTEST_F(HdiTypeConvertTest, CredentialInfoRoundTrip, TestSize.Level0)
{
    EngCredentialInfo eng = {};
    eng.credentialId = 1001;
    eng.executorIndex = 2;
    eng.templateId = 50001;
    eng.authType = static_cast<int32_t>(AuthType::FACE);
    eng.executorMatcher = 3;
    eng.executorSensorHint = 1;
    eng.authSubType = 10;
    eng.isAbandoned = true;
    eng.validityPeriod = 86400L;

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.credentialId, 1001U);
    EXPECT_EQ(hdi.executorIndex, 2U);
    EXPECT_EQ(hdi.templateId, 50001U);
    EXPECT_EQ(hdi.authType, static_cast<int32_t>(AuthType::FACE));
    EXPECT_EQ(hdi.executorMatcher, 3U);
    EXPECT_EQ(hdi.executorSensorHint, 1U);
    EXPECT_EQ(hdi.authSubType, 10);
    EXPECT_EQ(hdi.isAbandoned, true);
    EXPECT_EQ(hdi.validityPeriod, 86400L);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.credentialId, eng.credentialId);
    EXPECT_EQ(back.executorIndex, eng.executorIndex);
    EXPECT_EQ(back.templateId, eng.templateId);
    EXPECT_EQ(back.authType, eng.authType);
    EXPECT_EQ(back.executorMatcher, eng.executorMatcher);
    EXPECT_EQ(back.executorSensorHint, eng.executorSensorHint);
    EXPECT_EQ(back.authSubType, eng.authSubType);
    EXPECT_EQ(back.isAbandoned, eng.isAbandoned);
    EXPECT_EQ(back.validityPeriod, eng.validityPeriod);
}

HWTEST_F(HdiTypeConvertTest, EnrolledInfoRoundTrip, TestSize.Level0)
{
    EnrolledInfo eng = {};
    eng.authType = AuthType::PIN;
    eng.enrolledId = 999;

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.authType, static_cast<int32_t>(AuthType::PIN));
    EXPECT_EQ(hdi.enrolledId, 999U);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.authType, eng.authType);
    EXPECT_EQ(back.enrolledId, eng.enrolledId);
}

HWTEST_F(HdiTypeConvertTest, EnrollResultInfoRoundTrip, TestSize.Level0)
{
    EngEnrollResultInfo eng;
    eng.credentialId = 42;
    eng.oldInfo.credentialId = 41;
    eng.oldInfo.templateId = 100;
    eng.oldInfo.authType = static_cast<int32_t>(AuthType::PIN);
    eng.oldInfo.isAbandoned = false;
    eng.rootSecret = {0xCA, 0xFE};
    eng.oldRootSecret = {0xBA, 0xBE};
    eng.authToken = {0x01, 0x02, 0x03};

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.credentialId, 42U);
    EXPECT_EQ(hdi.oldInfo.credentialId, 41U);
    EXPECT_EQ(hdi.oldInfo.templateId, 100U);
    EXPECT_EQ(hdi.rootSecret, eng.rootSecret);
    EXPECT_EQ(hdi.oldRootSecret, eng.oldRootSecret);
    EXPECT_EQ(hdi.authToken, eng.authToken);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.credentialId, eng.credentialId);
    EXPECT_EQ(back.oldInfo.credentialId, eng.oldInfo.credentialId);
    EXPECT_EQ(back.oldInfo.templateId, eng.oldInfo.templateId);
    EXPECT_EQ(back.oldInfo.authType, eng.oldInfo.authType);
    EXPECT_EQ(back.rootSecret, eng.rootSecret);
    EXPECT_EQ(back.oldRootSecret, eng.oldRootSecret);
    EXPECT_EQ(back.authToken, eng.authToken);
}

HWTEST_F(HdiTypeConvertTest, ScheduleInfoRoundTrip, TestSize.Level0)
{
    EngScheduleInfo eng;
    eng.scheduleId = 100;
    eng.templateIds = {10, 20, 30};
    eng.authType = static_cast<int32_t>(AuthType::FACE);
    eng.executorMatcher = 5;
    eng.scheduleMode = 1;
    eng.executorIndexes = {0, 1, 2};
    eng.executorMessages = {{0x01}, {0x02, 0x03}};

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.scheduleId, 100U);
    EXPECT_EQ(hdi.templateIds, eng.templateIds);
    EXPECT_EQ(hdi.authType, static_cast<int32_t>(AuthType::FACE));
    EXPECT_EQ(hdi.executorMatcher, 5U);
    EXPECT_EQ(hdi.scheduleMode, 1);
    EXPECT_EQ(hdi.executorIndexes, eng.executorIndexes);
    EXPECT_EQ(hdi.executorMessages.size(), 2U);
    EXPECT_EQ(hdi.executorMessages[0], eng.executorMessages[0]);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.scheduleId, eng.scheduleId);
    EXPECT_EQ(back.templateIds, eng.templateIds);
    EXPECT_EQ(back.authType, eng.authType);
    EXPECT_EQ(back.executorMatcher, eng.executorMatcher);
    EXPECT_EQ(back.scheduleMode, eng.scheduleMode);
    EXPECT_EQ(back.executorIndexes, eng.executorIndexes);
    ASSERT_EQ(back.executorMessages.size(), eng.executorMessages.size());
    EXPECT_EQ(back.executorMessages[0], eng.executorMessages[0]);
    EXPECT_EQ(back.executorMessages[1], eng.executorMessages[1]);
}

HWTEST_F(HdiTypeConvertTest, UserInfoRoundTrip, TestSize.Level0)
{
    EngUserInfo eng;
    eng.secureUid = 12345;
    eng.pinSubType = 100;
    EnrolledInfo enrolled = {};
    enrolled.authType = AuthType::PIN;
    enrolled.enrolledId = 1;
    eng.enrolledInfos.push_back(enrolled);
    enrolled.enrolledId = 2;
    eng.enrolledInfos.push_back(enrolled);

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.secureUid, 12345U);
    EXPECT_EQ(hdi.pinSubType, 100);
    EXPECT_EQ(hdi.enrolledInfos.size(), 2U);
    EXPECT_EQ(hdi.enrolledInfos[0].enrolledId, 1U);
    EXPECT_EQ(hdi.enrolledInfos[1].enrolledId, 2U);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.secureUid, eng.secureUid);
    EXPECT_EQ(back.pinSubType, eng.pinSubType);
    ASSERT_EQ(back.enrolledInfos.size(), eng.enrolledInfos.size());
    EXPECT_EQ(back.enrolledInfos[0].enrolledId, eng.enrolledInfos[0].enrolledId);
}

HWTEST_F(HdiTypeConvertTest, ExtUserInfoRoundTrip, TestSize.Level0)
{
    EngExtUserInfo eng;
    eng.userId = 42;
    eng.userInfo.secureUid = 999;
    eng.userInfo.pinSubType = 10;
    EnrolledInfo enrolled = {};
    enrolled.authType = AuthType::FACE;
    enrolled.enrolledId = 77;
    eng.userInfo.enrolledInfos.push_back(enrolled);

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.userId, 42);
    EXPECT_EQ(hdi.userInfo.secureUid, 999U);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.userId, eng.userId);
    EXPECT_EQ(back.userInfo.secureUid, eng.userInfo.secureUid);
    EXPECT_EQ(back.userInfo.pinSubType, eng.userInfo.pinSubType);
    ASSERT_EQ(back.userInfo.enrolledInfos.size(), eng.userInfo.enrolledInfos.size());
}

HWTEST_F(HdiTypeConvertTest, AuthParamBaseRoundTrip, TestSize.Level0)
{
    EngAuthParamBase eng;
    eng.userId = 42;
    eng.authTrustLevel = 3;
    eng.executorSensorHint = 1;
    eng.challenge = {0x01, 0x02, 0x03, 0x04, 0x05};
    eng.callerName = "com.test.app";
    eng.callerType = Security::AccessToken::TOKEN_HAP;
    eng.apiVersion = 100;

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.userId, 42);
    EXPECT_EQ(hdi.authTrustLevel, 3U);
    EXPECT_EQ(hdi.callerName, "com.test.app");

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.userId, eng.userId);
    EXPECT_EQ(back.authTrustLevel, eng.authTrustLevel);
    EXPECT_EQ(back.executorSensorHint, eng.executorSensorHint);
    EXPECT_EQ(back.challenge, eng.challenge);
    EXPECT_EQ(back.callerName, eng.callerName);
    EXPECT_EQ(back.callerType, eng.callerType);
    EXPECT_EQ(back.apiVersion, eng.apiVersion);
}

HWTEST_F(HdiTypeConvertTest, AuthParamRoundTrip, TestSize.Level0)
{
    EngAuthParam eng;
    eng.baseParam.userId = 42;
    eng.baseParam.authTrustLevel = 2;
    eng.baseParam.callerName = "auth-app";
    eng.authType = static_cast<int32_t>(AuthType::FACE);
    eng.authIntent = 1;
    eng.isOsAccountVerified = true;
    eng.collectorUdid = "udid-001";

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.baseParam.userId, 42);
    EXPECT_EQ(hdi.authType, static_cast<int32_t>(AuthType::FACE));
    EXPECT_EQ(hdi.collectorUdid, "udid-001");

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.baseParam.userId, eng.baseParam.userId);
    EXPECT_EQ(back.authType, eng.authType);
    EXPECT_EQ(back.authIntent, eng.authIntent);
    EXPECT_EQ(back.isOsAccountVerified, eng.isOsAccountVerified);
    EXPECT_EQ(back.collectorUdid, eng.collectorUdid);
}

HWTEST_F(HdiTypeConvertTest, ReuseUnlockParamRoundTrip, TestSize.Level0)
{
    EngReuseUnlockParam eng;
    eng.baseParam.userId = 1;
    eng.baseParam.callerName = "reuse-test";
    eng.authTypes = {static_cast<int32_t>(AuthType::PIN), static_cast<int32_t>(AuthType::FACE)};
    eng.reuseUnlockResultDuration = 30000;
    eng.reuseUnlockResultMode = 0;

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.baseParam.userId, 1);
    ASSERT_EQ(hdi.authTypes.size(), 2U);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.baseParam.userId, eng.baseParam.userId);
    ASSERT_EQ(back.authTypes.size(), eng.authTypes.size());
    EXPECT_EQ(back.authTypes[0], eng.authTypes[0]);
    EXPECT_EQ(back.authTypes[1], eng.authTypes[1]);
    EXPECT_EQ(back.reuseUnlockResultDuration, eng.reuseUnlockResultDuration);
    EXPECT_EQ(back.reuseUnlockResultMode, eng.reuseUnlockResultMode);
}

HWTEST_F(HdiTypeConvertTest, EnrollParamRoundTrip, TestSize.Level0)
{
    EngEnrollParam eng;
    eng.authType = static_cast<int32_t>(AuthType::PIN);
    eng.executorSensorHint = 2;
    eng.callerName = "enroll-app";
    eng.callerType = Security::AccessToken::TOKEN_HAP;
    eng.apiVersion = 100;
    eng.userId = 42;
    eng.userType = static_cast<int32_t>(EngUserType::MAIN);
    eng.authSubType = 10;

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.authType, static_cast<int32_t>(AuthType::PIN));
    EXPECT_EQ(hdi.callerName, "enroll-app");

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.authType, eng.authType);
    EXPECT_EQ(back.executorSensorHint, eng.executorSensorHint);
    EXPECT_EQ(back.callerName, eng.callerName);
    EXPECT_EQ(back.callerType, eng.callerType);
    EXPECT_EQ(back.apiVersion, eng.apiVersion);
    EXPECT_EQ(back.userId, eng.userId);
    EXPECT_EQ(back.userType, eng.userType);
    EXPECT_EQ(back.authSubType, eng.authSubType);
}

HWTEST_F(HdiTypeConvertTest, EnrolledStateRoundTrip, TestSize.Level0)
{
    EngEnrolledState eng = {};
    eng.credentialDigest = 0xABCD;
    eng.credentialCount = 3;

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.credentialDigest, 0xABCDU);
    EXPECT_EQ(hdi.credentialCount, 3);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.credentialDigest, eng.credentialDigest);
    EXPECT_EQ(back.credentialCount, eng.credentialCount);
}

HWTEST_F(HdiTypeConvertTest, ReuseUnlockInfoRoundTrip, TestSize.Level0)
{
    EngReuseUnlockInfo eng;
    eng.authType = static_cast<int32_t>(AuthType::PIN);
    eng.token = {0xAA, 0xBB, 0xCC};
    eng.enrolledState.credentialDigest = 0x1000;
    eng.enrolledState.credentialCount = 1;

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.authType, static_cast<int32_t>(AuthType::PIN));
    EXPECT_EQ(hdi.token, eng.token);
    EXPECT_EQ(hdi.enrolledState.credentialDigest, 0x1000U);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.authType, eng.authType);
    EXPECT_EQ(back.token, eng.token);
    EXPECT_EQ(back.enrolledState.credentialDigest, eng.enrolledState.credentialDigest);
    EXPECT_EQ(back.enrolledState.credentialCount, eng.enrolledState.credentialCount);
}

HWTEST_F(HdiTypeConvertTest, GlobalConfigParamRoundTrip, TestSize.Level0)
{
    EngGlobalConfigParam eng;
    eng.type = static_cast<int32_t>(EngGlobalConfigType::PIN_EXPIRED_PERIOD);
    eng.value.pinExpiredPeriod = 777;
    eng.userIds = {0, 1, 2};
    eng.authTypes = {static_cast<int32_t>(AuthType::PIN)};

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.type, static_cast<int32_t>(EngGlobalConfigType::PIN_EXPIRED_PERIOD));
    EXPECT_EQ(hdi.value.pinExpiredPeriod, 777L);
    ASSERT_EQ(hdi.userIds.size(), 3U);
    ASSERT_EQ(hdi.authTypes.size(), 1U);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.type, eng.type);
    EXPECT_EQ(back.value.pinExpiredPeriod, eng.value.pinExpiredPeriod);
    ASSERT_EQ(back.userIds.size(), eng.userIds.size());
    EXPECT_EQ(back.userIds[0], eng.userIds[0]);
    EXPECT_EQ(back.authTypes[0], eng.authTypes[0]);
}

HWTEST_F(HdiTypeConvertTest, UserAuthTokenPlainRoundTrip, TestSize.Level0)
{
    EngUserAuthTokenPlain eng;
    eng.version = 1;
    eng.userId = 42;
    eng.challenge = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    eng.timeInterval = 1000;
    eng.authTrustLevel = 2;
    eng.authType = static_cast<int32_t>(AuthType::PIN);
    eng.authMode = 0;
    eng.securityLevel = 1;
    eng.tokenType = 1;
    eng.secureUid = 12345;
    eng.enrolledId = 888;
    eng.credentialId = 999;
    eng.collectorUdid = "collector-01";
    eng.verifierUdid = "verifier-01";

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.version, 1U);
    EXPECT_EQ(hdi.userId, 42);
    EXPECT_EQ(hdi.collectorUdid, "collector-01");
    EXPECT_EQ(hdi.verifierUdid, "verifier-01");

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.version, eng.version);
    EXPECT_EQ(back.userId, eng.userId);
    EXPECT_EQ(back.challenge, eng.challenge);
    EXPECT_EQ(back.timeInterval, eng.timeInterval);
    EXPECT_EQ(back.authTrustLevel, eng.authTrustLevel);
    EXPECT_EQ(back.authType, eng.authType);
    EXPECT_EQ(back.authMode, eng.authMode);
    EXPECT_EQ(back.securityLevel, eng.securityLevel);
    EXPECT_EQ(back.tokenType, eng.tokenType);
    EXPECT_EQ(back.secureUid, eng.secureUid);
    EXPECT_EQ(back.enrolledId, eng.enrolledId);
    EXPECT_EQ(back.credentialId, eng.credentialId);
    EXPECT_EQ(back.collectorUdid, eng.collectorUdid);
    EXPECT_EQ(back.verifierUdid, eng.verifierUdid);
}

HWTEST_F(HdiTypeConvertTest, CredentialOperateResultRoundTrip, TestSize.Level0)
{
    EngCredentialOperateResult eng;
    eng.operateType = EngCredentialOperateType::CREDENTIAL_DELETE;
    eng.scheduleInfo.scheduleId = 200;
    eng.scheduleInfo.templateIds = {11, 22};
    eng.scheduleInfo.authType = static_cast<int32_t>(AuthType::FACE);

    EngCredentialInfo ci = {};
    ci.credentialId = 300;
    ci.authType = static_cast<int32_t>(AuthType::PIN);
    ci.isAbandoned = false;
    eng.credentialInfos.push_back(ci);
    ci.credentialId = 301;
    ci.authType = static_cast<int32_t>(AuthType::FACE);
    eng.credentialInfos.push_back(ci);

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(static_cast<int32_t>(hdi.operateType),
        static_cast<int32_t>(EngCredentialOperateType::CREDENTIAL_DELETE));
    EXPECT_EQ(hdi.scheduleInfo.scheduleId, 200U);
    ASSERT_EQ(hdi.credentialInfos.size(), 2U);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.operateType, eng.operateType);
    EXPECT_EQ(back.scheduleInfo.scheduleId, eng.scheduleInfo.scheduleId);
    EXPECT_EQ(back.scheduleInfo.templateIds, eng.scheduleInfo.templateIds);
    ASSERT_EQ(back.credentialInfos.size(), eng.credentialInfos.size());
    EXPECT_EQ(back.credentialInfos[0].credentialId, eng.credentialInfos[0].credentialId);
    EXPECT_EQ(back.credentialInfos[1].credentialId, eng.credentialInfos[1].credentialId);
}

// ---- V4_1 round-trip tests -------------------------------------------------

HWTEST_F(HdiTypeConvertTest, AuthParamExtRoundTrip, TestSize.Level0)
{
    EngAuthParamExt eng;
    eng.baseParam.userId = 42;
    eng.baseParam.authTrustLevel = 3;
    eng.baseParam.callerName = "ext-auth";
    eng.authType = static_cast<int32_t>(AuthType::FACE);
    eng.authIntent = 0;
    eng.isOsAccountVerified = false;
    eng.collectorUdid = "ext-udid";
    eng.credentialIdList = {100, 200, 300};

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.baseParam.userId, 42);
    EXPECT_EQ(hdi.authType, static_cast<int32_t>(AuthType::FACE));
    ASSERT_EQ(hdi.credentialIdList.size(), 3U);

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.baseParam.userId, eng.baseParam.userId);
    EXPECT_EQ(back.baseParam.authTrustLevel, eng.baseParam.authTrustLevel);
    EXPECT_EQ(back.authType, eng.authType);
    EXPECT_EQ(back.authIntent, eng.authIntent);
    EXPECT_EQ(back.isOsAccountVerified, eng.isOsAccountVerified);
    EXPECT_EQ(back.collectorUdid, eng.collectorUdid);
    EXPECT_EQ(back.credentialIdList, eng.credentialIdList);
}

HWTEST_F(HdiTypeConvertTest, EnrollParamExtRoundTrip, TestSize.Level0)
{
    EngEnrollParamExt eng;
    eng.authType = static_cast<int32_t>(AuthType::PIN);
    eng.executorSensorHint = 1;
    eng.callerName = "ext-enroll";
    eng.callerType = Security::AccessToken::TOKEN_HAP;
    eng.apiVersion = 100;
    eng.userId = 42;
    eng.userType = static_cast<int32_t>(EngUserType::MAIN);
    eng.authSubType = 10;
    eng.additionalInfo = "extra-data";

    auto hdi = EngToHdi(eng);
    EXPECT_EQ(hdi.authType, static_cast<int32_t>(AuthType::PIN));
    EXPECT_EQ(hdi.callerName, "ext-enroll");
    EXPECT_EQ(hdi.additionalInfo, "extra-data");

    auto back = HdiToEng(hdi);
    EXPECT_EQ(back.authType, eng.authType);
    EXPECT_EQ(back.executorSensorHint, eng.executorSensorHint);
    EXPECT_EQ(back.callerName, eng.callerName);
    EXPECT_EQ(back.callerType, eng.callerType);
    EXPECT_EQ(back.apiVersion, eng.apiVersion);
    EXPECT_EQ(back.userId, eng.userId);
    EXPECT_EQ(back.userType, eng.userType);
    EXPECT_EQ(back.authSubType, eng.authSubType);
    EXPECT_EQ(back.additionalInfo, eng.additionalInfo);
}

// ---- Empty / default-value edge cases --------------------------------------

HWTEST_F(HdiTypeConvertTest, ScheduleInfoEmptyVectorsRoundTrip, TestSize.Level0)
{
    EngScheduleInfo eng;
    eng.scheduleId = 1;
    eng.authType = static_cast<int32_t>(AuthType::PIN);
    // templateIds, executorIndexes, executorMessages remain empty

    auto back = HdiToEng(EngToHdi(eng));
    EXPECT_EQ(back.scheduleId, eng.scheduleId);
    EXPECT_TRUE(back.templateIds.empty());
    EXPECT_TRUE(back.executorIndexes.empty());
    EXPECT_TRUE(back.executorMessages.empty());
}

HWTEST_F(HdiTypeConvertTest, AuthResultInfoNoMsgsRoundTrip, TestSize.Level0)
{
    EngAuthResultInfo eng;
    eng.result = SUCCESS;
    eng.userId = 1;
    // msgs remain empty

    auto back = HdiToEng(EngToHdi(eng));
    EXPECT_TRUE(back.msgs.empty());
    EXPECT_TRUE(back.token.empty());
    EXPECT_EQ(back.userId, 1);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
