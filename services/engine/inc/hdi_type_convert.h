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

#ifndef HDI_TYPE_CONVERT_H
#define HDI_TYPE_CONVERT_H

#include <cstdint>
#include <vector>

#include "iam_common_defines.h"
#include "hdi_type_aliases.h"
#include "user_auth_engine_types.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

int32_t HdfCodeToResult(int32_t hdfCode);

HdiExecutorRegisterInfo EngToHdi(const CoAuthInterface::ExecutorRegisterInfo &info);
CoAuthInterface::ExecutorRegisterInfo HdiToEng(const HdiExecutorRegisterInfo &hdi);

HdiExecutorSendMsg EngToHdi(const EngExecutorSendMsg &eng);
EngExecutorSendMsg HdiToEng(const HdiExecutorSendMsg &hdi);

HdiAuthResultInfo EngToHdi(const EngAuthResultInfo &eng);
EngAuthResultInfo HdiToEng(const HdiAuthResultInfo &hdi);

HdiIdentifyResultInfo EngToHdi(const EngIdentifyResultInfo &eng);
EngIdentifyResultInfo HdiToEng(const HdiIdentifyResultInfo &hdi);

HdiCredentialInfo EngToHdi(const EngCredentialInfo &eng);
EngCredentialInfo HdiToEng(const HdiCredentialInfo &hdi);

HdiEnrolledInfo EngToHdi(const EnrolledInfo &eng);
EnrolledInfo HdiToEng(const HdiEnrolledInfo &hdi);

HdiEnrollResultInfo EngToHdi(const EngEnrollResultInfo &eng);
EngEnrollResultInfo HdiToEng(const HdiEnrollResultInfo &hdi);

HdiScheduleInfo EngToHdi(const EngScheduleInfo &eng);
EngScheduleInfo HdiToEng(const HdiScheduleInfo &hdi);

HdiUserInfo EngToHdi(const EngUserInfo &eng);
EngUserInfo HdiToEng(const HdiUserInfo &hdi);

HdiExtUserInfo EngToHdi(const EngExtUserInfo &eng);
EngExtUserInfo HdiToEng(const HdiExtUserInfo &hdi);

HdiAuthParamBase EngToHdi(const EngAuthParamBase &eng);
EngAuthParamBase HdiToEng(const HdiAuthParamBase &hdi);

HdiAuthParam EngToHdi(const EngAuthParam &eng);
EngAuthParam HdiToEng(const HdiAuthParam &hdi);

HdiReuseUnlockParam EngToHdi(const EngReuseUnlockParam &eng);
EngReuseUnlockParam HdiToEng(const HdiReuseUnlockParam &hdi);

HdiEnrollParam EngToHdi(const EngEnrollParam &eng);
EngEnrollParam HdiToEng(const HdiEnrollParam &hdi);

// EngEnrolledState: dedicated mirror struct, converted by field name.
HdiEnrolledState EngToHdi(const EngEnrolledState &eng);
EngEnrolledState HdiToEng(const HdiEnrolledState &hdi);

HdiReuseUnlockInfo EngToHdi(const EngReuseUnlockInfo &eng);
EngReuseUnlockInfo HdiToEng(const HdiReuseUnlockInfo &hdi);

HdiGlobalConfigParam EngToHdi(const EngGlobalConfigParam &eng);
EngGlobalConfigParam HdiToEng(const HdiGlobalConfigParam &hdi);

HdiUserAuthTokenPlain EngToHdi(const EngUserAuthTokenPlain &eng);
EngUserAuthTokenPlain HdiToEng(const HdiUserAuthTokenPlain &hdi);

HdiCredentialOperateResult EngToHdi(const EngCredentialOperateResult &eng);
EngCredentialOperateResult HdiToEng(const HdiCredentialOperateResult &hdi);

HdiAuthParamExt EngToHdi(const EngAuthParamExt &eng);
EngAuthParamExt HdiToEng(const HdiAuthParamExt &hdi);

HdiEnrollParamExt EngToHdi(const EngEnrollParamExt &eng);
EngEnrollParamExt HdiToEng(const HdiEnrollParamExt &hdi);

template <typename D, typename H>
std::vector<H> VecEngToHdi(const std::vector<D> &engVec)
{
    std::vector<H> hdiVec;
    hdiVec.reserve(engVec.size());
    for (const auto &eng : engVec) {
        hdiVec.push_back(EngToHdi(eng));
    }
    return hdiVec;
}

template <typename D, typename H>
std::vector<D> VecHdiToEng(const std::vector<H> &hdiVec)
{
    std::vector<D> engVec;
    engVec.reserve(hdiVec.size());
    for (const auto &hdi : hdiVec) {
        engVec.push_back(HdiToEng(hdi));
    }
    return engVec;
}

// ---- HDI enum value consistency checks ----------------------------------
// Eng-side enums used in static_cast conversions must match their HDI
// counterparts.  HDI IDL is the reference for CredentialOperateType,
// UserType and GlobalConfigType (pure mirrors); for the remaining common
// enums the shared subset is asserted so IDL regen drift is caught early.

// CredentialOperateType (EngCredentialOperateType mirrors HDI)
static_assert(static_cast<int32_t>(EngCredentialOperateType::CREDENTIAL_DELETE) ==
        static_cast<int32_t>(HdiCredentialOperateType::CREDENTIAL_DELETE),
    "CREDENTIAL_DELETE drifted from HDI CredentialOperateType");
static_assert(static_cast<int32_t>(EngCredentialOperateType::CREDENTIAL_ABANDON) ==
        static_cast<int32_t>(HdiCredentialOperateType::CREDENTIAL_ABANDON),
    "CREDENTIAL_ABANDON drifted from HDI CredentialOperateType");

// UserType (EngUserType mirrors HDI)
static_assert(static_cast<int32_t>(EngUserType::MAIN) ==
        static_cast<int32_t>(HdiUserType::MAIN),
    "MAIN drifted from HDI UserType");
static_assert(static_cast<int32_t>(EngUserType::SUB) == static_cast<int32_t>(HdiUserType::SUB),
    "SUB drifted from HDI UserType");
static_assert(static_cast<int32_t>(EngUserType::PRIVATE) ==
        static_cast<int32_t>(HdiUserType::PRIVATE),
    "PRIVATE drifted from HDI UserType");

// GlobalConfigType (EngGlobalConfigType mirrors HDI)
static_assert(static_cast<int32_t>(EngGlobalConfigType::PIN_EXPIRED_PERIOD) ==
        static_cast<int32_t>(HdiGlobalConfigType::PIN_EXPIRED_PERIOD),
    "PIN_EXPIRED_PERIOD drifted from HDI GlobalConfigType");
static_assert(static_cast<int32_t>(EngGlobalConfigType::ENABLE_STATUS) ==
        static_cast<int32_t>(HdiGlobalConfigType::ENABLE_STATUS),
    "ENABLE_STATUS drifted from HDI GlobalConfigType");

// AuthType — common subset (Eng side has extras HDI doesn't define)
static_assert(static_cast<int32_t>(AuthType::ALL) == static_cast<int32_t>(HdiAuthType::ALL),
    "AuthType::ALL drifted from HDI");
static_assert(static_cast<int32_t>(AuthType::PIN) == static_cast<int32_t>(HdiAuthType::PIN),
    "AuthType::PIN drifted from HDI");
static_assert(static_cast<int32_t>(AuthType::FACE) == static_cast<int32_t>(HdiAuthType::FACE),
    "AuthType::FACE drifted from HDI");
static_assert(static_cast<int32_t>(AuthType::FINGERPRINT) ==
        static_cast<int32_t>(HdiAuthType::FINGERPRINT),
    "AuthType::FINGERPRINT drifted from HDI");
static_assert(static_cast<int32_t>(AuthType::RECOVERY_KEY) ==
        static_cast<int32_t>(HdiAuthType::RECOVERY_KEY),
    "AuthType::RECOVERY_KEY drifted from HDI");
static_assert(static_cast<int32_t>(AuthType::PRIVATE_PIN) ==
        static_cast<int32_t>(HdiAuthType::PRIVATE_PIN),
    "AuthType::PRIVATE_PIN drifted from HDI");

// ExecutorRole — common subset (Eng side has SCHEDULER HDI doesn't define)
static_assert(static_cast<int32_t>(ExecutorRole::COLLECTOR) ==
        static_cast<int32_t>(HdiExecutorRole::COLLECTOR),
    "ExecutorRole::COLLECTOR drifted from HDI");
static_assert(static_cast<int32_t>(ExecutorRole::VERIFIER) ==
        static_cast<int32_t>(HdiExecutorRole::VERIFIER),
    "ExecutorRole::VERIFIER drifted from HDI");
static_assert(static_cast<int32_t>(ExecutorRole::ALL_IN_ONE) ==
        static_cast<int32_t>(HdiExecutorRole::ALL_IN_ONE),
    "ExecutorRole::ALL_IN_ONE drifted from HDI");

// ExecutorSecureLevel — all values match
static_assert(static_cast<int32_t>(ExecutorSecureLevel::ESL0) ==
        static_cast<int32_t>(HdiExecutorSecureLevel::ESL0),
    "ExecutorSecureLevel::ESL0 drifted from HDI");
static_assert(static_cast<int32_t>(ExecutorSecureLevel::ESL1) ==
        static_cast<int32_t>(HdiExecutorSecureLevel::ESL1),
    "ExecutorSecureLevel::ESL1 drifted from HDI");
static_assert(static_cast<int32_t>(ExecutorSecureLevel::ESL2) ==
        static_cast<int32_t>(HdiExecutorSecureLevel::ESL2),
    "ExecutorSecureLevel::ESL2 drifted from HDI");
static_assert(static_cast<int32_t>(ExecutorSecureLevel::ESL3) ==
        static_cast<int32_t>(HdiExecutorSecureLevel::ESL3),
    "ExecutorSecureLevel::ESL3 drifted from HDI");

// ScheduleMode — all values match
static_assert(static_cast<int32_t>(ScheduleMode::ENROLL) ==
        static_cast<int32_t>(HdiScheduleMode::ENROLL),
    "ScheduleMode::ENROLL drifted from HDI");
static_assert(static_cast<int32_t>(ScheduleMode::AUTH) ==
        static_cast<int32_t>(HdiScheduleMode::AUTH),
    "ScheduleMode::AUTH drifted from HDI");
static_assert(static_cast<int32_t>(ScheduleMode::IDENTIFY) ==
        static_cast<int32_t>(HdiScheduleMode::IDENTIFY),
    "ScheduleMode::IDENTIFY drifted from HDI");
static_assert(static_cast<int32_t>(ScheduleMode::ABANDON) ==
        static_cast<int32_t>(HdiScheduleMode::ABANDON),
    "ScheduleMode::ABANDON drifted from HDI");

// PinSubType — common named values. PIN_MIX/PIN_MIXED and PATTERN/PIN_PATTERN
// differ in name only and are asserted pairwise below.
static_assert(static_cast<int32_t>(PinSubType::PIN_SIX) ==
        static_cast<int32_t>(HdiPinSubType::PIN_SIX),
    "PinSubType::PIN_SIX drifted from HDI");
static_assert(static_cast<int32_t>(PinSubType::PIN_NUMBER) ==
        static_cast<int32_t>(HdiPinSubType::PIN_NUMBER),
    "PinSubType::PIN_NUMBER drifted from HDI");
static_assert(static_cast<int32_t>(PinSubType::PIN_FOUR) ==
        static_cast<int32_t>(HdiPinSubType::PIN_FOUR),
    "PinSubType::PIN_FOUR drifted from HDI");
static_assert(static_cast<int32_t>(PinSubType::PIN_QUESTION) ==
        static_cast<int32_t>(HdiPinSubType::PIN_QUESTION),
    "PinSubType::PIN_QUESTION drifted from HDI");
// Differently-named but value-identical pairs.
static_assert(static_cast<int32_t>(PinSubType::PIN_MIXED) ==
        static_cast<int32_t>(HdiPinSubType::PIN_MIX),
    "PinSubType::PIN_MIXED must match HDI PinSubType::PIN_MIX");
static_assert(static_cast<int32_t>(PinSubType::PIN_PATTERN) ==
        static_cast<int32_t>(HdiPinSubType::PATTERN),
    "PinSubType::PIN_PATTERN must match HDI PinSubType::PATTERN");

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // HDI_TYPE_CONVERT_H
