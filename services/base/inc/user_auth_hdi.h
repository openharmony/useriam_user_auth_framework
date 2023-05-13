/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_HDI
#define USER_AUTH_HDI

#include "v1_0/user_auth_types.h"
#include "v1_1/iuser_auth_interface.h"
#include "v1_1/user_auth_types.h"
#include "v1_1/user_auth_interface_service.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using IUserAuthInterface = OHOS::HDI::UserAuth::V1_1::IUserAuthInterface;

using HdiAuthType = OHOS::HDI::UserAuth::V1_0::AuthType;
using HdiExecutorRole = OHOS::HDI::UserAuth::V1_0::ExecutorRole;
using HdiExecutorSecureLevel = OHOS::HDI::UserAuth::V1_0::ExecutorSecureLevel;
using HdiPinSubType = OHOS::HDI::UserAuth::V1_0::PinSubType;
using HdiScheduleMode = OHOS::HDI::UserAuth::V1_0::ScheduleMode;
using HdiExecutorRegisterInfo = OHOS::HDI::UserAuth::V1_0::ExecutorRegisterInfo;
using HdiExecutorInfo = OHOS::HDI::UserAuth::V1_0::ExecutorInfo;
using HdiScheduleInfoV1_0 = OHOS::HDI::UserAuth::V1_1::ScheduleInfo;
using HdiScheduleInfo = OHOS::HDI::UserAuth::V1_1::ScheduleInfoV1_1;
using HdiAuthSolution = OHOS::HDI::UserAuth::V1_0::AuthSolution;
using HdiExecutorSendMsg = OHOS::HDI::UserAuth::V1_0::ExecutorSendMsg;
using HdiAuthResultInfo = OHOS::HDI::UserAuth::V1_0::AuthResultInfo;
using HdiIdentifyResultInfo = OHOS::HDI::UserAuth::V1_0::IdentifyResultInfo;
using HdiEnrollParam = OHOS::HDI::UserAuth::V1_0::EnrollParam;
using HdiCredentialInfo = OHOS::HDI::UserAuth::V1_0::CredentialInfo;
using HdiEnrolledInfo = OHOS::HDI::UserAuth::V1_0::EnrolledInfo;
using HdiEnrollResultInfo = OHOS::HDI::UserAuth::V1_0::EnrollResultInfo;

using ScheduleInfoV1_1 = OHOS::HDI::UserAuth::V1_1::ScheduleInfoV1_1;
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // USER_AUTH_HDI