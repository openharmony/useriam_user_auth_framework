/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "useridm_callback_test.h"

#include "iam_logger.h"

#define LOG_LABEL UserIAM::Common::LABEL_USER_IDM_SDK

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
using namespace OHOS::UserIam::UserAuth;
void GetInfoCallbackUT::OnGetInfo(std::vector<CredentialInfo> &info)
{
    IAM_LOGI("GetInfoCallbackUT OnGetInfo");
    return;
}

void GetSecInfoCallbackUT::OnGetSecInfo(SecInfo &info)
{
    IAM_LOGI("GetSecInfoCallbackUT OnGetSecInfo");
    return;
}

void IDMCallbackUT::OnResult(int32_t result, RequestResult reqRet)
{
    IAM_LOGI("IDMCallbackUT OnResult");
    return;
}

void IDMCallbackUT::OnAcquireInfo(int32_t module, int32_t acquire, RequestResult reqRet)
{
    IAM_LOGI("IDMCallbackUT OnAcquireInfo");
    return;
}
}  // namespace UserIDM
}  // namespace UserIAM
}  // namespace OHOS

