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

#include "user_auth_stub_fuzzer.h"

#include <cinttypes>
#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "user_auth_service.h"

#define LOG_TAG "USER_AUTH_SA"

using namespace std;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t USER_AUTH_CODE_MIN = 0;
constexpr uint32_t USER_AUTH_CODE_MAX = 17;
const std::u16string USER_AUTH_INTERFACE_TOKEN = u"ohos.UserIam.UserAuth.IUserAuth";

bool UserAuthStubFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        return false;
    }

    auto service = UserAuthService::GetInstance();
    for (uint32_t code = USER_AUTH_CODE_MIN; code < USER_AUTH_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(USER_AUTH_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)service->OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(USER_AUTH_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)service->OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::UserIam::UserAuth::UserAuthStubFuzzTest(data, size);
    return 0;
}
