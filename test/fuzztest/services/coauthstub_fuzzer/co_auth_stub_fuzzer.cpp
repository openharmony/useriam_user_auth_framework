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

#include "co_auth_stub_fuzzer.h"

#include <cinttypes>
#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "co_auth_service.h"
#include "executor_messenger_service.h"

#define LOG_TAG "USER_AUTH_SA"

using namespace std;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t CO_AUTH_CODE_MIN = 1;
constexpr uint32_t CO_AUTH_CODE_MAX = 6;
const std::u16string CO_AUTH_INTERFACE_TOKEN = u"ohos.CoAuth.ICoAuth";
constexpr uint32_t EXECUTOR_MESSENGER_CODE_MIN = 0;
constexpr uint32_t EXECUTOR_MESSENGER_CODE_MAX = 2;
const std::u16string EXECUTOR_MESSENGER_INTERFACE_TOKEN = u"ohos.UserIam.AuthResPool.IExecutor_Messenger";

bool FuzzCoAuthStub(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        return false;
    }

    CoAuthService coAuthService;
    for (uint32_t code = CO_AUTH_CODE_MIN; code < CO_AUTH_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(CO_AUTH_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)coAuthService.OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(CO_AUTH_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)coAuthService.OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}

bool FuzzExecutorMessengerStub(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        return false;
    }

    sptr<ExecutorMessengerService> executorMessengerService = ExecutorMessengerService::GetInstance();

    if (executorMessengerService == nullptr) {
        IAM_LOGE("executor messenger service is null");
        return false;
    }

    for (uint32_t code = EXECUTOR_MESSENGER_CODE_MIN; code < EXECUTOR_MESSENGER_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(EXECUTOR_MESSENGER_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)executorMessengerService->OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(EXECUTOR_MESSENGER_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)executorMessengerService->OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}

void CoAuthStubFuzzTest(const uint8_t *data, size_t size)
{
    FuzzCoAuthStub(data, size);
    FuzzExecutorMessengerStub(data, size);
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::UserIam::UserAuth::CoAuthStubFuzzTest(data, size);
    return 0;
}
