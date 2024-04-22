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

#include "executor_callback_stub_fuzzer.h"

#include "parcel.h"

#include "co_auth_client.h"
#include "executor_callback_service.h"
#include "executor_messenger_client.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t EXECUTOR_CALLBACK_CODE_MIN = 1;
constexpr uint32_t EXECUTOR_CALLBACK_CODE_MAX = 6;
const std::u16string EXECUTOR_CALLBACK_INTERFACE_TOKEN = u"ohos.UserIam.AuthResPool.ExecutorCallback";

class DummyExecutorRegisterCallback final : public ExecutorRegisterCallback {
public:
    void OnMessengerReady(uint64_t executorIndex, const std::shared_ptr<ExecutorMessenger> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIds)
    {
        IAM_LOGI("start");
        static_cast<void>(executorIndex);
        static_cast<void>(messenger);
        static_cast<void>(publicKey);
        static_cast<void>(templateIds);
    }

    int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &commandAttrs)
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(publicKey);
        static_cast<void>(commandAttrs);
        return SUCCESS;
    }

    int32_t OnEndExecute(uint64_t scheduleId, const Attributes &commandAttrs)
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(commandAttrs);
        return SUCCESS;
    }

    int32_t OnSetProperty(const Attributes &properties)
    {
        IAM_LOGI("start");
        static_cast<void>(properties);
        return SUCCESS;
    }

    int32_t OnGetProperty(const Attributes &conditions, Attributes &results)
    {
        IAM_LOGI("start");
        static_cast<void>(conditions);
        static_cast<void>(results);
        return SUCCESS;
    }

    int32_t OnSendData(uint64_t scheduleId, const Attributes &data)
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(data);
        return SUCCESS;
    }
};

auto g_ExecutorCallbackService =
    Common::MakeShared<ExecutorCallbackService>(Common::MakeShared<DummyExecutorRegisterCallback>());

bool ExecutorCallbackStubFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        return false;
    }

    for (uint32_t code = EXECUTOR_CALLBACK_CODE_MIN; code < EXECUTOR_CALLBACK_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(EXECUTOR_CALLBACK_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)g_ExecutorCallbackService->OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(EXECUTOR_CALLBACK_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)g_ExecutorCallbackService->OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::ExecutorCallbackStubFuzzTest(data, size);
    return 0;
}
