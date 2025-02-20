/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "modal_callback_stub_fuzzer.h"

#include "parcel.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "modal_callback_service.h"

#define LOG_TAG "USER_AUTH_SA"

using namespace std;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t MODAL_CALLBACK_CODE_MIN = 0;
constexpr uint32_t MODAL_CALLBACK_CODE_MAX = 100;
const std::u16string MODAL_CALLBACK_INTERFACE_TOKEN = u"ohos.UserIam.UserAuth.ModalCallback";

class DummyUserAuthModalClientCallback final : public UserAuthModalClientCallback {
public:
    void SendCommand(uint64_t contextId, const std::string &cmdData)
    {
        IAM_LOGI("start");
        static_cast<void>(contextId);
        static_cast<void>(cmdData);
    }
    bool IsModalInit()
    {
        IAM_LOGI("start");
        return false;
    }
    bool IsModalDestroy()
    {
        IAM_LOGI("start");
        return false;
    }

private:
    void CancelAuthentication(uint64_t contextId, int32_t cancelReason)
    {
        IAM_LOGI("start");
        static_cast<void>(contextId);
        static_cast<void>(cancelReason);
    }
};

bool ModalCallbackStubFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        return false;
    }

    auto service =
        Common::MakeShared<ModalCallbackService>(Common::MakeShared<DummyUserAuthModalClientCallback>());
    for (uint32_t code = MODAL_CALLBACK_CODE_MIN; code < MODAL_CALLBACK_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(MODAL_CALLBACK_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)service->OnRemoteRequest(code, data, reply, optionSync);
        // Async
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
    OHOS::UserIam::UserAuth::ModalCallbackStubFuzzTest(data, size);
    return 0;
}
