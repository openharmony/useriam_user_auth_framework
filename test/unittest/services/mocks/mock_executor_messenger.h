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
#ifndef IAM_MOCK_EXECUTOR_MESSENGER_H
#define IAM_MOCK_EXECUTOR_MESSENGER_H

#include <memory>

#include <gmock/gmock.h>

#include "executor_messenger_interface.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockExecutorMessenger final : public ExecutorMessengerInterface {
public:
    MOCK_METHOD0(AsObject, sptr<IRemoteObject>());
    MOCK_METHOD4(OnRemoteRequest,
        int32_t(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD5(SendData, int32_t(uint64_t scheduleId, uint64_t transNum, ExecutorRole srcRole, ExecutorRole dstRole,
                               const std::vector<uint8_t> &msg));
    MOCK_METHOD5(Finish,
        int32_t(uint64_t scheduleId, ExecutorRole srcRole, int32_t resultCode, const Attributes &finalResult));

    static std::shared_ptr<ExecutorMessengerInterface> Create()
    {
        using namespace testing;
        auto messenger = UserIAM::Common::MakeShared<MockExecutorMessenger>();
        return messenger;
    }
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_MOCK_EXECUTOR_MESSENGER_H