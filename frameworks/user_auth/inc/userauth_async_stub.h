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

#ifndef USERAUTH_ASYNC_STUB_H
#define USERAUTH_ASYNC_STUB_H

#include <iremote_stub.h>
#include <nocopyable.h>
#include "iuserauth_callback.h"
#include "userauth_callback.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class UserAuthAsyncStub : public IRemoteStub<IUserAuthCallback> {
public:
    DISALLOW_COPY_AND_MOVE(UserAuthAsyncStub);
    explicit UserAuthAsyncStub(std::shared_ptr<UserAuthCallback>& impl);
    explicit UserAuthAsyncStub(std::shared_ptr<SetPropCallback>& impl);
    explicit UserAuthAsyncStub(std::shared_ptr<GetPropCallback>& impl);
    ~UserAuthAsyncStub() override = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo) override;
    void onResult(const int32_t result, const AuthResult &extraInfo) override;
    void onExecutorPropertyInfo(const ExecutorProperty &result) override;
    void onSetExecutorProperty(const int32_t result) override;

private:
    int32_t onAcquireInfoStub(MessageParcel& data, MessageParcel& reply);
    int32_t onResultStub(MessageParcel& data, MessageParcel& reply);
    int32_t onExecutorPropertyInfoStub(MessageParcel& data, MessageParcel& reply);
    int32_t onSetExecutorPropertyStub(MessageParcel& data, MessageParcel& reply);
    std::shared_ptr<UserAuthCallback> authCallback_ {nullptr};
    std::shared_ptr<SetPropCallback> setPropCallback_ {nullptr};
    std::shared_ptr<GetPropCallback> getPropCallback_ {nullptr};
};
}  // namespace UserAuth
}  // namespace UserIAM
}  // namespace OHOS

#endif // USERAUTH_ASYNC_STUB_H
