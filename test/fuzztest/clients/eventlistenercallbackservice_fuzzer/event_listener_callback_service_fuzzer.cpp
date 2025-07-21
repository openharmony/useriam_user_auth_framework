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

#include "event_listener_callback_service.h"
#include "event_listener_callback_service_fuzzer.h"
#include "user_auth_client_impl.h"
#include "user_idm_client_impl.h"

#include "callback_manager.h"
#include "iam_fuzz_test.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyAuthSuccessEventListener final : public AuthSuccessEventListener {
public:
    void OnNotifyAuthSuccessEvent(int32_t userId, AuthType authType, int32_t callerType,
        const std::string &callerName) override
    {
        IAM_LOGI("start");
        static_cast<void>(userId);
        static_cast<void>(authType);
        static_cast<void>(callerType);
        static_cast<void>(callerName);
    }
};

class DummyCredChangeEventListener final : public CredChangeEventListener {
public:
    void OnNotifyCredChangeEvent(int32_t userId, AuthType authType, CredChangeEventType eventType,
        const CredChangeEventInfo &changeInfo) override
    {
        IAM_LOGI("start");
        static_cast<void>(userId);
        static_cast<void>(authType);
        static_cast<void>(eventType);
        static_cast<void>(changeInfo);
    }
};

void FuzzAddUserAuthSuccessEventListener(Parcel &parcel)
{
    IAM_LOGI("begin");
    UserAuthClientImpl &impl = UserAuthClientImpl::Instance();
    auto proxy = impl.GetProxy();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(authType);
    auto listener = Common::MakeShared<DummyAuthSuccessEventListener>();
    EventListenerCallbackManager &manage = EventListenerCallbackManager::GetInstance();
    manage.AddUserAuthSuccessEventListener(proxy, authTypeList, listener);
    IAM_LOGI("end");
}

void FuzzRemoveUserAuthSuccessEventListener(Parcel &parcel)
{
    IAM_LOGI("begin");
    UserAuthClientImpl &impl = UserAuthClientImpl::Instance();
    auto proxy = impl.GetProxy();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(authType);
    auto listener = Common::MakeShared<DummyAuthSuccessEventListener>();
    EventListenerCallbackManager &manage = EventListenerCallbackManager::GetInstance();
    manage.AddUserAuthSuccessEventListener(proxy, authTypeList, listener);
    manage.RemoveUserAuthSuccessEventListener(proxy, listener);
    IAM_LOGI("end");
}

void FuzzAddCredChangeEventListener(Parcel &parcel)
{
    IAM_LOGI("begin");
    UserIdmClientImpl &impl = UserIdmClientImpl::Instance();
    auto proxy = impl.GetProxy();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(authType);
    auto listener = Common::MakeShared<DummyCredChangeEventListener>();
    EventListenerCallbackManager &manage = EventListenerCallbackManager::GetInstance();
    manage.AddCredChangeEventListener(proxy, authTypeList, listener);
    IAM_LOGI("end");
}

void FuzzRemoveCredChangeEventListener(Parcel &parcel)
{
    IAM_LOGI("begin");
    UserIdmClientImpl &impl = UserIdmClientImpl::Instance();
    auto proxy = impl.GetProxy();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(authType);
    auto listener = Common::MakeShared<DummyCredChangeEventListener>();
    EventListenerCallbackManager &manage = EventListenerCallbackManager::GetInstance();
    manage.AddCredChangeEventListener(proxy, authTypeList, listener);
    manage.RemoveCredChangeEventListener(proxy, listener);
    IAM_LOGI("end");
}

void FuzzOnServiceDeath(Parcel &parcel)
{
    IAM_LOGI("begin");
    EventListenerCallbackManager &manage = EventListenerCallbackManager::GetInstance();
    manage.OnServiceDeath();
    IAM_LOGI("end");
}

void FuzzGetAuthEventListenerSet(Parcel &parcel)
{
    IAM_LOGI("begin");
    EventListenerCallbackManager &manage = EventListenerCallbackManager::GetInstance();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    manage.GetAuthEventListenerSet(authType);

    UserAuthClientImpl &impl = UserAuthClientImpl::Instance();
    auto proxy = impl.GetProxy();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(authType);
    auto listener = Common::MakeShared<DummyAuthSuccessEventListener>();
    manage.AddUserAuthSuccessEventListener(proxy, authTypeList, listener);
    manage.GetAuthEventListenerSet(authType);
    IAM_LOGI("end");
}

void FuzzGetCredEventListenerSet(Parcel &parcel)
{
    IAM_LOGI("begin");
    EventListenerCallbackManager &manage = EventListenerCallbackManager::GetInstance();
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    manage.GetCredEventListenerSet(authType);

    UserIdmClientImpl &impl = UserIdmClientImpl::Instance();
    auto proxy = impl.GetProxy();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(authType);
    auto listener = Common::MakeShared<DummyCredChangeEventListener>();
    manage.AddCredChangeEventListener(proxy, authTypeList, listener);
    manage.GetCredEventListenerSet(authType);
    IAM_LOGI("end");
}

void FuzzOnNotifyAuthSuccessEvent(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    int32_t callerType = parcel.ReadInt32();
    std::string callerName = "";
    Common::FillFuzzString(parcel, callerName);
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    EventListenerCallbackManager &manage = EventListenerCallbackManager::GetInstance();
    auto subManage = manage.authEventListenerCallbackImpl_;
    subManage->OnNotifyAuthSuccessEvent(userId, authType, callerType, callerName);

    UserAuthClientImpl &impl = UserAuthClientImpl::Instance();
    auto proxy = impl.GetProxy();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(authType);
    auto listener = Common::MakeShared<DummyAuthSuccessEventListener>();
    manage.AddUserAuthSuccessEventListener(proxy, authTypeList, listener);
    subManage->OnNotifyAuthSuccessEvent(userId, authType, callerType, callerName);
    IAM_LOGI("end");
}

void FuzzOnNotifyCredChangeEvent(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t userId = parcel.ReadInt32();
    int32_t callerType = parcel.ReadInt32();
    IpcCredChangeEventInfo info = {};
    AuthType authType = static_cast<AuthType>(parcel.ReadInt32());
    EventListenerCallbackManager &manage = EventListenerCallbackManager::GetInstance();
    auto subManage = manage.credEventListenerCallbackImpl_;
    subManage->OnNotifyCredChangeEvent(userId, authType, callerType, info);

    UserIdmClientImpl &impl = UserIdmClientImpl::Instance();
    auto proxy = impl.GetProxy();
    std::vector<AuthType> authTypeList;
    authTypeList.emplace_back(authType);
    auto listener = Common::MakeShared<DummyCredChangeEventListener>();
    manage.AddCredChangeEventListener(proxy, authTypeList, listener);
    subManage->OnNotifyCredChangeEvent(userId, authType, callerType, info);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzAddUserAuthSuccessEventListener);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzAddUserAuthSuccessEventListener,
    FuzzRemoveUserAuthSuccessEventListener,
    FuzzAddCredChangeEventListener,
    FuzzRemoveCredChangeEventListener,
    FuzzOnServiceDeath,
    FuzzGetAuthEventListenerSet,
    FuzzGetCredEventListenerSet,
    FuzzOnNotifyAuthSuccessEvent,
    FuzzOnNotifyCredChangeEvent,
};

void EventListenerCallbackServiceFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    for (auto fuzzFunc : g_fuzzFuncs) {
        fuzzFunc(parcel);
    }
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::EventListenerCallbackServiceFuzzTest(data, size);
    return 0;
}