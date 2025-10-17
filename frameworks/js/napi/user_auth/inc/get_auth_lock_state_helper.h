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

#ifndef GET_AUTH_LOCK_STATE_HELPER_H
#define GET_AUTH_LOCK_STATE_HELPER_H

#include <atomic>
#include <future>
#include <mutex>

#include "auth_common.h"
#include "napi/native_api.h"
#include "nocopyable.h"
#include "user_auth_napi_helper.h"
#include "user_auth_client.h"
#include "user_auth_client_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace GetAuthLockStateHelper {
struct GetAuthLockStateAsyncHolder {
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    AuthType authType = AuthType(-1);
    AuthLockState authLockState = {};
    napi_status status = napi_ok;
    ResultCode resultCode = ResultCode::SUCCESS;
    std::string errMsg;
};

bool GetAuthLockStateWork(napi_env env, GetAuthLockStateAsyncHolder *asyncHolder);

bool ParseGetAuthLockStateParams(napi_env env, napi_callback_info info,
    GetAuthLockStateAsyncHolder *asyncHolder);

void GetAuthLockStateExecute(GetAuthLockStateAsyncHolder *asyncHolder);

void GetAuthLockStateComplete(napi_env env, GetAuthLockStateAsyncHolder *asyncHolder);

napi_status GetAuthLockStateCompleteInner(napi_env env, GetAuthLockStateAsyncHolder *asyncHolder,
    napi_value &authLockStateResult);
}

class GetAuthLockStateCallbackV21 : public GetPropCallback,
                                    public std::enable_shared_from_this<GetAuthLockStateCallbackV21>,
                                    public NoCopyable {
public:
    GetAuthLockStateCallbackV21();
    ~GetAuthLockStateCallbackV21() override;
    void OnResult(int32_t result, const UserAuth::Attributes &extraInfo) override;
    void ProcessAuthLockStateResult(
        GetAuthLockStateHelper::GetAuthLockStateAsyncHolder *asyncHolder);
    void SetResult(ResultCode result);
    ResultCode WaitResult();

private:
    std::mutex mutex_;
    ResultCode resultCode_ = ResultCode::SUCCESS;
    AuthLockState authLockState_ = {};
    std::atomic_bool isResultSetted_{false};
    std::promise<ResultCode> promise_;
    std::shared_future<ResultCode> future_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif
