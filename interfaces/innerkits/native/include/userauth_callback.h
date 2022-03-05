/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef USERAUTH_CALLBACK_H
#define USERAUTH_CALLBACK_H

#include "userauth_info.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
class UserAuthCallback {
public:
    virtual void onAcquireInfo(const int32_t module, const uint32_t acquireInfo, const int32_t extraInfo) = 0;
    virtual void onResult(const int32_t result, const AuthResult extraInfo) = 0;
};
class GetPropCallback {
public:
    virtual void onGetProperty(const ExecutorProperty result) = 0;
};
class SetPropCallback {
public:
    virtual void onSetProperty(const int32_t result) = 0;
};
} // namespace UserAuth
} // namespace UserIAM
} // namespace OHOS
#endif // IUSERAUTH_CALLBACK_H
