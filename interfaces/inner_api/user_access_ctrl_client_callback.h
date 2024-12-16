/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

/**
 * @file user_access_ctrl_client_callback.h
 *
 * @brief Callback definitions returned by user auth client.
 * @since 5.1
 * @version 1.0
 */

#ifndef USER_ACCESS_CTRL_CLIENT_CALLBACK_H
#define USER_ACCESS_CTRL_CLIENT_CALLBACK_H

#include "attributes.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class VerifyTokenCallback {
public:
    /**
     * @brief The callback return verify token result.
     *
     * @param result The result success or error code{@link ResultCode}.
     * @param extraInfo Other related information about verify token.
     */
    virtual void OnResult(int32_t result, const Attributes &extraInfo) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_ACCESS_CTRL_CLIENT_CALLBACK_H