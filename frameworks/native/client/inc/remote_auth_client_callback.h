/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef REMOTE_AUTH_CLIENT_CALLBACK_H
#define REMOTE_AUTH_CLIENT_CALLBACK_H

#include <string>

#include "attributes.h"
#include "set_widget_param_callback.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RemoteAuthClientCallback {
public:
    /**
     * @brief The callback return remote auth widget param.
     *
     * @param challenge Auth challenge which can prevent replay attacks.
     * @param callback Callback to set widget param.
     */
    virtual void OnGetRemoteAuthWidgetParam(const std::vector<uint8_t> &challenge,
        const std::shared_ptr<SetWidgetParamClientCallback> &callback)  = 0;

    /**
     * @brief The callback return remote auth result.
     *
     * @param challenge Auth challenge which can prevent replay attacks.
     * @param result The result success or error code{@link ResultCode}.
     * @param extraInfo Other related information about remote auth.
     */
    virtual void OnRemoteAuthResult(const std::vector<uint8_t> &challenge, int32_t result,
        const Attributes &extraInfo)  = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif //REMOTE_AUTH_CLIENT_CALLBACK_H