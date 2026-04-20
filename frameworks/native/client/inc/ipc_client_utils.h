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

#ifndef IPC_CLIENT_UTILS_H
#define IPC_CLIENT_UTILS_H

#include "iam_common_defines.h"
#include "iremote_object.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
constexpr uint32_t MAX_SYNC_WAIT_TIME_SEC = 4; // 4 seconds

class IpcClientUtils {
public:
    static sptr<IRemoteObject> GetRemoteObject(int32_t saId);
    static int32_t RunOnResidentSync(std::function<int32_t> func, uint32_t timeoutSec);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IPC_CLIENT_UTILS_H