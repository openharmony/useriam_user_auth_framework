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

#ifndef IPC_COMMON_H
#define IPC_COMMON_H

#include <cinttypes>
#include <iremote_stub.h>
#include <optional>
#include <string>

#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class IpcCommon final : public NoCopyable {
public:
    static int32_t GetCallingUserId(IPCObjectStub &stub, std::optional<int32_t> &userId);
    static int32_t GetActiveAccountId(std::optional<int32_t> &userId);
    static bool CheckPermission(IPCObjectStub &stub, const std::string &permission);
private:
    static uint32_t GetTokenId(IPCObjectStub &stub);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IPC_COMMON_H