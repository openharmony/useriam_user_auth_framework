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

#include "user_auth_engine.h"

// userauth_engine_api is an inner_kit static library that exposes the engine
// interface headers to user_auth_framework_ext, so it can implement
// IUserAuthEngine (TEE engine). The engine surface is header-only (pure-virtual
// interface plus DTO structs; GetUserAuthEngine() is link-time replaced), so
// this TU exists only to give the inner_kit a binary artifact. Compiling it
// also validates that the full public header dependency chain resolves.
namespace OHOS {
namespace UserIam {
namespace UserAuth {
extern "C" const char *UserAuthEngineApiVersion()
{
    return "1.0";
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
