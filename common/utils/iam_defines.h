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

#ifndef IAM_DEFINES_H
#define IAM_DEFINES_H
namespace OHOS {
namespace UserIam {
namespace UserAuth {
const int32_t INVALID_AUTH_TYPE = -1;
#define IAM_TRY(action0, action1) \
    do {                          \
        try {                     \
            action0;              \
        } catch (...) {           \
            action1;              \
        }                         \
    } while (0)

enum OperationType : uint32_t {
    TRACE_ADD_CREDENTIAL = 0,
    TRACE_DELETE_CREDENTIAL = 1,
    TRACE_DELETE_USER = 2,
    TRACE_ENFORCE_DELETE_USER = 3,
    TRACE_UPDATE_CREDENTIAL = 4,
    TRACE_AUTH_USER = 5,
    TRACE_IDENTIFY = 6,
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_DEFINES_H