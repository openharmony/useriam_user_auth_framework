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

#ifndef CO_AUTH_INFO_DEFINE_H
#define CO_AUTH_INFO_DEFINE_H

#include "co_auth_defines.h"
#include "parcel.h"

namespace OHOS {
namespace UserIAM {
enum AuthAbility {
    /* Executor authentication ability six number pin */
    PIN_SIX = 1,
    /* Executor authentication ability self defined number pin */
    PIN_NUMBER = 2,
    /* Executor authentication ability mixed pin */
    PIN_MIXED = 4,
    /* Executor authentication ability 2D face */
    FACE_2D = 1,
    /* Executor authentication ability 3D face */
    FACE_3D = 2
};

enum ExecutorType {
    /* Type of coauth */
    TYPE_CO_AUTH = 0,
    /* Type of executor collector */
    TYPE_COLLECTOR = 1,
    /* Type of executor verifier */
    TYPE_VERIFIER = 2,
    /* Type of executor all in one */
    TYPE_ALL_IN_ONE = 3
};
} // namespace UserIAM
} // namespace OHOS
#endif // CO_AUTH_INFO_DEFINE_H
