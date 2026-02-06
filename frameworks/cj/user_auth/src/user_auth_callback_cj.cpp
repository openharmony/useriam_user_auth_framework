/*
* Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "user_auth_ffi.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#define LOG_TAG "USER_AUTH_NAPI"


using namespace OHOS::UserIam::UserAuth;

void CjUserAuthCallback::OnAcquireInfo(const int32_t module, const uint32_t acquireInfo, const Attributes &extraInfo)
{
    (void) module;
    (void) acquireInfo;
    (void) extraInfo;
}

void CjUserAuthCallback::OnResult(const int32_t result, const Attributes &extraInfo)
{   
   IAM_LOGI("OnResult: start");
   if (this->onResult_ == nullptr) {
        return;
    }

    std::vector<uint8_t> token;
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
    int32_t authType{0};
    extraInfo.GetInt32Value(Attributes::ATTR_AUTH_TYPE, authType);

    // 创建 token 的堆拷贝，避免悬空指针
    uint8_t* tokenCopy = nullptr;
    int64_t tokenLen = static_cast<int64_t>(token.size());
    IAM_LOGI("OnResult: token size=%ld, preparing heap copy", tokenLen);
    
    if (tokenLen > 0) {
        tokenCopy = new uint8_t[tokenLen];
        std::copy(token.begin(), token.end(), tokenCopy);
        IAM_LOGI("OnResult: token copied to heap, address=%p", tokenCopy);
    } else {
        IAM_LOGI("OnResult: token is empty, no heap allocation");
    }

    CjUserAuthResult ret = {
        .result = result,
        .token = tokenCopy,  // 使用堆拷贝
        .tokenLen = tokenLen,
        .authType = static_cast<uint32_t>(authType),
    };

    extraInfo.GetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, ret.credentialDigest);
    extraInfo.GetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT, ret.credentialCount);

    IAM_LOGI("OnResult: before calling onResult_, result=%d, tokenLen=%ld, token=%p", 
             ret.result, ret.tokenLen, ret.token);
    this->onResult_(ret);
    IAM_LOGI("OnResult: after calling onResult_, about to delete tokenCopy=%p", tokenCopy);
    
    // 仓颉侧已经拷贝完数据，释放堆内存
    if (tokenCopy != nullptr) {
        delete[] tokenCopy;
        IAM_LOGI("OnResult: tokenCopy deleted successfully");
    }
}
