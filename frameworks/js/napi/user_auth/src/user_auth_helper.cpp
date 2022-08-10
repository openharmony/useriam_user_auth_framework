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

#include "user_auth_helper.h"

#include <cinttypes>

#include "iam_logger.h"

#include "user_auth_impl.h"

#define LOG_LABEL UserIam::Common::LABEL_USER_AUTH_NAPI

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::UserIam::UserAuth;
napi_value UserAuthServiceConstructor(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    std::unique_ptr<UserAuthImpl> userAuthImpl {new (std::nothrow) UserAuthImpl()};
    if (userAuthImpl == nullptr) {
        IAM_LOGE("userAuthImpl is nullptr");
        return nullptr;
    }

    napi_value thisVar = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    NAPI_CALL(env, napi_wrap(env, thisVar, userAuthImpl.get(),
        [](napi_env env, void *data, void *hint) {
            UserAuthImpl *userAuthImpl = static_cast<UserAuthImpl *>(data);
            if (userAuthImpl != nullptr) {
                delete userAuthImpl;
            }
        },
        nullptr, nullptr));
    userAuthImpl.release();
    return thisVar;
}

napi_value GetVersion(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value thisVar = nullptr;
    size_t argcAsync = 0;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    UserAuthImpl *userAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(&userAuthImpl)));
    if (userAuthImpl == nullptr) {
        IAM_LOGE("userAuthImpl is nullptr");
        return nullptr;
    }
    return userAuthImpl->GetVersion(env, info);
}

napi_value GetAvailableStatus(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value thisVar = nullptr;
    size_t argcAsync = 0;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    UserAuthImpl *userAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(&userAuthImpl)));
    if (userAuthImpl == nullptr) {
        IAM_LOGE("userAuthImpl is nullptr");
        return nullptr;
    }
    return userAuthImpl->GetAvailableStatus(env, info);
}

napi_value Auth(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value thisVar = nullptr;
    size_t argcAsync = 0;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    UserAuthImpl *userAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(&userAuthImpl)));
    if (userAuthImpl == nullptr) {
        IAM_LOGE("userAuthImpl is nullptr");
        return nullptr;
    }
    return userAuthImpl->Auth(env, info);
}

napi_value Execute(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value thisVar = nullptr;
    size_t argcAsync = 0;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    UserAuthImpl *userAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(&userAuthImpl)));
    if (userAuthImpl == nullptr) {
        IAM_LOGE("userAuthImpl is nullptr");
        return nullptr;
    }
    return userAuthImpl->Execute(env, info);
}

napi_value CancelAuth(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value thisVar = nullptr;
    size_t argcAsync = 0;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisVar, nullptr));
    UserAuthImpl *userAuthImpl = nullptr;
    NAPI_CALL(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(&userAuthImpl)));
    if (userAuthImpl == nullptr) {
        IAM_LOGE("userAuthImpl is nullptr");
        return nullptr;
    }
    return userAuthImpl->CancelAuth(env, info);
}

napi_value AuthTrustLevelConstructor(napi_env env)
{
    napi_value authTrustLevel = nullptr;
    napi_value atl1 = nullptr;
    napi_value atl2 = nullptr;
    napi_value atl3 = nullptr;
    napi_value atl4 = nullptr;
    NAPI_CALL(env, napi_create_object(env, &authTrustLevel));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthTrustLevel::ATL1), &atl1));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthTrustLevel::ATL2), &atl2));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthTrustLevel::ATL3), &atl3));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthTrustLevel::ATL4), &atl4));
    NAPI_CALL(env, napi_set_named_property(env, authTrustLevel, "ATL1", atl1));
    NAPI_CALL(env, napi_set_named_property(env, authTrustLevel, "ATL2", atl2));
    NAPI_CALL(env, napi_set_named_property(env, authTrustLevel, "ATL3", atl3));
    NAPI_CALL(env, napi_set_named_property(env, authTrustLevel, "ATL4", atl4));
    return authTrustLevel;
}

napi_value ResultCodeConstructor(napi_env env)
{
    napi_value resultCode = nullptr;
    napi_value success = nullptr;
    napi_value fail = nullptr;
    napi_value generalError = nullptr;
    napi_value canceled = nullptr;
    napi_value timeout = nullptr;
    napi_value typeNotSupport = nullptr;
    napi_value trustLevelNotSupport = nullptr;
    napi_value busy = nullptr;
    napi_value invalidParameters = nullptr;
    napi_value locked = nullptr;
    napi_value notEnrolled = nullptr;
    NAPI_CALL(env, napi_create_object(env, &resultCode));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::SUCCESS, &success));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::FAIL, &fail));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::GENERAL_ERROR, &generalError));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::CANCELED, &canceled));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::TIMEOUT, &timeout));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::TYPE_NOT_SUPPORT, &typeNotSupport));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::TRUST_LEVEL_NOT_SUPPORT, &trustLevelNotSupport));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::BUSY, &busy));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::INVALID_PARAMETERS, &invalidParameters));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::LOCKED, &locked));
    NAPI_CALL(env, napi_create_int32(env, ResultCode::NOT_ENROLLED, &notEnrolled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "SUCCESS", success));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "FAIL", fail));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "GENERAL_ERROR", generalError));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "CANCELED", canceled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TIMEOUT", timeout));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TYPE_NOT_SUPPORT", typeNotSupport));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TRUST_LEVEL_NOT_SUPPORT", trustLevelNotSupport));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "BUSY", busy));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "INVALID_PARAMETERS", invalidParameters));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "LOCKED", locked));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "NOT_ENROLLED", notEnrolled));
    return resultCode;
}

napi_value AuthenticationResultConstructor(napi_env env)
{
    napi_value resultCode = nullptr;
    napi_value no_support = nullptr;
    napi_value success = nullptr;
    napi_value compare_failure = nullptr;
    napi_value canceled = nullptr;
    napi_value timeout = nullptr;
    napi_value camera_fail = nullptr;
    napi_value busy = nullptr;
    napi_value invalid_parameters = nullptr;
    napi_value locked = nullptr;
    napi_value not_enrolled = nullptr;
    napi_value general_error = nullptr;
    NAPI_CALL(env, napi_create_object(env, &resultCode));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::NO_SUPPORT), &no_support));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::SUCCESS), &success));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::COMPARE_FAILURE),
        &compare_failure));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::CANCELED), &canceled));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::TIMEOUT), &timeout));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::CAMERA_FAIL), &camera_fail));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::BUSY), &busy));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::INVALID_PARAMETERS),
        &invalid_parameters));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::LOCKED), &locked));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::NOT_ENROLLED), &not_enrolled));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AuthenticationResult::GENERAL_ERROR), &general_error));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "NO_SUPPORT", no_support));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "SUCCESS", success));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "COMPARE_FAILURE", compare_failure));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "CANCELED", canceled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "TIMEOUT", timeout));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "CAMERA_FAIL", camera_fail));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "BUSY", busy));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "INVALID_PARAMETERS", invalid_parameters));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "LOCKED", locked));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "NOT_ENROLLED", not_enrolled));
    NAPI_CALL(env, napi_set_named_property(env, resultCode, "GENERAL_ERROR", general_error));
    return resultCode;
}

napi_value FaceTipsCodeConstructor(napi_env env)
{
    napi_value faceTipsCode = nullptr;
    napi_value faceAuthTipTooBright = nullptr;
    napi_value faceAuthTipTooDark = nullptr;
    napi_value faceAuthTipTooClose = nullptr;
    napi_value faceAuthTipTooFar = nullptr;
    napi_value faceAuthTipTooHigh = nullptr;
    napi_value faceAuthTipTooLow = nullptr;
    napi_value faceAuthTipTooRight = nullptr;
    napi_value faceAuthTipTooLeft = nullptr;
    napi_value faceAuthTipTooMuchMotion = nullptr;
    napi_value faceAuthTipPoorGaze = nullptr;
    napi_value faceAuthTipNotDetected = nullptr;
    NAPI_CALL(env, napi_create_object(env, &faceTipsCode));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_BRIGHT, &faceAuthTipTooBright));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_DARK, &faceAuthTipTooDark));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_CLOSE, &faceAuthTipTooClose));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_FAR, &faceAuthTipTooFar));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_HIGH, &faceAuthTipTooHigh));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_LOW, &faceAuthTipTooLow));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_RIGHT, &faceAuthTipTooRight));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_LEFT, &faceAuthTipTooLeft));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_TOO_MUCH_MOTION, &faceAuthTipTooMuchMotion));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_POOR_GAZE, &faceAuthTipPoorGaze));
    NAPI_CALL(env, napi_create_int32(env, FaceTipsCode::FACE_AUTH_TIP_NOT_DETECTED, &faceAuthTipNotDetected));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_BRIGHT", faceAuthTipTooBright));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_DARK", faceAuthTipTooDark));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_CLOSE", faceAuthTipTooClose));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_FAR", faceAuthTipTooFar));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_HIGH", faceAuthTipTooHigh));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_LOW", faceAuthTipTooLow));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_RIGHT", faceAuthTipTooRight));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_TOO_LEFT", faceAuthTipTooLeft));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode,
        "FACE_AUTH_TIP_TOO_MUCH_MOTION", faceAuthTipTooMuchMotion));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_POOR_GAZE", faceAuthTipPoorGaze));
    NAPI_CALL(env, napi_set_named_property(env, faceTipsCode, "FACE_AUTH_TIP_NOT_DETECTED", faceAuthTipNotDetected));
    return faceTipsCode;
}

napi_value FingerprintTipsConstructorForKits(napi_env env)
{
    napi_value fingerprintTips = nullptr;
    napi_value fingerprintTipGood = nullptr;
    napi_value fingerprintTipImagerDirty = nullptr;
    napi_value fingerprintTipInsufficient = nullptr;
    napi_value fingerprintTipPartial = nullptr;
    napi_value fingerprintTipTooFast = nullptr;
    napi_value fingerprintTipTooSlow = nullptr;
    NAPI_CALL(env, napi_create_object(env, &fingerprintTips));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_GOOD, &fingerprintTipGood));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_IMAGER_DIRTY,
        &fingerprintTipImagerDirty));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_INSUFFICIENT,
        &fingerprintTipInsufficient));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_PARTIAL, &fingerprintTipPartial));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_TOO_FAST, &fingerprintTipTooFast));
    NAPI_CALL(env, napi_create_int32(env, FingerprintTips::FINGERPRINT_AUTH_TIP_TOO_SLOW, &fingerprintTipTooSlow));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips, "FINGERPRINT_AUTH_TIP_GOOD", fingerprintTipGood));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_AUTH_TIP_DIRTY", fingerprintTipImagerDirty));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_AUTH_TIP_INSUFFICIENT", fingerprintTipInsufficient));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_AUTH_TIP_PARTIAL", fingerprintTipPartial));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_AUTH_TIP_TOO_FAST", fingerprintTipTooFast));
    NAPI_CALL(env, napi_set_named_property(env, fingerprintTips,
        "FINGERPRINT_AUTH_TIP_TOO_SLOW", fingerprintTipTooSlow));
    return fingerprintTips;
}

napi_value UserAuthTypeConstructor(napi_env env)
{
    napi_value userAuthType = nullptr;
    napi_value face = nullptr;
    napi_value fingerprint = nullptr;
    NAPI_CALL(env, napi_create_object(env, &userAuthType));
    NAPI_CALL(env, napi_create_int32(env, AuthType::FACE, &face));
    NAPI_CALL(env, napi_create_int32(env, AuthType::FINGERPRINT, &fingerprint));
    NAPI_CALL(env, napi_set_named_property(env, userAuthType, "FACE", face));
    NAPI_CALL(env, napi_set_named_property(env, userAuthType, "FINGERPRINT", fingerprint));
    return userAuthType;
}

napi_value UserAuthInit(napi_env env, napi_value exports)
{
    IAM_LOGI("start");
    napi_status status;
    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_FUNCTION("getAuthenticator", UserAuth::ConstructorForAPI6),
    };
    status = napi_define_properties(env, exports,
        sizeof(exportFuncs) / sizeof(napi_property_descriptor), exportFuncs);
    if (status != napi_ok) {
        IAM_LOGE("napi_define_properties failed");
    }
    status = napi_set_named_property(env, exports, "UserAuth", GetCtor(env));
    if (status != napi_ok) {
        IAM_LOGE("napi_set_named_property failed");
    }
    return exports;
}

napi_value EnumExport(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_PROPERTY("AuthTrustLevel", AuthTrustLevelConstructor(env)),
        DECLARE_NAPI_PROPERTY("ResultCode", ResultCodeConstructor(env)),
        DECLARE_NAPI_PROPERTY("FingerprintTips", FingerprintTipsConstructorForKits(env)),
        DECLARE_NAPI_PROPERTY("UserAuthType", UserAuthTypeConstructor(env)),
        DECLARE_NAPI_PROPERTY("FaceTips", FaceTipsCodeConstructor(env)),
        DECLARE_NAPI_PROPERTY("AuthenticationResult", AuthenticationResultConstructor(env)),
    };
    napi_define_properties(env, exports, sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors);
    return exports;
}

napi_value ConstructorForAPI6(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_value userAuthForAPI6 = nullptr;
    NAPI_CALL(env, napi_new_instance(env, GetCtorForAPI6(env), 0, nullptr, &userAuthForAPI6));
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));
    return userAuthForAPI6;
}

napi_value GetCtor(napi_env env)
{
    IAM_LOGI("start");
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("getVersion", UserAuth::GetVersion),
        DECLARE_NAPI_FUNCTION("getAvailableStatus", UserAuth::GetAvailableStatus),
        DECLARE_NAPI_FUNCTION("auth", UserAuth::Auth),
        DECLARE_NAPI_FUNCTION("cancelAuth", UserAuth::CancelAuth),
    };
    NAPI_CALL(env, napi_define_class(env, "UserAuth", NAPI_AUTO_LENGTH, UserAuthServiceConstructor, nullptr,
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    return cons;
}

napi_value GetCtorForAPI6(napi_env env)
{
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("execute", UserAuth::Execute),
    };
    NAPI_CALL(env, napi_define_class(env, "UserAuth", NAPI_AUTO_LENGTH, UserAuthServiceConstructor, nullptr,
        sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    return cons;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
