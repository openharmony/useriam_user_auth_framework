/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "js_user_auth_extension.h"

#include "ability_info.h"
#include "ability_manager_client.h"
#include "hitrace_meter.h"
#include "js_data_struct_converter.h"
#include "js_extension_common.h"
#include "js_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "js_ui_extension_content_session.h"
#include "js_ui_extension_context.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_configuration.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"
#include "ui_extension_window_command.h"

#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_NAPI"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
using namespace OHOS::UserIam::Common;
namespace {
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr static char DEFAULT_BACKGROUND_COLOR[] = "#40ffffff";
}

napi_value AttachUIExtensionContext(napi_env env, void *value, void *)
{
    IAM_LOGD("JsUserAuthExtension attachUIExtensionContext");
    if (value == nullptr) {
        IAM_LOGE("JsUserAuthExtension invalid parameter.");
        return nullptr;
    }

    auto ptr = reinterpret_cast<std::weak_ptr<UIExtensionContext> *>(value)->lock();
    if (ptr == nullptr) {
        IAM_LOGE("JsUserAuthExtension invalid context.");
        return nullptr;
    }
    napi_value objValue = JsUIExtensionContext::CreateJsUIExtensionContext(env, ptr);
    if (objValue == nullptr) {
        IAM_LOGE("JsUserAuthExtension create context error.");
        return nullptr;
    }
    std::shared_ptr<NativeReference> shellContextRef = JsRuntime::LoadSystemModuleByEngine(env,
        "application.UIExtensionContext", &objValue, ARGC_ONE);
    if (shellContextRef == nullptr) {
        IAM_LOGE("JsUserAuthExtension load context error.");
        return nullptr;
    }
    napi_value contextObjValue = shellContextRef->GetNapiValue();
    if (contextObjValue == nullptr) {
        IAM_LOGE("JsUserAuthExtension get context value error.");
        return nullptr;
    }
    napi_coerce_to_native_binding_object(env, contextObjValue, DetachCallbackFunc,
        AttachUIExtensionContext, value, nullptr);

    auto workContext = new (std::nothrow) std::weak_ptr<UIExtensionContext>(ptr);
    if (workContext == nullptr) {
        IAM_LOGE("JsUserAuthExtension create context error.");
        return nullptr;
    }
    napi_status status = napi_wrap(env, contextObjValue, workContext,
        [](napi_env env, void *data, void *) {
            IAM_LOGD("JsUserAuthExtension finalizer for weak_ptr ui extension context is called");
            delete static_cast<std::weak_ptr<UIExtensionContext> *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        IAM_LOGE("JsUserAuthExtension failed to wrap the context");
        delete workContext;
        return nullptr;
    }
    return contextObjValue;
}

bool IsMethodNative(napi_env env, napi_value value, napi_value method)
{
    if (method == nullptr) {
        return false;
    }
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, method, &valuetype);
    if (valuetype != napi_function) {
        return false;
    }
    return true;
}

JsUserAuthExtension* JsUserAuthExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    return new JsUserAuthExtension(static_cast<JsRuntime&>(*runtime));
}

JsUserAuthExtension::JsUserAuthExtension(JsRuntime& jsRuntime) : jsRuntime_(jsRuntime) {}
JsUserAuthExtension::~JsUserAuthExtension()
{
    IAM_LOGD("JsUserAuthExtension destructor.");
    auto context = GetContext();
    if (context) {
        context->Unbind();
    }

    jsRuntime_.FreeNativeReference(std::move(jsObj_));
    jsRuntime_.FreeNativeReference(std::move(shellContextRef_));
}

void JsUserAuthExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    IAM_LOGD("JsUserAuthExtension begin init");
    UserAuthExtension::Init(record, application, handler, token);
    if (Extension::abilityInfo_->srcEntrance.empty()) {
        IAM_LOGE("JsUserAuthExtension init abilityInfo srcEntrance is empty");
        return;
    }
    std::string srcPath(Extension::abilityInfo_->moduleName + "/");
    srcPath.append(Extension::abilityInfo_->srcEntrance);
    srcPath.erase(srcPath.rfind('.'));
    srcPath.append(".abc");

    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    HandleScope handleScope(jsRuntime_);
    napi_env env = jsRuntime_.GetNapiEnv();
    jsObj_ = jsRuntime_.LoadModule(
        moduleName, srcPath, abilityInfo_->hapPath, abilityInfo_->compileMode == CompileMode::ES_MODULE);
    if (jsObj_ == nullptr) {
        IAM_LOGE("JsUserAuthExtension failed to get jsObj_");
        return;
    }
    BindContext(env, jsObj_->GetNapiValue());

    SetExtensionCommon(
        JsExtensionCommon::Create(jsRuntime_, static_cast<NativeReference&>(*jsObj_), shellContextRef_));
}

void JsUserAuthExtension::BindContext(napi_env env, napi_value obj)
{
    auto context = GetContext();
    if (context == nullptr) {
        IAM_LOGE("JsUserAuthExtension failed to get context");
        return;
    }
    HILOG_DEBUG("JsUserAuthExtension create JsUIExtensionContext.");
    napi_value contextObjValue = JsUIExtensionContext::CreateJsUIExtensionContext(env, context);
    if (contextObjValue == nullptr) {
        IAM_LOGE("JsUserAuthExtension create context value error.");
        return;
    }

    shellContextRef_ = JsRuntime::LoadSystemModuleByEngine(env, "application.UIExtensionContext",
        &contextObjValue, ARGC_ONE);
    if (shellContextRef_ == nullptr) {
        IAM_LOGE("JsUserAuthExtension load context error.");
        return;
    }
    contextObjValue = shellContextRef_->GetNapiValue();
    if (contextObjValue == nullptr) {
        IAM_LOGE("JsUserAuthExtension get context value error.");
        return;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<UIExtensionContext>(context);
    if (workContext == nullptr) {
        IAM_LOGE("JsUserAuthExtension create work context error.");
        return;
    }
    napi_coerce_to_native_binding_object(env, contextObjValue, DetachCallbackFunc, AttachUIExtensionContext,
        workContext, nullptr);

    context->Bind(jsRuntime_, shellContextRef_.get());
    napi_set_named_property(env, obj, "context", contextObjValue);

    napi_status status = napi_wrap(env, contextObjValue, workContext,
        [](napi_env env, void* data, void*) {
            IAM_LOGD("JsUserAuthExtension finalizer for weak_ptr ui extension context is called");
            delete static_cast<std::weak_ptr<UIExtensionContext> *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok) {
        IAM_LOGE("JsUserAuthExtension failed to wrap the context");
        delete workContext;
    }

    IAM_LOGD("JsUserAuthExtension init end.");
}

void JsUserAuthExtension::OnStart(const AAFwk::Want &want)
{
    IAM_LOGD("JsUserAuthExtension onStart begin.");
    Extension::OnStart(want);
    HandleScope handleScope(jsRuntime_);
    napi_env env = jsRuntime_.GetNapiEnv();
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
    auto launchParam = Extension::GetLaunchParam();
    if (InsightIntentExecuteParam::IsInsightIntentExecute(want)) {
        launchParam.launchReason = AAFwk::LaunchReason::LAUNCHREASON_INSIGHT_INTENT;
    }

    napi_value argv[] = {CreateJsLaunchParam(env, launchParam), napiWant};
    CallObjectMethod("onCreate", argv, ARGC_TWO);
    IAM_LOGD("JsUserAuthExtension onStart end.");
}

void JsUserAuthExtension::OnStop()
{
    UserAuthExtension::OnStop();
    IAM_LOGD("JsUserAuthExtension onStop begin.");
    HandleScope handleScope(jsRuntime_);
    CallObjectMethod("onDestroy");
    IAM_LOGD("JsUserAuthExtension onStop end.");
}

sptr<IRemoteObject> JsUserAuthExtension::OnConnect(const AAFwk::Want &want)
{
    HandleScope handleScope(jsRuntime_);
    napi_value result = CallOnConnect(want);
    napi_env env = jsRuntime_.GetNapiEnv();
    auto remoteObj = NAPI_ohos_rpc_getNativeRemoteObject(env, result);
    if (remoteObj == nullptr) {
        IAM_LOGE("JsUserAuthExtension remoteObj is nullptr.");
    }
    IAM_LOGD("JsUserAuthExtension onConnect.");
    return remoteObj;
}

void JsUserAuthExtension::OnDisconnect(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    Extension::OnDisconnect(want);
    IAM_LOGD("JsUserAuthExtension onDisconnect begin.");
    CallOnDisconnect(want, false);
    IAM_LOGD("JsUserAuthExtension onDisconnect end.");
}

void JsUserAuthExtension::OnCommandWindow(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo,
    AAFwk::WindowCommand winCmd)
{
    if (sessionInfo == nullptr) {
        IAM_LOGE("JsUserAuthExtension sessionInfo is nullptr.");
        return;
    }
    IAM_LOGD("JsUserAuthExtension begin. persistentId: %{private}d, winCmd: %{public}d",
        sessionInfo->persistentId, winCmd);
    Extension::OnCommandWindow(want, sessionInfo, winCmd);
    switch (winCmd) {
        case AAFwk::WIN_CMD_FOREGROUND:
            ForegroundWindow(want, sessionInfo);
            break;
        case AAFwk::WIN_CMD_BACKGROUND:
            BackgroundWindow(sessionInfo);
            break;
        case AAFwk::WIN_CMD_DESTROY:
            DestroyWindow(sessionInfo);
            break;
        default:
            IAM_LOGD("JsUserAuthExtension unsupported cmd.");
            break;
    }
    auto context = GetContext();
    if (context == nullptr) {
        IAM_LOGE("JsUserAuthExtension failed to get context");
        return;
    }
    AAFwk::AbilityCommand abilityCmd;
    if (uiWindowMap_.empty()) {
        abilityCmd = AAFwk::ABILITY_CMD_DESTROY;
    } else if (foregroundWindows_.empty()) {
        abilityCmd = AAFwk::ABILITY_CMD_BACKGROUND;
    } else {
        abilityCmd = AAFwk::ABILITY_CMD_FOREGROUND;
    }
    AAFwk::AbilityManagerClient::GetInstance()->ScheduleCommandAbilityWindowDone(
        context->GetToken(), sessionInfo, winCmd, abilityCmd);
    IAM_LOGD("end.");
}

void JsUserAuthExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    Extension::OnCommand(want, restart, startId);
    IAM_LOGD("JsUserAuthExtension onCommand begin restart=%{public}s,startId=%{public}d.",
        restart ? "true" : "false", startId);
    // wrap want
    HandleScope handleScope(jsRuntime_);
    napi_env env = jsRuntime_.GetNapiEnv();
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
    // wrap startId
    napi_value napiStartId = nullptr;
    napi_create_int32(env, startId, &napiStartId);
    napi_value argv[] = {napiWant, napiStartId};
    CallObjectMethod("onRequest", argv, ARGC_TWO);
    IAM_LOGD("JsUserAuthExtension onCommand end.");
}

void JsUserAuthExtension::OnForeground(const Want &want, sptr<AAFwk::SessionInfo> sessionInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    IAM_LOGD("JsUserAuthExtension onForeground begin.");
    Extension::OnForeground(want, sessionInfo);

    ForegroundWindow(want, sessionInfo);

    HandleScope handleScope(jsRuntime_);
    CallObjectMethod("onForeground");
    IAM_LOGD("JsUserAuthExtension onForeground end.");
}

void JsUserAuthExtension::OnBackground()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    IAM_LOGD("JsUserAuthExtension onBackground begin.");
    HandleScope handleScope(jsRuntime_);
    CallObjectMethod("onBackground");
    Extension::OnBackground();
    IAM_LOGD("JsUserAuthExtension onBackground end.");
}

void JsUserAuthExtension::ForegroundWindow(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    IAM_LOGD("JsUserAuthExtension foreground begin.");
    if (sessionInfo == nullptr || sessionInfo->sessionToken == nullptr) {
        IAM_LOGE("Invalid sessionInfo.");
        return;
    }
    IAM_LOGD("JsUserAuthExtension component id: %{public}" PRId64 ".", sessionInfo->uiExtensionComponentId);
    auto componentId = sessionInfo->uiExtensionComponentId;
    if (uiWindowMap_.find(componentId) == uiWindowMap_.end()) {
        sptr<Rosen::WindowOption> option(new (std::nothrow) Rosen::WindowOption());
        if (option == nullptr) {
            IAM_LOGE("JsUserAuthExtension failed to create window option");
            return;
        }
        auto context = GetContext();
        if (context == nullptr || context->GetAbilityInfo() == nullptr) {
            IAM_LOGE("JsUserAuthExtension failed to get context");
            return;
        }
        option->SetWindowName(context->GetBundleName() + context->GetAbilityInfo()->name);
        option->SetWindowType(Rosen::WindowType::WINDOW_TYPE_UI_EXTENSION);
        option->SetWindowSessionType(Rosen::WindowSessionType::EXTENSION_SESSION);
        option->SetParentId(sessionInfo->hostWindowId);
        auto uiWindow = Rosen::Window::Create(option, GetContext(), sessionInfo->sessionToken);
        if (uiWindow == nullptr) {
            IAM_LOGE("JsUserAuthExtension create ui window error.");
            return;
        }
        uiWindow->SetBackgroundColor(DEFAULT_BACKGROUND_COLOR);
        HandleScope handleScope(jsRuntime_);
        napi_env env = jsRuntime_.GetNapiEnv();
        napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
        napi_value nativeContentSession =
            JsUIExtensionContentSession::CreateJsUIExtensionContentSession(env, sessionInfo, uiWindow);
            
        napi_ref tmpRef = nullptr;
        napi_create_reference(env, nativeContentSession, 1, &tmpRef);
        contentSessions_.emplace(componentId, reinterpret_cast<NativeReference *>(tmpRef));
        napi_value argv[] = {napiWant, nativeContentSession};
        CallObjectMethod("onSessionCreate", argv, ARGC_TWO);
        uiWindowMap_[componentId] = uiWindow;
    }
    auto& uiWindow = uiWindowMap_[componentId];
    if (uiWindow) {
        uiWindow->Show();
        foregroundWindows_.emplace(componentId);
    }
    IAM_LOGD("JsUserAuthExtension foreground end.");
}

void JsUserAuthExtension::BackgroundWindow(const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    IAM_LOGD("JsUserAuthExtension background begin.");
    if (sessionInfo == nullptr || sessionInfo->sessionToken == nullptr) {
        IAM_LOGE("Invalid sessionInfo.");
        return;
    }
    IAM_LOGD("JsUserAuthExtension component id: %{public}" PRId64 ".", sessionInfo->uiExtensionComponentId);
    auto componentId = sessionInfo->uiExtensionComponentId;
    if (uiWindowMap_.find(componentId) == uiWindowMap_.end()) {
        IAM_LOGE("JsUserAuthExtension fail to find uiWindow");
        return;
    }
    auto& uiWindow = uiWindowMap_[componentId];
    if (uiWindow) {
        uiWindow->Hide();
        foregroundWindows_.erase(componentId);
    }
    IAM_LOGD("JsUserAuthExtension background end.");
}

void JsUserAuthExtension::DestroyWindow(const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    IAM_LOGD("JsUserAuthExtension destroy begin.");
    if (sessionInfo == nullptr || sessionInfo->sessionToken == nullptr) {
        IAM_LOGE("JsUserAuthExtension invalid sessionInfo.");
        return;
    }
    IAM_LOGD("JsUserAuthExtension component id: %{public}" PRId64 ".", sessionInfo->uiExtensionComponentId);
    auto componentId = sessionInfo->uiExtensionComponentId;
    if (uiWindowMap_.find(componentId) == uiWindowMap_.end()) {
        IAM_LOGE("JsUserAuthExtension fail to find uiWindow");
        return;
    }
    if (contentSessions_.find(componentId) != contentSessions_.end() && contentSessions_[componentId] != nullptr) {
        HandleScope handleScope(jsRuntime_);
        napi_value argv[] = {contentSessions_[componentId]->GetNapiValue()};
        CallObjectMethod("onSessionDestroy", argv, ARGC_ONE);
    }
    auto& uiWindow = uiWindowMap_[componentId];
    if (uiWindow) {
        uiWindow->Destroy();
    }
    uiWindowMap_.erase(componentId);
    foregroundWindows_.erase(componentId);
    contentSessions_.erase(componentId);
    IAM_LOGD("JsUserAuthExtension destroy end.");
}

napi_value JsUserAuthExtension::CallObjectMethod(const char *name, const napi_value *argv, size_t argc)
{
    IAM_LOGD("JsUserAuthExtension call funcation %{public}s begin", name);

    if (!jsObj_) {
        IAM_LOGE("JsUserAuthExtension not found UIExtension.js");
        return nullptr;
    }

    napi_env env = jsRuntime_.GetNapiEnv();

    napi_value value = jsObj_->GetNapiValue();
    if (value == nullptr) {
        HILOG_ERROR("JsUserAuthExtension failed to get UserAuthExtension object");
        return nullptr;
    }

    napi_value method = nullptr;
    napi_get_named_property(env, value, name, &method);
    if (!IsMethodNative(env, value, method)) {
        IAM_LOGE("JsUserAuthExtension failed to get %{public}s from UIExtension object", name);
        return nullptr;
    }
    IAM_LOGD("JsUserAuthExtension call funcation %{public}s success", name);

    napi_value callFunctionResult = nullptr;
    if (napi_call_function(env, value, method, argc, argv, &callFunctionResult) != napi_ok) {
        IAM_LOGE("JsUserAuthExtension call funcation %{public}s error", name);
        return nullptr;
    }
    return callFunctionResult;
}

napi_value JsUserAuthExtension::CallOnConnect(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    Extension::OnConnect(want);
    IAM_LOGD("JsUserAuthExtension callOnConnect begin.");
    HandleScope handleScope(jsRuntime_);
    napi_env env = jsRuntime_.GetNapiEnv();
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
    napi_value argv[] = {napiWant};
    if (!jsObj_) {
        IAM_LOGE("JsUserAuthExtension not found UIExtension.js");
        return nullptr;
    }

    napi_value value = jsObj_->GetNapiValue();
    if (value == nullptr) {
        IAM_LOGE("JsUserAuthExtension failed to get UIExtension object");
        return nullptr;
    }

    napi_value method = nullptr;
    napi_get_named_property(env, value, "onConnect", &method);
    if (method == nullptr) {
        IAM_LOGE("JsUserAuthExtension failed to get onConnect from UIExtension object");
        return nullptr;
    }
    IAM_LOGD("JsUserAuthExtension call funcation onConnect success");

    napi_value callFunctionResult = nullptr;
    if (napi_call_function(env, value, method, ARGC_ONE, argv, &callFunctionResult) != napi_ok) {
        IAM_LOGE("JsUserAuthExtension call funcation onConnect error");
        return nullptr;
    }
    IAM_LOGD("JsUserAuthExtension callOnConnect end.");
    return callFunctionResult;
}

napi_value JsUserAuthExtension::CallOnDisconnect(const AAFwk::Want &want, bool withResult)
{
    HandleEscape handleEscape(jsRuntime_);
    napi_env env = jsRuntime_.GetNapiEnv();
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
    napi_value argv[] = {napiWant};
    if (!jsObj_) {
        IAM_LOGE("JsUserAuthExtension not found UIExtension.js");
        return nullptr;
    }

    napi_value value = jsObj_->GetNapiValue();
    if (value == nullptr) {
        IAM_LOGE("JsUserAuthExtension failed to get UIExtension object");
        return nullptr;
    }

    napi_value method = nullptr;
    napi_get_named_property(env, value, "onDisconnect", &method);
    if (method == nullptr) {
        IAM_LOGE("JsUserAuthExtension failed to get onDisconnect from UIExtension object");
        return nullptr;
    }
    IAM_LOGD("JsUserAuthExtension call funcation onDisconnect success");

    napi_value callFunctionResult = nullptr;
    if (napi_call_function(env, value, method, ARGC_ONE, argv, &callFunctionResult) != napi_ok) {
        IAM_LOGE("JsUserAuthExtension call funcation onDisconnect error");
        return nullptr;
    }

    if (withResult) {
        return handleEscape.Escape(callFunctionResult);
    } else {
        return nullptr;
    }
    IAM_LOGD("JsUserAuthExtension call funcation onDisconnect end.");
}

void JsUserAuthExtension::OnConfigurationUpdated(const AppExecFwk::Configuration& configuration)
{
    Extension::OnConfigurationUpdated(configuration);
    IAM_LOGD("JsUserAuthExtension onConfigurationUpdated called.");

    HandleScope handleScope(jsRuntime_);
    napi_env env = jsRuntime_.GetNapiEnv();

    // Notify extension context
    auto fullConfig = GetContext()->GetConfiguration();
    if (!fullConfig) {
        IAM_LOGE("JsUserAuthExtension configuration is nullptr.");
        return;
    }
    JsExtensionContext::ConfigurationUpdated(env, shellContextRef_, fullConfig);

    napi_value napiConfiguration = OHOS::AppExecFwk::WrapConfiguration(env, *fullConfig);
    CallObjectMethod("onConfigurationUpdate", &napiConfiguration, ARGC_ONE);
}

void ConvertDumpInfo(napi_env env, napi_value callFunctionResult, std::vector<std::string> &info)
{
    uint32_t arrLen = 0;
    napi_get_array_length(env, callFunctionResult, &arrLen);
    for (uint32_t i = 0; i < arrLen; i++) {
        napi_value item = nullptr;
        napi_get_element(env, callFunctionResult, i, &item);
        std::string dumpInfoStr;
        if (!ConvertFromJsValue(env, item, dumpInfoStr)) {
            IAM_LOGE("JsUserAuthExtension parse dumpInfoStr failed");
            return;
        }
        info.push_back(dumpInfoStr);
    }
}

void JsUserAuthExtension::Dump(const std::vector<std::string> &params, std::vector<std::string> &info)
{
    Extension::Dump(params, info);
    IAM_LOGD("JsUserAuthExtension dump called.");
    HandleScope handleScope(jsRuntime_);
    napi_env env = jsRuntime_.GetNapiEnv();
    napi_value arrayValue = nullptr;
    napi_create_array_with_length(env, params.size(), &arrayValue);
    uint32_t index = 0;
    for (const auto &param : params) {
        napi_set_element(env, arrayValue, index++, CreateJsValue(env, param));
    }
    napi_value argv[] = {arrayValue};
    if (!jsObj_) {
        IAM_LOGE("JsUserAuthExtension not found UIExtension.js");
        return;
    }
    napi_value value = jsObj_->GetNapiValue();
    if (value == nullptr) {
        IAM_LOGE("JsUserAuthExtension failed to get UIExtension object");
        return;
    }
    napi_value method;
    napi_get_named_property(env, value, "onDump", &method);
    if (!IsMethodNative(env, value, method)) {
        napi_get_named_property(env, value, "dump", &method);
        if (!IsMethodNative(env, value, method)) {
            IAM_LOGE("JsUserAuthExtension failed to get dump function from UIExtension object");
            return;
        }
    }
    napi_value callFunctionResult;
    if (napi_call_function(env, value, method, ARGC_ONE, argv, &callFunctionResult) != napi_ok) {
        IAM_LOGE("JsUserAuthExtension call funcation onDump error");
        return;
    }
    if (callFunctionResult == nullptr) {
        IAM_LOGE("JsUserAuthExtension dump result is nullptr.");
        return;
    }
    bool isArray = false;
    napi_is_array(env, callFunctionResult, &isArray);
    if (!isArray) {
        IAM_LOGE("JsUserAuthExtension dump result is not an array");
        return;
    }
    ConvertDumpInfo(env, callFunctionResult, info);
    IAM_LOGD("JsUserAuthExtension dump info size: %{public}zu", info.size());
}
}
}
