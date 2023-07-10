/**
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

import account_osAccount from '@ohos.account.osAccount';
import display from '@ohos.display';
import util from '@ohos.util';
import Pwd from '../../common/components/Pwd'
import SixPwd from '../../common/components/SixPwd'
import { DialogType } from '../../common/module/DialogType';
import AuthUtils from '../../common/utils/AuthUtils';
import LogUtils from '../../common/utils/LogUtils';
import TimeUtils from '../../common/utils/TimeUtils';
import Constants, { CmdType, FingerPosition } from '../../common/vm/Constants';

let pinAuthManager;
const TAG = 'FaceAuth';
const INTERVAL = 1000;

let pinData = '';

@Component
export default struct FaceAuth {
  @State prompt: string = globalThis.context.resourceManager
    .getStringSync($r('app.string.unified_authwidget_hint_recognition'));
  @State @Watch('onFlagChange') controllerFlag: boolean = false;
  @State @Watch('onTextValueChange') textValue: string = '';
  @Link @Watch('onCmdDataChange') cmdData: Array<CmdType>;
  @State isEdit: boolean = true;
  // 0:six number 1:arbitrary character 2:arbitrary number
  @Link type: string;
  @Link pinSubType: string;
  @Link dialogType: DialogType;
  @State inputValue: string = '';
  @State flag: boolean = true;
  @State flagN: number = this.dialogType === DialogType.PIN_FACE ? 1 : (this.dialogType === DialogType.ALL ? 2 : 6);
  @State screenClass: object = {};
  @State fingerPosition: FingerPosition = {
    sensorType: ''
  }
  @State screen: number[] = [];

  countTime(freezingTime): void {
    const TRY_AGAIN = globalThis.context.resourceManager.getStringSync($r('app.string.unified_authwidget_postretry'));
    let promptText: string = '';
    let freezingMillisecond = freezingTime;
    if (freezingMillisecond > 0) {
      promptText = TimeUtils.getFreezingTimeNm(freezingMillisecond, globalThis.context);
      promptText = globalThis.context.resourceManager
        .getStringSync($r('app.string.unified_authwidget_many_failures')) + promptText + TRY_AGAIN;
      setTimeout(this.countTime.bind(this), INTERVAL, freezingTime - INTERVAL);
    } else {
      promptText = ' ';
      this.isEdit = true;
    }
    this.inputValue = promptText;
  }

  aboutToAppear(): void {
    if (this.cmdData && this.cmdData.length > 0) {
      this.onCmdDataChange('first');
    }
    if (this.dialogType === DialogType.PIN_FACE || this.dialogType === DialogType.ALL ||
    this.dialogType === DialogType.FACE) {
      this.prompt = globalThis.context.resourceManager
        .getStringSync($r('app.string.unified_authwidget_hint_recognition'));
      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFace]);
    }

    try {
      LogUtils.d(TAG, 'PINAuth start');
      pinAuthManager = new account_osAccount.PINAuth();
      LogUtils.d(TAG, 'PINAuth new success: ' + pinData);
      pinAuthManager.registerInputer({
        onGetData: (authSubType, callback) => {
          let textEncoder = new util.TextEncoder();
          let uint8PW = textEncoder.encode(pinData);
          callback.onSetData(authSubType, uint8PW);
        }
      });
    } catch (error) {
      LogUtils.e(TAG, 'PINAuth catch error: ' + JSON.stringify(error));
    }
  }

  aboutToDisappear(): void {
    pinAuthManager?.unregisterInputer?.();
  }

  onTextValueChange(): void {
    pinData = this.textValue;
  }

  onCmdDataChange(num?: string): void {
    this.cmdData.length > 0 && this.cmdData.map((item) => {
      const { type,remainAttempts, lockoutDuration,sensorInfo} = item.payload;
      switch (type) {
        case Constants.noticeTypePin:
          if (remainAttempts) {
            this.inputValue = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_pwd_error'));
            this.textValue = '';
            if (num === 'first') {
              this.inputValue = '';
            }
            if (remainAttempts < 3) {
              this.inputValue = globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_pwd_error_can_try'))
              + remainAttempts + globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_frequency'));
            }
          }
          if (remainAttempts === 0 && lockoutDuration) {
            this.countTime(lockoutDuration);
            this.isEdit = false;
          }
          break;
        case Constants.noticeTypeFace:
          if (remainAttempts) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_face_verify_fail_click_retry_s1'));
          }
          if (num === 'first') {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_recognition'));
          }
          if (remainAttempts === 0) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_title_number_failed_face_forbidden'));
          }
          break;
        case Constants.noticeTypeFinger:
          if (sensorInfo && JSON.stringify(sensorInfo) !== '{}') {
            this.fingerPosition = JSON.parse(sensorInfo);
            const displayClass = display.getDefaultDisplaySync();
            this.screen = [displayClass.width, displayClass.height];
            if (JSON.parse(sensorInfo).udSensorCenterYInThousandth / displayClass.height < 0.75) {
              this.flagN = 3;
            }
          }
          if (remainAttempts) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_fp_retry_s2'));
          }
          if (num === 'first') {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_normal_fp_only'));
          }
          if (remainAttempts === 0) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'));
          }
        default:
          break;
      }
    })
  }

  onFlagChange(): void {
    if (this.controllerFlag) {
      globalThis.session?.terminateSelf?.();
    }
  }

  build() {
    Column() {
      GridRow({
        columns: 8,
        gutter: { x: 5, y: 10 },
        breakpoints: { value: Constants.deviceDpi,
          reference: BreakpointsReference.WindowSize },
        direction: GridRowDirection.Row
      }) {
        GridCol({ span: { xs: 0, sm: 0, md: 2, lg: 2 } })
          .visibility(Visibility.Hidden)
        GridCol({
          span: { xs: 8, sm: 8, md: 4, lg: 4 },
        }) {
          Column() {
            if (this.flagN === 1) {
              // Single FACE
              Text(globalThis.wantParams.title)
                .fontSize($r('sys.float.ohos_id_text_size_body1'))
                .margin({ top: $r('app.float.content_padding_top') })
                .fontSize($r('sys.float.ohos_id_text_size_body1'))
                .fontColor($r('sys.color.ohos_id_color_text_primary'))
                .fontWeight(FontWeight.Medium)
              if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_hint_recognize_success'))) {
                Image($r('app.media.right_faceID'))
                  .margin({
                    top: $r('app.float.digitalpsd_passwdmask_height'),
                    bottom: $r('app.float.digitalpsd_passwdmask_height')
                  })
                  .width($r('app.float.image_size'))
                  .height($r('app.float.image_size'))
                  .colorBlend($r('sys.color.ohos_id_color_activated'))
                Text(this.prompt).fontSize($r('sys.float.ohos_id_text_size_body2'))
                  .fontColor($r('sys.color.ohos_id_color_secondary'))
              } else if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_hint_face_verify_fail_click_retry_s1'))) {
                Image($r('app.media.error_faceID'))
                  .margin({
                    top: $r('app.float.digitalpsd_passwdmask_height'),
                    bottom: $r('app.float.digitalpsd_passwdmask_height')
                  })
                  .width($r('app.float.image_size'))
                  .height($r('app.float.image_size'))
                  .colorBlend($r('sys.color.ohos_id_color_activated'))
                Text(this.prompt).id('promptText_resetPin_faceAuth')
                  .fontColor($r('sys.color.ohos_id_color_warning'))
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
                  .onClick(() => {
                    this.prompt = globalThis.context.resourceManager
                      .getStringSync($r('app.string.unified_authwidget_hint_recognition'));
                    AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFace]);
                  })
              } else if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
                Image($r('app.media.error_faceID'))
                  .margin({
                    top: $r('app.float.digitalpsd_passwdmask_height'),
                    bottom: $r('app.float.digitalpsd_passwdmask_height')
                  })
                  .width($r('app.float.image_size'))
                  .height($r('app.float.image_size'))
                  .colorBlend($r('sys.color.ohos_id_color_activated'))
                Text(this.prompt).fontSize($r('sys.float.ohos_id_text_size_body2'))
                  .fontColor($r('sys.color.ohos_id_color_warning'))
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
              } else if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_hint_recognition'))) {
                Image($r('app.media.error_faceID'))
                  .margin({
                    top: $r('app.float.digitalpsd_passwdmask_height'),
                    bottom: $r('app.float.digitalpsd_passwdmask_height')
                  })
                  .width($r('app.float.image_size'))
                  .height($r('app.float.image_size'))
                  .colorBlend($r('sys.color.ohos_id_color_activated'))
                Text(this.prompt).fontColor($r('sys.color.ohos_id_color_text_secondary'))
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
              }
              Row() {
                Column() {
                  Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                    .id('cancelBtn_pin_faceAuth')
                    .margin({ left: $r('app.float.content_padding') })
                    .width(Constants.ninetyPercentWidth)
                    .height($r('app.float.btn_height'))
                    .fontSize($r('sys.float.ohos_id_text_size_button1'))
                    .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                    .fontWeight(FontWeight.Medium)
                    .backgroundColor(Color.Transparent)
                    .onClick(() => {
                      globalThis.session?.terminateSelf?.();
                    })
                }.width(Constants.halfContainerWidth)

                Divider()
                  .vertical(true)
                  .height($r('app.float.digitalpsd_passwdmask_height'))
                  .color($r('sys.color.ohos_id_color_list_separator'))
                  .width($r('app.float.divider_width'))
                Column() {
                  Button($r('app.string.unified_authwidget_usepwd'))
                    .id('usePwd_pin_faceAuth')
                    .margin({ right: $r('app.float.content_padding') })
                    .width(Constants.ninetyPercentWidth)
                    .height($r('app.float.btn_height'))
                    .fontSize($r('sys.float.ohos_id_text_size_button1'))
                    .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                    .fontWeight(FontWeight.Medium)
                    .backgroundColor(Color.Transparent)
                    .onClick(() => {
                      this.inputValue = ' '
                      if (this.pinSubType !== Constants.pinSix) {
                        this.flagN = 4
                      } else {
                        this.flagN = 5
                      }
                      LogUtils.i(TAG, 'flagN: ' + this.flagN)
                    })
                }.width(Constants.halfContainerWidth)

              }
              .height($r('app.float.btn_height'))
              .margin({ top: $r('app.float.element_margin'), bottom: $r('app.float.content_padding') })
            }
            if (this.flagN === 2) {
              // The first form of facial fingerprint password
              Flex({ justifyContent: FlexAlign.SpaceBetween }) {
                Image($r('app.media.ic_public_cancel'))
                  .id('cancelImg_all_faceAuth')
                  .width($r('app.float.digitalpsd_passwdmask_height'))
                  .height($r('app.float.digitalpsd_passwdmask_height'))
                  .margin({
                    top: $r('app.float.digitalpsd_passwdmask_height'),
                    left: $r('app.float.digitalpsd_passwdmask_height')
                  })
                  .onClick(() => {
                    globalThis.session?.terminateSelf?.();
                    this.textValue = ''
                  })
                Button($r('app.string.unified_authwidget_usepwd'))
                  .id('usePwdBtn_all_faceAuth')
                  .backgroundColor(Color.White)
                  .height($r('app.float.digitalpsd_passwdmask_height'))
                  .padding(0)
                  .margin({
                    top: $r('app.float.digitalpsd_passwdmask_height'),
                    right: $r('app.float.digitalpsd_passwdmask_height')
                  })
                  .fontColor($r('sys.color.ohos_id_color_activated'))
                  .fontSize($r('sys.float.ohos_id_text_size_body1'))
                  .fontWeight(FontWeight.Medium)
                  .onClick(() => {
                    this.inputValue = ' '
                    if (this.pinSubType !== Constants.pinSix) {
                      this.flagN = 4
                    } else {
                      this.flagN = 5
                    }
                  })
              }

              Image($r('app.media.error_faceID'))
                .width($r('app.float.image_small'))
                .height($r('app.float.image_small'))
                .margin({ top: $r('app.float.content_padding'), bottom: $r('app.float.content_padding') })
                .colorBlend($r('sys.color.ohos_id_color_activated'))
              Text(globalThis.wantParams.title).fontSize($r('sys.float.ohos_id_text_size_body1'))
                .fontColor($r('sys.color.ohos_id_color_text_primary'))

              if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_hint_face_verify_fail_click_retry_s1'))) {
                Text(this.prompt)
                  .id('resetPromptText_all_faceAuth')
                  .margin({ top: $r('app.float.element_margin') })
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
                  .fontColor($r('sys.color.ohos_id_color_warning'))
                  .onClick(() => {
                    this.prompt = globalThis.context.resourceManager
                      .getStringSync($r('app.string.unified_authwidget_hint_recognition'));
                    AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFace]);
                  })
              } else if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
                Text(this.prompt)
                  .margin({ top: $r('app.float.element_margin') })
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
                  .fontColor($r('sys.color.ohos_id_color_warning'))
              } else if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_title_number_failed_face_forbidden'))) {
                Text(this.prompt)
                  .margin({ top: $r('app.float.element_margin') })
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
                  .fontColor($r('sys.color.ohos_id_color_warning'))
              } else {
                Text(this.prompt)
                  .margin({ top: $r('app.float.element_margin') })
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
                  .fontColor($r('sys.color.ohos_id_color_secondary'))
              }
              Image($r('app.media.ic_blue_fingerprint'))
                .id('blueFingerprintImg_all_faceAuth')
                .width($r('app.float.image_medium'))
                .height($r('app.float.image_medium'))
                .margin({
                  top: $r('app.float.digitalpsd_passwdmask_height'),
                  bottom: $r('app.float.digitalpsd_passwdmask_height')
                })
                .onClick(() => {
                  if (this.prompt !== globalThis.context.resourceManager
                    .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
                    AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
                  }
                })
            }
            if (this.flagN === 3) {
              // Facial fingerprint password, second form
              Image($r('app.media.error_faceID'))
                .id('errFaceImg_faceAuth')
                .width($r('app.float.image_small'))
                .height($r('app.float.image_small'))
                .margin({ top: $r('app.float.content_padding_top'), bottom: $r('app.float.content_padding') })
                .colorBlend($r('sys.color.ohos_id_color_activated'))
              Text(globalThis.wantParams.title).fontSize($r('sys.float.ohos_id_text_size_body1'))
                .fontColor($r('sys.color.ohos_id_color_text_primary'))

              Image($r('app.media.ic_blue_fingerprint'))
                .id('blueFingerprintImg_faceAuth')
                .width($r('app.float.image_medium'))
                .height($r('app.float.image_medium'))
                .margin({ top: $r('app.float.content_padding') })
                .onClick(() => {
                  if (this.prompt !== globalThis.context.resourceManager
                    .getStringSync($r('app.string.unified_authwidget_title_fp_forbidden_enter_pwd'))) {
                    AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
                  }
                })
              Text($r('app.string.unified_authwidget_hint_inscreen_fp'))
                .margin({ top: $r('app.float.content_padding') })
                .fontColor($r('sys.color.ohos_id_color_text_secondary'))
                .fontSize($r('sys.float.ohos_id_text_size_body2'))
              Row() {
                Column() {
                  Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                    .id('cancelBtn_faceAuth')
                    .margin({ left: $r('app.float.content_padding') })
                    .width(Constants.ninetyPercentWidth)
                    .height($r('app.float.btn_height'))
                    .fontSize($r('sys.float.ohos_id_text_size_button1'))
                    .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                    .fontWeight(FontWeight.Medium)
                    .backgroundColor(Color.Transparent)
                    .onClick(() => {
                      globalThis.session?.terminateSelf?.();
                      this.textValue = ''
                    })
                }.width(Constants.halfContainerWidth)

                Divider()
                  .vertical(true)
                  .height($r('app.float.digitalpsd_passwdmask_height'))
                  .color($r('sys.color.ohos_id_color_list_separator'))
                  .width($r('app.float.divider_width'))
                Column() {
                  Button($r('app.string.unified_authwidget_usepwd'))
                    .id('usePwdBtn_faceAuth')
                    .margin({ right: $r('app.float.content_padding') })
                    .width(Constants.ninetyPercentWidth)
                    .height($r('app.float.btn_height'))
                    .fontSize($r('sys.float.ohos_id_text_size_button1'))
                    .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                    .fontWeight(FontWeight.Medium)
                    .backgroundColor(Color.Transparent)
                    .onClick(() => {
                      globalThis.session?.terminateSelf?.();
                    })

                }.width(Constants.halfContainerWidth)

              }
              .height($r('app.float.btn_height'))
              .margin({ top: $r('app.float.element_margin'), bottom: $r('app.float.content_padding') })
            }
            if (this.flagN === 4) {
              // Password 32-bit
              Column() {
                Pwd({
                  textValue: $textValue,
                  inputValue: $inputValue,
                  isEdit: $isEdit,
                  pinSubType: $pinSubType
                })
                Row() {
                  Column() {
                    Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                      .id('cancelBtn_mixedPin_faceAuth')
                      .margin({ left: $r('app.float.content_padding') })
                      .width(Constants.ninetyPercentWidth)
                      .height($r('app.float.btn_height'))
                      .fontSize($r('sys.float.ohos_id_text_size_button1'))
                      .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                      .fontWeight(FontWeight.Medium)
                      .backgroundColor(Color.Transparent)
                      .onClick(() => {
                        globalThis.session?.terminateSelf?.();
                        this.textValue = ''
                      })
                  }.width(Constants.halfContainerWidth)

                  Divider()
                    .vertical(true)
                    .height($r('app.float.digitalpsd_passwdmask_height'))
                    .color($r('sys.color.ohos_id_color_list_separator'))
                    .width($r('app.float.divider_width'))
                  Column() {
                    Button($r('app.string.unified_authwidget_confirm'))
                      .id('okBtn_faceAuth')
                      .margin({ right: $r('app.float.content_padding') })
                      .width(Constants.ninetyPercentWidth)
                      .height($r('app.float.btn_height'))
                      .fontSize($r('sys.float.ohos_id_text_size_button1'))
                      .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                      .fontWeight(FontWeight.Medium)
                      .backgroundColor(Color.Transparent)
                      .onClick(async (e) => {
                        AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypePin]);
                      })
                  }.width(Constants.halfContainerWidth)
                }
                .height($r('app.float.btn_height'))
                .margin({ top: $r('app.float.element_margin'), bottom: $r('app.float.content_padding') })
              }

            }
            if (this.flagN === 5) {
              // Password 6-bit
              Column() {
                SixPwd({
                  textValue: $textValue,
                  inputValue: $inputValue,
                  isEdit: $isEdit
                })
                Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                  .id('cancelBtn_sixPin_faceAuth')
                  .onClick(() => {
                    globalThis.session?.terminateSelf?.();
                    this.textValue = ''
                  })
                  .backgroundColor(Color.Transparent)
                  .height($r('app.float.btn_height'))
                  .width(Constants.halfContainerWidth)
                  .margin({ top: $r('app.float.element_margin'), bottom: $r('app.float.content_padding') })
                  .fontSize($r('sys.float.ohos_id_text_size_button1'))
                  .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                  .fontWeight(FontWeight.Medium)
              }
            }
            if (this.flagN === 6) {
              // Single FACE
              Text(globalThis.wantParams.title)
                .fontSize($r('sys.float.ohos_id_text_size_body1'))
                .margin({ top: $r('app.float.content_padding_top') })
                .fontSize($r('sys.float.ohos_id_text_size_body1'))
                .fontColor($r('sys.color.ohos_id_color_text_primary'))
                .fontWeight(FontWeight.Medium)
              if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_hint_recognize_success'))) {
                Image($r('app.media.right_faceID'))
                  .margin({
                    top: $r('app.float.digitalpsd_passwdmask_height'),
                    bottom: $r('app.float.digitalpsd_passwdmask_height')
                  })
                  .width($r('app.float.image_size'))
                  .height($r('app.float.image_size'))
                  .colorBlend($r('sys.color.ohos_id_color_activated'))
                Text(this.prompt).fontSize($r('sys.float.ohos_id_text_size_body2'))
                  .fontColor($r('sys.color.ohos_id_color_secondary'))
              } else if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_hint_face_verify_fail_click_retry_s1'))) {
                Image($r('app.media.error_faceID'))
                  .margin({
                    top: $r('app.float.digitalpsd_passwdmask_height'),
                    bottom: $r('app.float.digitalpsd_passwdmask_height')
                  })
                  .width($r('app.float.image_size'))
                  .height($r('app.float.image_size'))
                  .colorBlend($r('sys.color.ohos_id_color_activated'))
                Text(this.prompt)
                  .id('promptText_reset_faceAuth')
                  .fontColor($r('sys.color.ohos_id_color_warning'))
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
                  .onClick(() => {
                    if (this.prompt === globalThis.context.resourceManager
                      .getStringSync($r('app.string.unified_authwidget_hint_face_verify_fail_click_retry_s1'))) {
                      this.prompt = globalThis.context.resourceManager
                        .getStringSync($r('app.string.unified_authwidget_hint_recognition'));
                      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFace]);
                    }
                  })
              } else if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_hint_recognition'))) {
                Image($r('app.media.error_faceID'))
                  .margin({
                    top: $r('app.float.digitalpsd_passwdmask_height'),
                    bottom: $r('app.float.digitalpsd_passwdmask_height')
                  })
                  .width($r('app.float.image_size'))
                  .height($r('app.float.image_size'))
                  .colorBlend($r('sys.color.ohos_id_color_activated'))
                Text(this.prompt).fontColor($r('sys.color.ohos_id_color_text_secondary'))
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
              }
              if (!globalThis.wantParams?.navigationButtonText) {
                Row() {
                  Column() {
                    Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                      .id('cancelBtn_all_face')
                      .onClick(() => {
                        globalThis.session?.terminateSelf?.();
                      })
                      .backgroundColor(Color.Transparent)
                      .height($r('app.float.btn_height'))
                      .width(Constants.fullContainerWidth)
                      .fontSize($r('sys.float.ohos_id_text_size_button1'))
                      .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                      .fontWeight(FontWeight.Medium)
                  }
                }
                .height($r('app.float.btn_height'))
                .padding({ left: $r('app.float.content_padding'), right: $r('app.float.content_padding') })
                .margin({ top: $r('app.float.element_margin'), bottom: $r('app.float.content_padding') })
              } else {
                Row() {
                  Column() {
                    Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                      .margin({ left: $r('app.float.content_padding') })
                      .width(Constants.ninetyPercentWidth)
                      .height($r('app.float.btn_height'))
                      .fontSize($r('sys.float.ohos_id_text_size_button1'))
                      .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                      .fontWeight(FontWeight.Medium)
                      .backgroundColor(Color.Transparent)
                      .onClick(() => {
                        globalThis.session?.terminateSelf?.();
                      })
                  }.width(Constants.halfContainerWidth)

                  Divider()
                    .vertical(true)
                    .height($r('app.float.digitalpsd_passwdmask_height'))
                    .color($r('sys.color.ohos_id_color_list_separator'))
                    .width($r('app.float.divider_width'))
                  Column() {
                    Button(globalThis.wantParams?.navigationButtonText)
                      .onClick(() => {
                        globalThis.session?.terminateSelf?.();
                      })
                      .margin({ right: $r('app.float.content_padding') })
                      .width(Constants.ninetyPercentWidth)
                      .height($r('app.float.btn_height'))
                      .fontSize($r('sys.float.ohos_id_text_size_button1'))
                      .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                      .fontWeight(FontWeight.Medium)
                      .backgroundColor(Color.Transparent)
                  }.width(Constants.halfContainerWidth)
                }
                .height($r('app.float.btn_height'))
                .margin({ top: $r('app.float.element_margin'), bottom: $r('app.float.content_padding') })
              }
            }
          }
          .position({ y: this.fingerPosition.udSensorCenterYInThousandth / this.screen[1] < 0.75
            ? (this.fingerPosition.udSensorCenterYInThousandth - Constants.thousandth)
            : Constants.normalPosition })
          .backgroundColor($r('sys.color.ohos_id_color_dialog_bg'))
          .borderRadius($r('sys.float.ohos_id_corner_radius_dialog'))
          .margin({
            left: ($r('sys.float.ohos_id_dialog_margin_start')),
            right: ($r('sys.float.ohos_id_dialog_margin_end')),
            bottom: ($r('sys.float.ohos_id_dialog_margin_bottom'))
          })
        }
      }
    }
    .height(Constants.fullContainerHeight)
    .justifyContent(FlexAlign.End)
    .backgroundColor(Color.Transparent)
  }
}
