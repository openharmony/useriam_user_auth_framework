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
import screen from '@ohos.screen';
import Pwd from '../../common/components/Pwd';
import SixPwd from '../../common/components/SixPwd';
import { DialogType } from '../../common/module/DialogType';
import AuthUtils from '../../common/utils/AuthUtils';
import FuncUtils from '../../common/utils/FuncUtils';
import LogUtils from '../../common/utils/LogUtils';
import TimeUtils from '../../common/utils/TimeUtils';
import Constants, { CmdType, FingerPosition } from '../../common/vm/Constants';


const TAG = 'FingerprintAuth';
const INTERVAL = 1000;
let pinAuthManager;
let pinData = '';

@Component
export default struct FingerprintAuth {
  @Link type: string;
  @Link pinSubType: string;
  @Link dialogType: DialogType;
  @State prompt: string = globalThis.context.resourceManager
    .getStringSync($r('app.string.unified_authwidget_hint_inscreen_fp'));
  @State @Watch('onFlagChange') controllerFlag: boolean = false;
  @State @Watch('onTextValueChange') textValue: string = '';
  @Link @Watch('onCmdDataChange') cmdData: Array<CmdType>;
  @State isEdit: boolean = true;
  @State inputValue: string = '';
  @State flag: boolean = true;
  @State state: number = this.dialogType === DialogType.PIN_FINGER ? (this.flag ? 2 : 3) : (this.flag ? 1 : 3);
  @State screenClass: object = {};
  @State fingerPosition: FingerPosition = {
    sensorType: ''
  }
  @State screen: number[] = [];

  queryScreenInfo(): void {
    try {
      screen.getAllScreens((err, data) => {
        if (err.code) {
          LogUtils.e(TAG, 'Failed to get all screens. Cause: ' + JSON.stringify(err));
          return;
        }
        this.screenClass = data[0];
      });
    } catch (exception) {
      LogUtils.e(TAG, 'getAllScreens catch exception: ' + exception);
    }
  }

  aboutToAppear(): void {
    if (this.cmdData && this.cmdData.length > 0) {
      this.onCmdDataChange('first');
    }
    try {
      LogUtils.i(TAG, 'aboutToAppear PINAuth start');
      pinAuthManager = new account_osAccount.PINAuth();
      LogUtils.i(TAG, 'aboutToAppear PINAuth new success: ' + pinData);
      pinAuthManager.registerInputer({
        onGetData: (authSubType, callback) => {
          let uint8PW = FuncUtils.getUint8PW(pinData);
          callback.onSetData(authSubType, uint8PW);
        }
      });
    } catch (error) {
      LogUtils.e(TAG, 'aboutToAppear PINAuth catch error: ' + JSON.stringify(error));
    }
  }

  aboutToDisappear(): void {
    LogUtils.i(TAG, 'PINAuth unregisterInputer');
    pinAuthManager?.unregisterInputer?.();
  }

  onTextValueChange(): void {
    pinData = this.textValue;
  }

  onCmdDataChange(num?: string): void {
    this.cmdData.length > 0 && this.cmdData.map((item) => {
      const { type,remainAttempts, lockoutDuration,sensorInfo } = item.payload;
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
                .getStringSync($r('app.string.unified_authwidget_pwd_error_can_try')) +
              remainAttempts + globalThis.context.resourceManager
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
          if (remainAttempts === 0) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_title_number_failed_face_forbidden'));
          }
          break;
        case Constants.noticeTypeFinger:
          if (sensorInfo && JSON.stringify(sensorInfo) !== '{}') {
            this.fingerPosition = JSON.parse(sensorInfo);
            switch (this.fingerPosition.sensorType) {
              case 'OUT_OF_SCREEN_SENSOR': {
                this.flag = false;
                break;
              }
            }
            const displayClass = display.getDefaultDisplaySync();
            this.screen = [displayClass.width, displayClass.height];
          }
          if (remainAttempts) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_fp_retry_s2'));
          }
          if (num === 'first') {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_inscreen_fp'));
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
            if (this.state === 3) {
              Text(globalThis.wantParams?.title)
                .margin({ top: $r('app.float.title_padding_top') })
                .fontSize($r('sys.float.ohos_id_text_size_body1'))
                .fontColor($r('sys.color.ohos_id_color_text_primary'))
                .fontWeight(FontWeight.Medium)
              Swiper() {
                Image($r('app.media.icon_applock_2'))
                  .width($r('app.float.image_big'))
                  .height($r('app.float.image_big'))
                  .margin({ top: $r('app.float.content_padding'), bottom: $r('app.float.content_padding') })
                Image($r('app.media.icon_applock_3'))
                  .width($r('app.float.image_big'))
                  .height($r('app.float.image_big'))
                  .margin({ top: $r('app.float.content_padding'), bottom: $r('app.float.content_padding') })
                Image($r('app.media.icon_applock_4'))
                  .width($r('app.float.image_big'))
                  .height($r('app.float.image_big'))
                  .margin({ top: $r('app.float.content_padding'), bottom: $r('app.float.content_padding') })
              }
              .loop(true)
              .autoPlay(true)
              .interval(2000)

              Text($r('app.string.unified_authwidget_hint_normal_fp_only'))
                .fontColor($r('sys.color.ohos_id_color_primary'))
                .fontSize($r('sys.float.ohos_id_text_size_body2'))
              Row() {
                Column() {
                  Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                    .id('cancelBth_state3_fingerprintAuth')
                    .margin({ left: $r('app.float.content_padding') })
                    .width(Constants.ninetyPercentWidth)
                    .height($r('app.float.btn_height'))
                    .fontSize($r('sys.float.ohos_id_text_size_button1'))
                    .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                    .fontWeight(FontWeight.Medium)
                    .backgroundColor(Color.Transparent)
                    .onClick(() => {
                      globalThis.session?.terminateSelf?.();
                      this.textValue = '';
                    })
                }.width(Constants.halfContainerWidth)

                Divider()
                  .vertical(true)
                  .height($r('app.float.digitalpsd_passwdmask_height'))
                  .color($r('sys.color.ohos_id_color_list_separator'))
                  .width($r('app.float.divider_width'))
                Column() {
                  Button($r('app.string.unified_authwidget_usepwd'))
                    .id('usePwdBtn_state3_fingerprintAuth')
                    .margin({ right: $r('app.float.content_padding') })
                    .width(Constants.ninetyPercentWidth)
                    .height($r('app.float.btn_height'))
                    .fontSize($r('sys.float.ohos_id_text_size_button1'))
                    .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                    .fontWeight(FontWeight.Medium)
                    .backgroundColor(Color.Transparent)
                    .onClick(() => {
                      this.state = 5;
                    })
                }.width(Constants.halfContainerWidth)

              }
              .height($r('app.float.btn_height'))
              .margin({ top: $r('app.float.element_margin'), bottom: $r('app.float.content_padding') })
            }
            else if (this.state === 2) {
              Text(globalThis.wantParams?.title)
                .margin({ top: $r('app.float.title_padding_top') })
                .fontSize($r('sys.float.ohos_id_text_size_body1'))
                .fontColor($r('sys.color.ohos_id_color_text_primary'))
                .fontWeight(FontWeight.Medium)
              if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_hint_fp_verify_success'))) {
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
                .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
                Image($r('app.media.ic_blue_fingerprint'))
                  .margin({
                    top: $r('app.float.digitalpsd_passwdmask_height'),
                    bottom: $r('app.float.digitalpsd_passwdmask_height')
                  })
                  .width($r('app.float.image_size'))
                  .height($r('app.float.image_size'))
                Text(this.prompt)
                  .fontColor($r('sys.color.ohos_id_color_warning'))
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
              } else if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_hint_inscreen_fp'))) {
                Image($r('app.media.ic_blue_fingerprint'))
                  .id('blueFingerprintImg_state2_fingerprintAuth')
                  .margin({
                    top: $r('app.float.digitalpsd_passwdmask_height'),
                    bottom: $r('app.float.digitalpsd_passwdmask_height')
                  })
                  .width($r('app.float.image_size'))
                  .height($r('app.float.image_size'))
                  .onClick(() => {
                    if (this.prompt !== globalThis.context.resourceManager
                      .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
                      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
                    }
                  })
                Text(this.prompt)
                  .fontColor($r('sys.color.ohos_id_color_primary'))
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
              } else if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_hint_fp_retry_s2'))) {
                Image($r('app.media.ic_blue_fingerprint'))
                  .margin({
                    top: $r('app.float.digitalpsd_passwdmask_height'),
                    bottom: $r('app.float.digitalpsd_passwdmask_height')
                  })
                  .width($r('app.float.image_size'))
                  .height($r('app.float.image_size'))
                  .onClick(() => {
                    if (this.prompt !== globalThis.context.resourceManager
                      .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
                      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
                    }
                  })
                Text(this.prompt)
                  .fontColor($r('sys.color.ohos_id_color_warning'))
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
              }
              Row() {
                Column() {
                  Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                    .id('cancelBtn_state2_fingerprintAuth')
                    .margin({ left: $r('app.float.content_padding') })
                    .width(Constants.ninetyPercentWidth)
                    .height($r('app.float.btn_height'))
                    .fontSize($r('sys.float.ohos_id_text_size_button1'))
                    .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                    .fontWeight(FontWeight.Medium)
                    .backgroundColor(Color.Transparent)
                    .onClick(() => {
                      globalThis.session?.terminateSelf?.();
                      this.textValue = '';
                    })
                }.width(Constants.halfContainerWidth)

                Divider()
                  .vertical(true)
                  .height($r('app.float.digitalpsd_passwdmask_height'))
                  .color($r('sys.color.ohos_id_color_list_separator'))
                  .width($r('app.float.divider_width'))
                Column() {
                  Button($r('app.string.unified_authwidget_usepwd'))
                    .id('usePwdBtn_state2_fingerprintAuth')
                    .margin({ right: $r('app.float.content_padding') })
                    .width(Constants.ninetyPercentWidth)
                    .height($r('app.float.btn_height'))
                    .fontSize($r('sys.float.ohos_id_text_size_button1'))
                    .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                    .fontWeight(FontWeight.Medium)
                    .backgroundColor(Color.Transparent)
                    .onClick(() => {
                      this.inputValue = ' ';
                      if (this.pinSubType !== Constants.pinSix) {
                        this.state = 5;
                      } else {
                        this.state = 6;
                      }
                    })
                }.width(Constants.halfContainerWidth)
              }
              .height($r('app.float.btn_height'))
              .margin({ top: $r('app.float.element_margin'), bottom: $r('app.float.content_padding') })
            }
            else if (this.state === 1) {
              if (JSON.parse(JSON.stringify(this.screenClass)).orientation === 2) {
                Flex({
                  direction: FlexDirection.ColumnReverse,
                  justifyContent: FlexAlign.Center,
                  alignItems: ItemAlign.Center
                }) {
                  Text(globalThis.context.resourceManager
                    .getStringSync($r('app.string.unified_authwidget_tip_verify_in_portrait_mode')))
                    .fontSize($r('sys.float.ohos_id_text_size_body2'))
                    .fontColor($r('sys.color.ohos_id_color_secondary'))
                }
                .width(Constants.fullContainerWidth)
                .height(Constants.halfContainerWidth)
              }
              else {
                Text(globalThis.wantParams?.title)
                  .margin({ top: $r('app.float.title_padding_top') })
                  .fontSize($r('sys.float.ohos_id_text_size_body1'))
                  .fontColor($r('sys.color.ohos_id_color_text_primary'))
                  .fontWeight(FontWeight.Medium)
                if (this.prompt === globalThis.context.resourceManager
                  .getStringSync($r('app.string.unified_authwidget_hint_fp_verify_success'))) {
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
                  .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
                  Image($r('app.media.ic_blue_fingerprint'))
                    .margin({
                      top: $r('app.float.digitalpsd_passwdmask_height'),
                      bottom: $r('app.float.digitalpsd_passwdmask_height')
                    })
                    .width($r('app.float.image_size'))
                    .height($r('app.float.image_size'))

                  Text(this.prompt)
                    .fontColor($r('sys.color.ohos_id_color_warning'))
                    .fontSize($r('sys.float.ohos_id_text_size_body2'))
                } else if (this.prompt === globalThis.context.resourceManager
                  .getStringSync($r('app.string.unified_authwidget_hint_inscreen_fp'))) {
                  Image($r('app.media.ic_blue_fingerprint'))
                    .id('blueFingerprint_state1_fingerprintAuth')
                    .margin({
                      top: $r('app.float.digitalpsd_passwdmask_height'),
                      bottom: $r('app.float.digitalpsd_passwdmask_height')
                    })
                    .width($r('app.float.image_size'))
                    .height($r('app.float.image_size'))
                    .onClick(() => {
                      if (this.prompt !== globalThis.context.resourceManager
                        .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
                        AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
                      }
                    })
                  Text(this.prompt)
                    .fontColor($r('sys.color.ohos_id_color_primary'))
                    .fontSize($r('sys.float.ohos_id_text_size_body2'))
                } else if (this.prompt === globalThis.context.resourceManager
                  .getStringSync($r('app.string.unified_authwidget_hint_fp_retry_s2'))) {
                  Image($r('app.media.ic_blue_fingerprint'))
                    .margin({
                      top: $r('app.float.digitalpsd_passwdmask_height'),
                      bottom: $r('app.float.digitalpsd_passwdmask_height')
                    })
                    .width($r('app.float.image_size'))
                    .height($r('app.float.image_size'))
                    .onClick(() => {
                      if (this.prompt !== globalThis.context.resourceManager
                        .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
                        AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
                      }
                    })
                  Text(this.prompt)
                    .fontColor($r('sys.color.ohos_id_color_warning'))
                    .fontSize($r('sys.float.ohos_id_text_size_body2'))
                }
                if (!globalThis.wantParams?.navigationButtonText) {
                  Row() {
                    Column() {
                      Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                        .id('usePwdBtn_state1_fingerprintAuth')
                        .onClick(() => {
                          globalThis.session?.terminateSelf?.();
                        })
                        .backgroundColor(Color.Transparent)
                        .height($r('app.float.btn_height'))
                        .width(Constants.fullContainerHeight)
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
                        .id('cancelBtn_state1_fingerprintAuth')
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
            else if (this.state === 4) {
              Flex({ justifyContent: FlexAlign.SpaceBetween }) {
                Image($r('app.media.ic_public_cancel'))
                  .id('cancel_state4_fingerprintAuth')
                  .width($r('app.float.digitalpsd_passwdmask_height'))
                  .height($r('app.float.digitalpsd_passwdmask_height'))
                  .margin({
                    top: $r('app.float.digitalpsd_passwdmask_height'),
                    left: $r('app.float.digitalpsd_passwdmask_height')
                  })
                  .onClick(() => {
                    globalThis.session?.terminateSelf?.();
                  })
                Button($r('app.string.unified_authwidget_usepwd'))
                  .id('usePwdBtn_state4_fingerprintAuth')
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
                    this.state = 5;
                  })
              }

              Text(globalThis.wantParams?.title)
                .fontSize($r('sys.float.ohos_id_text_size_body1'))
                .fontColor($r('sys.color.ohos_id_color_text_primary'))
                .margin({ top: $r('app.float.digitalpsd_passwdmask_height') })
              Text($r('app.string.unified_authwidget_hint_inscreen_fp'))
                .margin({ top: $r('app.float.element_margin') })
                .fontColor($r('sys.color.ohos_id_color_text_secondary'))
                .fontSize($r('sys.float.ohos_id_text_size_body2'))
              Image($r('app.media.ic_blue_fingerprint'))
                .width($r('app.float.image_medium'))
                .height($r('app.float.image_medium'))
                .margin({
                  top: $r('app.float.digitalpsd_passwdmask_height'),
                  bottom: $r('app.float.digitalpsd_passwdmask_height')
                })
            }
            else if (this.state === 5) {
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
                      .id('cancelBtn_state5_fingerprintAuth')
                      .margin({ left: $r('app.float.content_padding') })
                      .width(Constants.ninetyPercentWidth)
                      .height($r('app.float.btn_height'))
                      .fontSize($r('sys.float.ohos_id_text_size_button1'))
                      .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                      .fontWeight(FontWeight.Medium)
                      .backgroundColor(Color.Transparent)
                      .onClick(() => {
                        globalThis.session?.terminateSelf?.();
                        this.textValue = '';
                      })
                  }.width(Constants.halfContainerWidth)

                  Divider()
                    .vertical(true)
                    .height($r('app.float.digitalpsd_passwdmask_height'))
                    .color($r('sys.color.ohos_id_color_list_separator'))
                    .width($r('app.float.divider_width'))
                  Column() {
                    Button($r('app.string.unified_authwidget_confirm'))
                      .id('okBth_state5_fingerprintAuth')
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
            else if (this.state === 6) {
              // Password 6-bit
              Column() {
                SixPwd({
                  textValue: $textValue,
                  inputValue: $inputValue,
                  isEdit: $isEdit
                })
                Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                  .id('cancel_state6_fingerprintAuth')
                  .onClick(() => {
                    globalThis.session?.terminateSelf?.();
                    this.textValue = '';
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

          }.backgroundColor($r('sys.color.ohos_id_color_dialog_bg'))
          .borderRadius($r('sys.float.ohos_id_corner_radius_dialog'))
          .position({ y: (this.fingerPosition.udSensorCenterYInThousandth - Constants.thousandth) })
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

