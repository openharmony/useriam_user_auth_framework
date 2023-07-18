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
import PassWord from '../../common/components/PassWord';
import SixPassword from '../../common/components/SixPassword';
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
const THOUSANDTH = 1000;
const NORMAL_POSITION = -260;
const OUT_SENSOR = -292
const MARGIN_TOP = 66
const OFF_SCREEN_FINGER = 3;
const SINGLE_FINGER = 1;
const PIN_FINGER = 2;
const SIX_PIN = 6;
const MULTI_PIN = 5;
const RADIUS = 2;
const PIN_FAIL_TIP = 3;
const AUTH_LOCK = 0;

@Component
export default struct FingerprintAuth {
  @Link type: string;
  @Link pinSubType: string;
  @Link dialogType: DialogType;
  @State prompt: string = globalThis.context.resourceManager
    .getStringSync($r('app.string.unified_authwidget_hint_inscreen_fp'));
  @State @Watch('onTextValueChange') textValue: string = '';
  @Link @Watch('onCmdDataChange') cmdData: Array<CmdType>;
  @State isEdit: boolean = true;
  @State inputValue: string = '';
  @State state: number = 0;
  @State screenClass: object = {};
  @State fingerPosition: FingerPosition = {
    sensorType: '',
    udSensorRadiusInPx: 60
  }
  @StorageLink('SYSTEM_NAVIGATION_BAR_HEIGHT') SYSTEM_NAVIGATION_BAR_HEIGHT: number = 0;
  @State screen: number[] = [];
  @Consume isLandscape: boolean;

  aboutToAppear(): void {
    AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
    try {
      if (this.cmdData && this.cmdData.length > 0) {
        this.onCmdDataChange('first');
      }
      LogUtils.info(TAG, 'aboutToAppear PINAuth');
      pinAuthManager = new account_osAccount.PINAuth();
      pinAuthManager.registerInputer({
        onGetData: (authSubType, callback) => {
          LogUtils.info(TAG, 'aboutToAppear registerInputer onGetData');
          let uint8PW = FuncUtils.getUint8PW(pinData);
          callback.onSetData(authSubType, uint8PW);
        }
      });
    } catch (error) {
      LogUtils.error(TAG, 'aboutToAppear PINAuth catch error: ' + error?.code);
      globalThis.session?.terminateSelf?.();
    }
  }

  aboutToDisappear(): void {
    LogUtils.info(TAG, 'PINAuth unregisterInputer');
    pinAuthManager?.unregisterInputer?.();
  }

  onTextValueChange(): void {
    pinData = this.textValue;
  }

  onCmdDataChange(num?: string): void {
    this.cmdData.length > 0 && this.cmdData.map((item) => {
      let stateNew = this.dialogType === DialogType.PIN_FINGER ? PIN_FINGER : SINGLE_FINGER;
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
            if (remainAttempts < PIN_FAIL_TIP) {
              this.inputValue = globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_pwd_error_can_try')) +
              remainAttempts + globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_frequency'));
            }
          }
          if (remainAttempts === AUTH_LOCK && lockoutDuration) {
            this.countTime(lockoutDuration);
            this.isEdit = false;
          }
          break;
        case Constants.noticeTypeFinger:
          if ([MULTI_PIN, SIX_PIN].includes(this.state)) {
            return;
          }
          if (sensorInfo && JSON.stringify(sensorInfo) !== '{}') {
            this.fingerPosition = JSON.parse(sensorInfo);
            switch (this.fingerPosition.sensorType) {
              case 'OUT_OF_SCREEN_SENSOR': {
                stateNew = OFF_SCREEN_FINGER;
                break;
              }
            }
            const displayClass = display.getDefaultDisplaySync();
            this.screen = [displayClass.width, displayClass.height];
          }
          if (remainAttempts) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_fp_retry_s2'));
            if (num !== 'first' && remainAttempts > AUTH_LOCK) {
              AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
            }
          }
          if (num === 'first') {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_inscreen_fp'));
          }
          if (remainAttempts === AUTH_LOCK) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'));
            if (this.dialogType === DialogType.PIN_FINGER) {
              if (this.pinSubType !== Constants.pinSix) {
                stateNew = MULTI_PIN;
              } else {
                stateNew = SIX_PIN;
              }
            }
          }
          break;
        default:
          LogUtils.error(TAG, 'onCmdDataChange default');
          break;
      }
      this.state = stateNew;
    })
  }

  countTime(freezingTime): void {
    const TRY_AGAIN = globalThis.context.resourceManager
      .getStringSync($r('app.string.unified_authwidget_postretry'));
    let promptText: string = '';
    let freezingMillisecond = freezingTime;
    // O: freezing FINISH
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

  onFingerPrintFontColor(prompt: string, context: Context): Resource {
    switch (prompt) {
      case context?.resourceManager
      ?.getStringSync($r('app.string.unified_authwidget_hint_fp_retry_s2')):
      case context?.resourceManager
      ?.getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden')):
        return $r('sys.color.ohos_id_color_warning');
      case context?.resourceManager
      ?.getStringSync($r('app.string.unified_authwidget_hint_fp_verify_success')):
      case context?.resourceManager
      ?.getStringSync($r('app.string.unified_authwidget_hint_inscreen_fp')):
        return $r('sys.color.ohos_id_color_text_secondary');
    }
  }

  getFingerPosition(type: string): Resource {
    switch (type) {
      case 'BACK':
        return $r('app.media.icon_applock_2');
      case 'FRONT':
        return $r('app.media.icon_applock_3');
      case 'SIDE':
        return $r('app.media.icon_applock_4');
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
            if (this.state === OFF_SCREEN_FINGER) {
              Text(globalThis.wantParams?.title)
                .margin({ top: $r('app.float.title_padding_top') })
                .fontSize($r('sys.float.ohos_id_text_size_body1'))
                .fontColor($r('sys.color.ohos_id_color_text_primary'))
                .fontWeight(FontWeight.Medium)
              Image(this.getFingerPosition(this.fingerPosition?.outOfScreenSensorType))
                .width($r('app.float.image_big'))
                .height($r('app.float.image_big'))
                .margin({ top: $r('app.float.content_padding'), bottom: $r('app.float.content_padding') })

              Text($r('app.string.unified_authwidget_hint_normal_fp_only'))
                .fontColor($r('sys.color.ohos_id_color_text_secondary'))
                .fontSize($r('sys.float.ohos_id_text_size_body2'))
              if (this.dialogType === DialogType.PIN_FINGER) {
                Row() {
                  Column() {
                    Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                      .id('cancelBthState3FingerprintAuth')
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
                    .height($r('app.float.digital_password_mask_height'))
                    .color($r('sys.color.ohos_id_color_list_separator'))
                    .width($r('app.float.divider_width'))
                  Column() {
                    Button($r('app.string.unified_authwidget_usepwd'))
                      .id('usePwdBtnState3FingerprintAuth')
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
                          this.state = MULTI_PIN;
                        } else {
                          this.state = SIX_PIN;
                        }
                      })
                  }.width(Constants.halfContainerWidth)
                }
                .height($r('app.float.btn_height'))
                .margin({ top: $r('app.float.element_margin'), bottom: $r('app.float.content_padding') })
              } else {
                if (!globalThis.wantParams?.navigationButtonText) {
                  Row() {
                    Column() {
                      Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                        .id('cancelDefBtnState3FingerprintAuth')
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
                        .id('cancelBtnState3FingerprintAuth')
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
                      .height($r('app.float.digital_password_mask_height'))
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
            } else if (this.state === PIN_FINGER) {
              if (!this.isLandscape) {
                Text(globalThis.wantParams?.title)
                  .margin({ top: $r('app.float.title_padding_top') })
                  .fontSize($r('sys.float.ohos_id_text_size_body1'))
                  .fontColor($r('sys.color.ohos_id_color_text_primary'))
                  .fontWeight(FontWeight.Medium)
                Image(this.prompt === globalThis.context.resourceManager
                  .getStringSync($r('app.string.unified_authwidget_hint_fp_verify_success'))
                  ? $r('app.media.right_faceID') : $r('app.media.ic_blue_fingerprint'))
                  .margin({
                    top: $r('app.float.digital_password_mask_height'),
                    bottom: $r('app.float.digital_password_mask_height')
                  })
                  .id('blueFingerprintImgState2FingerprintAuth')
                  .width(px2vp(this.fingerPosition.udSensorRadiusInPx * RADIUS))
                  .height(px2vp(this.fingerPosition.udSensorRadiusInPx * RADIUS))
                  .onClick(() => {
                    if (this.prompt !== globalThis.context.resourceManager
                      .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
                      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
                    }
                  })
                Text(this.prompt)
                  .fontColor(this.onFingerPrintFontColor(this.prompt, globalThis.context))
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
                Row() {
                  Column() {
                    Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                      .id('cancelBtnState2FingerprintAuth')
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
                    .height($r('app.float.digital_password_mask_height'))
                    .color($r('sys.color.ohos_id_color_list_separator'))
                    .width($r('app.float.divider_width'))
                  Column() {
                    Button($r('app.string.unified_authwidget_usepwd'))
                      .id('usePwdBtnState2FingerprintAuth')
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
                          this.state = MULTI_PIN;
                        } else {
                          this.state = SIX_PIN;
                        }
                      })
                  }.width(Constants.halfContainerWidth)
                }
                .height($r('app.float.btn_height'))
                .margin({ top: $r('app.float.element_margin'), bottom: $r('app.float.content_padding') })
              }
            } else if (this.state === SINGLE_FINGER) {
              if (!this.isLandscape) {
                Text(globalThis.wantParams?.title)
                  .margin({ top: $r('app.float.title_padding_top') })
                  .fontSize($r('sys.float.ohos_id_text_size_body1'))
                  .fontColor($r('sys.color.ohos_id_color_text_primary'))
                  .fontWeight(FontWeight.Medium)
                Image(this.prompt === globalThis.context.resourceManager
                  .getStringSync($r('app.string.unified_authwidget_hint_fp_verify_success'))
                  ? $r('app.media.right_faceID') : $r('app.media.ic_blue_fingerprint'))
                  .margin({
                    top: $r('app.float.digital_password_mask_height'),
                    bottom: $r('app.float.digital_password_mask_height')
                  })
                  .id('blueFingerprintState1FingerprintAuth')
                  .width(px2vp(this.fingerPosition.udSensorRadiusInPx * RADIUS))
                  .height(px2vp(this.fingerPosition.udSensorRadiusInPx * RADIUS))
                  .onClick(() => {
                    if (this.prompt !== globalThis.context.resourceManager
                      .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
                      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
                    }
                  })
                Text(this.prompt)
                  .fontColor(this.onFingerPrintFontColor(this.prompt, globalThis.context))
                  .fontSize($r('sys.float.ohos_id_text_size_body2'))
                if (!globalThis.wantParams?.navigationButtonText) {
                  Row() {
                    Column() {
                      Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                        .id('cancelDefBtnState1FingerprintAuth')
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
                        .id('cancelBtnState1FingerprintAuth')
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
                      .height($r('app.float.digital_password_mask_height'))
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
            } else if (this.state === MULTI_PIN) {
              // Password 32-bit
              Column() {
                PassWord({
                  textValue: $textValue,
                  inputValue: $inputValue,
                  isEdit: $isEdit,
                  pinSubType: $pinSubType
                })
                Row() {
                  Column() {
                    Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                      .id('cancelBtnState5FingerprintAuth')
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
                    .height($r('app.float.digital_password_mask_height'))
                    .color($r('sys.color.ohos_id_color_list_separator'))
                    .width($r('app.float.divider_width'))
                  Column() {
                    Button($r('app.string.unified_authwidget_confirm'))
                      .id('okBthState5FingerprintAuth')
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
            } else if (this.state === SIX_PIN) {
              // Password 6-bit
              Column() {
                SixPassword({
                  textValue: $textValue,
                  inputValue: $inputValue,
                  isEdit: $isEdit
                })
                Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                  .id('cancelState6FingerprintAuth')
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
          }
          .backgroundColor($r('sys.color.ohos_id_color_dialog_bg'))
          .borderRadius($r('sys.float.ohos_id_corner_radius_dialog'))
          .position({
            y: (this.isLandscape || !this.fingerPosition.udSensorCenterYInThousandth)
              ? (this.state === OFF_SCREEN_FINGER
                ? OUT_SENSOR - this.SYSTEM_NAVIGATION_BAR_HEIGHT : NORMAL_POSITION)
              : (px2vp(this.screen[1]) * this.fingerPosition.udSensorCenterYInThousandth / THOUSANDTH)
                - px2vp(this.screen[1]) - MARGIN_TOP - px2vp(this.fingerPosition.udSensorRadiusInPx)
          })
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
    .id('fingerprintAuth')
  }
}

