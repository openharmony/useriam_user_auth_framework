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

import display from '@ohos.display';
import screen from '@ohos.screen';
import userAuth from '@ohos.userIAM.userAuth';
import Constants, { CmdType, FingerPosition } from '../../common/vm/Constants';
import AuthUtils from '../utils/AuthUtils';
import LogUtils from '../utils/LogUtils';
import TimeUtils from '../utils/TimeUtils';
import NumKeyBoard from './NumkeyBoard';

const TAG = 'CustomPSD';
const INTERVAL = 1000;
const DIGITALPSD_IC_DIAMETER = 12;

interface ControlType {
  isSixPassword?: boolean,
  isLandscape: boolean,
  jumpFinger: boolean,
  isShowFace: boolean,
  isShowFinger: boolean,
}

interface KeyboardType {
  index: number,
  row1: string | Resource,
  row2?: string,
  value?: number,
  bkg?: boolean,
}

@Component
export default struct CustomPSD {
  @Link pinSubType: string;
  @Link textValue: string;
  @Link themeType: number;
  @Link controllerFlag: boolean;
  @Link authType: Array<userAuth.UserAuthType>;
  @Link @Watch('onCmdDataChange') cmdData: Array<CmdType>;
  @State lock: number = 0;
  @State screenClass: object = {};
  @StorageLink('cueWord') cueWord: string = globalThis.context.resourceManager
    .getStringSync($r('app.string.unified_authwidget_use_pwd'));
  @StorageLink('passwordArr') passwordArr: string[] = ['', '', '', '', '', ''];
  @StorageLink('passwordArrNumber') passwordArrNumber: string[] = [];
  @State passwordObj: string = '';
  numKeyboard: KeyboardType[] = Constants.numKeyBoard;
  @State prompt: string = globalThis.context.resourceManager
    .getStringSync($r('app.string.unified_authwidget_use_pwd'));
  @State fingerText: string = globalThis.context.resourceManager
    .getStringSync($r('app.string.unified_authwidget_hint_inscreen_fp'));
  @StorageLink('screenLockDirection') screenLockDirection: number = 1;
  @State controlType: ControlType = {
    jumpFinger: false,
    isLandscape: false,
    isSixPassword: true,
    isShowFace: this.authType.includes(2),
    isShowFinger: this.authType.includes(4)
  }
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

  onCmdDataChange(num?: string): void {
    this.cmdData.length > 0 && this.cmdData.map((item) => {
      const { type,remainAttempts, lockoutDuration,sensorInfo} = item.payload;
      switch (type) {
        case Constants.noticeTypePin:
          this.clearPassword();
          if (remainAttempts) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_pwd_error'));
            if (num === 'first') {
              this.prompt = globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_use_pwd'));
            }
            if (remainAttempts < 3) {
              this.prompt = globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_pwd_error_can_try'))
              + remainAttempts + globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_frequency'));
            }
          }
          if (remainAttempts === 0 && lockoutDuration) {
            this.lock = 1;
            this.countdown(lockoutDuration);
          }

          if (!remainAttempts && !lockoutDuration) {
            this.lock = 1;
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
          }
          if (remainAttempts) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_fp_retry_s2'));
            this.fingerText = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_hint_fp_retry_s2'));
          }
          if (num === 'first') {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_use_pwd'));
          }
          if (remainAttempts === 0) {
            this.prompt = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'));
            this.fingerText = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'));
          }
        default:
          break;
      }
    })
  }

  aboutToAppear(): void {
    AppStorage.SetOrCreate('passwordArr', ['', '', '', '', '', '']);
    this.queryScreenInfo();
    AuthUtils.getInstance().sendNotice('CMD_NOTIFY_AUTH_START', [Constants.noticeTypePin]);
    if (this.cmdData && this.cmdData.length > 0) {
      this.onCmdDataChange('first');
    }
    if (this.controlType.isShowFace) {
      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFace]);
    }
  }

  clearPassword(): void {
    this.passwordArr = [];
    this.passwordArrNumber = [];
    this.passwordArr = ['', '', '', '', '', ''];
    this.numKeyboard[11].value = Constants.goBack;
    this.updateStorage(() => {
    })
  }

  aboutToDisappear(): void {
    this.clearPassword();
  }

  countdown(freezingTime): void {
    const TRY_AGAIN = globalThis.context.resourceManager.getStringSync($r('app.string.unified_authwidget_postretry'));
    let promptText: string = '';
    let freezingMillisecond = freezingTime;
    if (freezingMillisecond > 0) {
      promptText = TimeUtils.getFreezingTimeNm(freezingMillisecond, globalThis.context);
      promptText += TRY_AGAIN;
      setTimeout(this.countdown.bind(this), INTERVAL, freezingTime - INTERVAL);
    } else {
      promptText = globalThis.context.resourceManager.getStringSync($r('app.string.unified_authwidget_use_pwd'));
      this.clearPassword();
      this.lock = 0;
    }
    this.prompt = promptText;
  }

  updateStorage(callback): void {
    AppStorage.SetOrCreate('passwordArr', this.passwordArr);
    AppStorage.SetOrCreate('numKeyboard', this.numKeyboard);
    callback();
  }

  build() {
    if (!this.controlType.jumpFinger) {
      Column() {
        Column() {
          if (this.lock === 1) {
            Text($r('app.string.unified_authwidget_locked'))
              .margin({ bottom: '16vp' })
              .fontColor(this.themeType === Constants.themeTypeWhite
                ? $r('sys.color.ohos_id_color_text_primary')
                : $r('sys.color.ohos_id_color_text_primary_contrary'))
              .fontSize($r('sys.float.ohos_id_text_size_headline6'))
              .fontWeight(FontWeight.Medium)
          }
          if (this.controlType.isShowFace) {
            if (this.themeType === Constants.themeTypeGaussianBlur) {
              Image($r('app.media.white_faceID'))
                .id('faceImg_customPwd')
                .width('30vp')
                .height('30vp')
                .margin({ bottom: '16vp' })
                .onClick(() => {
                  if (this.prompt !== globalThis.context.resourceManager
                    .getStringSync($r('app.string.unified_authwidget_title_number_failed_face_forbidden')) &&
                  this.prompt !== globalThis.context.resourceManager
                    .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
                    AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFace]);
                  }
                })
            }
            if (this.themeType === Constants.themeTypeWhite) {
              Image($r('app.media.error_faceID'))
                .width('30vp')
                .height('30vp')
                .margin({ bottom: '16vp' })
                .visibility(Visibility.Visible)
                .colorBlend($r('sys.color.ohos_id_color_activated'))
            }
          }
          Text(this.prompt)
            .id('textPrompt_customPwd')
            .fontSize(this.prompt === globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_use_pwd'))
              ? $r('sys.float.ohos_id_text_size_body1')
              : $r('sys.float.ohos_id_text_size_body2'))
            .fontWeight(FontWeight.Medium)
            .fontColor(this.themeType === Constants.themeTypeWhite
              ? $r('sys.color.ohos_id_color_text_primary')
              : $r('sys.color.ohos_id_color_text_secondary_contrary'))
            .margin({ bottom: '8vp' })
            .textAlign(TextAlign.Center)
            .textOverflow({ overflow: TextOverflow.None })
            .height('20vp')
            .onClick(() => {
              if (this.prompt === globalThis.context.resourceManager
                .getStringSync($r('app.string.unified_authwidget_hint_face_verify_fail_click_retry_s1'))) {
                this.prompt = globalThis.context.resourceManager
                  .getStringSync($r('app.string.unified_authwidget_hint_recognition'));
                AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFace]);
              }
            })

          Flex({ alignItems: ItemAlign.Center, justifyContent: FlexAlign.Center }) {
            if (this.lock === 0) {
              if (this.pinSubType === Constants.pinSix) {
                List({ space: DIGITALPSD_IC_DIAMETER }) {
                  ForEach(this.passwordArr, (item) => {
                    if ((!item || item === '') && item !== 0) {
                      ListItem() {
                        Button()
                          .border({
                            color: this.themeType === Constants.themeTypeWhite ? Color.Black : Color.White,
                            style: BorderStyle.Solid,
                            width: 1
                          })
                          .borderRadius('12vp')
                          .width('12vp')
                          .height('12vp')
                          .type(ButtonType.Circle)
                          .backgroundColor(Color.Transparent)

                      }
                      .margin({ left: '5vp', right: '5vp' })
                    } else {
                      ListItem() {
                        Button()
                          .borderRadius('12vp')
                          .width('12vp')
                          .height('12vp')
                          .type(ButtonType.Circle)
                          .backgroundColor(this.themeType === Constants.themeTypeWhite ? Color.Black : Color.White)
                      }
                      .margin({ left: '5vp', right: '5vp' })
                    }
                  })
                }
                .listDirection(Axis.Horizontal)
                .height('12vp')

              } else if (this.pinSubType === Constants.pinNumber) {
                Stack() {
                  TextInput({ placeholder: '', text: this.passwordArrNumber.join('') })
                    .width('100%')
                    .onChange(async (value: string) => {
                      this.passwordArrNumber = value.replace(/[^\d]/g, '').split('');
                    })
                    .id('pinInput_number')
                    .onSubmit(async (enterKey: EnterKeyType) => {
                      let str = this.passwordArrNumber.toString();
                      this.textValue = str.replace(/,/g, '');
                      if (this.passwordArrNumber.length < 4) {
                        return;
                      }

                      const strData = this.passwordArrNumber.toString();
                      this.textValue = strData.replace(/,/g, '');
                      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypePin]);
                    })
                    .type(InputType.Password)
                    .backgroundImageSize(ImageSize.Auto)
                    .visibility(Visibility.Visible)
                    .copyOption(CopyOptions.None)
                    .maxLength(32)

                }
              } else if (this.pinSubType === Constants.pinMixed) {
                TextInput({ text: this.passwordObj })
                  .height('40vp')
                  .type(InputType.Password)
                  .textAlign(TextAlign.Center)
                  .copyOption(CopyOptions.None)
                  .maxLength(32)
                  .onSubmit(async (enterKey: EnterKeyType) => {
                    // check callback
                    if (this.passwordObj.length < 4) {
                      return;
                    }
                    this.textValue = this.passwordObj;
                    AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypePin]);
                  })
                  .onChange((value: string) => {
                    this.passwordObj = value;
                  })
                  .id('pinInput')
              }
            }
          }
          .width(this.screenLockDirection === 1 ? $r('app.float.custompsd_input_width')
                                                : $r('app.float.custompsd_input_width_portrait'))
          .height('40vp')

          Button(($r('app.string.unified_authwidget_forgotpwd')), {
            stateEffect: true
          })
            .id('forgotBtn_customPwd')
            .height('40vp')
            .backgroundColor(Color.Transparent)
            .fontColor(this.themeType === Constants.themeTypeWhite
              ? $r('sys.color.ohos_id_color_text_primary_activated')
              : $r('sys.color.ohos_id_color_text_primary_contrary'))
            .fontSize($r('sys.float.ohos_id_text_size_button1'))
            .fontWeight(FontWeight.Medium)
            .onClick(() => {
              let str = this.passwordArrNumber.toString()
              this.textValue = str.replace(/,/g, '');
            })
        }

        Column() {
          if (this.lock === 0 && this.pinSubType === Constants.pinSix) {
            NumKeyBoard({
              themeType: $themeType,
              onKeyPress: (index, callback) => {
                let keyValue = this.numKeyboard[index].value;
                if (keyValue > 0 || keyValue === 0) {
                  const index = this.passwordArr.map(item => item).indexOf('')
                  if (index > -1) {
                    this.passwordArr[index] = keyValue + '';
                    this.numKeyboard[11].row1 = $r('app.string.unified_authwidget_delete');
                    this.numKeyboard[11].value = Constants.delPwd;
                    if (index === 5) {
                      this.passwordArr[index] = keyValue + '';
                      if (this.passwordArr.join('').length < 6) {
                        return;
                      }
                      let str = this.passwordArr.toString();
                      this.textValue = str.replace(/,/g, '');
                      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypePin]);
                    }
                    this.updateStorage(callback);
                  }
                } else if (keyValue === Constants.delPwd) {
                  const index = this.passwordArr.map(item => item).indexOf('');
                  if (index === -1) {
                    this.passwordArr[5] = '';
                  } else if (index === 1) {
                    this.passwordArr[index-1] = '';
                    this.numKeyboard[11].value = Constants.goBack;
                    this.numKeyboard[11].row1 = globalThis.context.resourceManager
                      .getStringSync($r('app.string.unified_authwidget_back'));
                  } else {
                    this.passwordArr[index-1] = '';
                  }
                  this.updateStorage(callback);
                } else if (keyValue === Constants.goBack) {
                  this.lock = 0;
                  this.clearPassword();
                  globalThis.session?.terminateSelf?.();
                } else if (keyValue === Constants.callPhone) {
                  if (this.passwordArr.join('').length < 6) {
                    return;
                  }

                  let str = this.passwordArr.toString();
                  this.textValue = str.replace(/,/g, '');
                  AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypePin]);
                }
              }
            })
          } else {
            Text().height(Constants.fullContainerHeight)
          }
        }
        .width(Constants.fullContainerWidth)
        .height('40%')

        Column() {
          if (this.controlType.isShowFinger && this.lock !== 1) {
            if (this.themeType === Constants.themeTypeWhite) {
              if (this.fingerPosition.sensorType === 'OUT_OF_SCREEN_SENSOR'
              || this.fingerPosition.sensorType === 'BOTH_SENSOR'
              || this.fingerPosition.sensorType === 'SensorType1') {
                if (this.fingerPosition.udSensorCenterYInThousandth / this.screen[1] > 0.75) {
                  Image($r('app.media.ic_blue_fingerprint'))
                    .id('fingerprintImg_customPwd')
                    .width(px2vp(this.fingerPosition.udSensorRadiusInPx))
                    .height(px2vp(this.fingerPosition.udSensorRadiusInPx))
                    .position({
                      x: px2vp(this.fingerPosition.udSensorCenterXInThousandth),
                      y: px2vp(this.fingerPosition.udSensorCenterYInThousandth)
                    })
                    .onClick(() => {
                      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
                    })
                } else {
                  Image($r('app.media.finger_guide'))
                    .id('fingerWhiteImg_customPwd')
                    .width('24vp')
                    .height('24vp')
                    .margin({ top: '12vp' })
                    .onClick(() => {
                      this.controlType.jumpFinger = true;
                    })
                }
              }
            }
            if (this.themeType === Constants.themeTypeGaussianBlur) {
              if (this.fingerPosition.sensorType === 'OUT_OF_SCREEN_SENSOR'
              || this.fingerPosition.sensorType === 'BOTH_SENSOR'
              || this.fingerPosition.sensorType === 'SensorType1') {
                if (this.fingerPosition.udSensorCenterYInThousandth / this.screen[1] > 0.75) {
                  Image($r('app.media.ic_unlock_fingerprint'))
                    .id('fingerprintImg_customPwd')
                    .width(px2vp(this.fingerPosition.udSensorRadiusInPx))
                    .height(px2vp(this.fingerPosition.udSensorRadiusInPx))
                    .position({
                      x: px2vp(this.fingerPosition.udSensorCenterXInThousandth),
                      y: px2vp(this.fingerPosition.udSensorCenterYInThousandth)
                    })
                    .onClick(() => {
                      AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
                    })
                } else {
                  Image($r('app.media.finger_white'))
                    .id('fingerWhiteImg_customPwd')
                    .width('24vp')
                    .height('24vp')
                    .margin({ top: '12vp' })
                    .onClick(() => {
                      this.controlType.jumpFinger = true;
                    })
                }

              }
            }
          }

        }.width('24vp')
        .height(this.controlType.isShowFinger ? '72vp' : '9%')
        .justifyContent(FlexAlign.Start)
      }
      .justifyContent(FlexAlign.End)
      .width(Constants.fullContainerWidth)
    } else if (!this.controlType.isLandscape) {
      Column() {
        Text(globalThis.wantParams?.title)
          .height('40vp')
          .fontColor(this.themeType === Constants.themeTypeWhite
            ? $r('sys.color.ohos_id_color_text_primary')
            : $r('sys.color.ohos_id_color_text_primary_contrary'))
          .fontSize($r('sys.float.ohos_id_text_size_sub_title2'))
          .fontWeight(FontWeight.Medium)
          .position({ y: Constants.titlePosition })
          .width('100%')
          .textAlign(TextAlign.Center)
        Text(this.fingerText)
          .height('40vp')
          .fontColor(this.themeType === Constants.themeTypeWhite
            ? $r('sys.color.ohos_id_color_text_secondary')
            : $r('sys.color.ohos_id_color_text_primary_contrary'))
          .fontSize($r('sys.float.ohos_id_text_size_body2'))
          .position({ y: Constants.fingerTextPosition })
          .width('100%')
          .textAlign(TextAlign.Center)
        Image(this.themeType === Constants.themeTypeWhite
          ? $r('app.media.ic_blue_fingerprint')
          : $r('app.media.ic_unlock_fingerprint'))
          .id('unlockFingerprintImg_customPwd')
          .width((this.fingerPosition.udSensorRadiusInPx * 2))
          .height((this.fingerPosition.udSensorRadiusInPx * 2))
          .position({ x: Constants.fingerImgPosition
          , y: (this.fingerPosition.udSensorCenterYInThousandth / Constants.thousandth * this.screen[1] / 2) })
          .onClick(() => {
            if (this.prompt !== globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_title_number_failed_fp_forbidden'))) {
              AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypeFinger]);
            }
          })
        Button($r('app.string.unified_authwidget_cancel'), {
          type: ButtonType.Normal,
          stateEffect: true
        })
          .margin({ bottom: '300vp', left: 'auto', right: 'auto' })
          .backgroundColor(Color.Transparent)
          .fontColor(this.themeType === Constants.themeTypeWhite
            ? $r('sys.color.ohos_id_color_text_secondary')
            : $r('sys.color.ohos_id_color_text_primary_contrary'))
          .onClick(() => {
            this.controlType.jumpFinger = false;
          })
      }
      .justifyContent(FlexAlign.End)
      .height('100%')
      .width('100%')
    } else {
      Column() {
        Text(globalThis.context.resourceManager
          .getStringSync($r('app.string.unified_authwidget_tip_verify_in_portrait_mode')))
          .height('40vp')
          .fontColor(this.themeType === Constants.themeTypeWhite
            ? $r('sys.color.ohos_id_color_text_primary')
            : $r('sys.color.ohos_id_color_text_primary_contrary'))
          .fontSize($r('sys.float.ohos_id_text_size_sub_title2'))
          .fontWeight(FontWeight.Medium)
      }.justifyContent(FlexAlign.End)
      .height('300vp')
      .width('100%')
    }
  }
}