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
import PassWord from '../../common/components/PassWord';
import SixPassword from '../../common/components/SixPassword';
import AuthUtils from '../../common/utils/AuthUtils';
import FuncUtils from '../../common/utils/FuncUtils';
import LogUtils from '../../common/utils/LogUtils';
import TimeUtils from '../../common/utils/TimeUtils';
import Constants, { CmdType } from '../../common/vm/Constants';

const TAG = 'PasswordAuth';
const INTERVAL = 1000;
const BUTTON_OPACITY = 1;
const TEXT_LENGTH = 4;

let pinAuthManager;
let pinData = '';

@Component
export default struct PasswordAuth {
  @Link pinSubType: string;
  @State @Watch('onTextValueChange') textValue: string = '';
  @Link @Watch('onCmdDataChange') cmdData: Array<CmdType>;
  @State isEdit: boolean = true;
  // tip
  @State inputValue: string = ' ';
  @StorageLink('SYSTEM_NAVIGATION_BAR_HEIGHT') SYSTEM_NAVIGATION_BAR_HEIGHT: number = 0;

  onTextValueChange(): void {
    pinData = this.textValue;
  }

  onCmdDataChange(num?: string): void {
    this.cmdData.length > 0 && this.cmdData.map((item) => {
      const { type,remainAttempts, lockoutDuration} = item.payload;
      if (type === Constants.noticeTypePin) {
        if (remainAttempts) {
          this.inputValue = globalThis.context.resourceManager
            .getStringSync($r('app.string.unified_authwidget_hint_pwd_error'));
          this.textValue = '';
          if (num === 'first') {
            this.inputValue = '';
          }
          // pin auth Remaining number
          if (remainAttempts < 3) {
            this.inputValue = globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_pwd_error_can_try'))
            + remainAttempts + globalThis.context.resourceManager
              .getStringSync($r('app.string.unified_authwidget_frequency'));
          }
          return;
        }
        // pin auth Remaining number
        if (remainAttempts === 0 && lockoutDuration) {
          this.countTime(lockoutDuration);
          this.isEdit = false;
          this.textValue = '';
          return;
        }
        this.inputValue = globalThis.context.resourceManager
          .getStringSync($r('app.string.unified_authwidget_hint_pwd_error'));
        this.textValue = '';
      }
    })
  }

  aboutToAppear(): void {
    try {
      if (this.cmdData && this.cmdData.length > 0) {
        this.onCmdDataChange('first');
      }
      LogUtils.info(TAG, 'aboutToAppear PINAuth start');
      pinAuthManager = new account_osAccount.PINAuth();
      // register input
      pinAuthManager.registerInputer({
        onGetData: (authSubType, callback) => {
          LogUtils.info(TAG, 'aboutToAppear registerInputer onGetData');
          const uint8PW = FuncUtils.getUint8PW(pinData);
          callback.onSetData(authSubType, uint8PW);
        }
      });
    } catch (error) {
      LogUtils.error(TAG, 'aboutToAppear PINAuth catch error: ' + error?.code);
      globalThis.session?.terminateSelf?.();
    }
  }

  aboutToDisappear(): void {
    LogUtils.info(TAG, 'aboutToAppear pinAuthManager unregisterInputer');
    pinAuthManager?.unregisterInputer?.();
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
            if (this.pinSubType !== Constants.pinSix) {
              // arbitrary input
              Column() {
                PassWord({
                  pinSubType: $pinSubType,
                  textValue: $textValue,
                  inputValue: $inputValue,
                  isEdit: $isEdit,
                })
                Row() {
                  Column() {
                    Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                      .margin({ left: $r('app.float.content_padding') })
                      .width('90%')
                      .height($r('app.float.btn_height'))
                      .fontSize($r('sys.float.ohos_id_text_size_button1'))
                      .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                      .fontWeight(FontWeight.Medium)
                      .backgroundColor(Color.Transparent)
                      .onClick(() => {
                        globalThis.session?.terminateSelf?.();
                      })
                      .id('cancelBtnDialogPwd')
                  }.width('50%')

                  Divider()
                    .vertical(true)
                    .height($r('app.float.btn_height'))
                    .color($r('sys.color.ohos_id_color_list_separator'))
                    .width($r('app.float.divider_width'))
                  Column() {
                    Button($r('app.string.unified_authwidget_confirm'))
                      .onClick(async () => {
                        AuthUtils.getInstance().sendNotice('EVENT_AUTH_TYPE_READY', [Constants.noticeTypePin]);
                      })
                      .enabled(this.textValue.length >= TEXT_LENGTH)
                      .margin({ right: $r('app.float.content_padding') })
                      .width('90%')
                      .height($r('app.float.btn_height'))
                      .fontSize($r('sys.float.ohos_id_text_size_button1'))
                      .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                      .opacity(this.textValue.length >= TEXT_LENGTH
                        ? BUTTON_OPACITY
                        : $r('sys.float.ohos_fa_alpha_disabled'))
                      .fontWeight(FontWeight.Medium)
                      .backgroundColor(Color.Transparent)
                      .id('okBtn')
                  }.width('50%')
                }
                .height($r('app.float.btn_height'))
                .margin({ top: $r('app.float.element_margin'), bottom: $r('app.float.content_padding') })
              }
            } else {
              // six number
              Column() {
                SixPassword({
                  textValue: $textValue,
                  inputValue: $inputValue,
                  isEdit: $isEdit
                })
                Button($r('app.string.unified_authwidget_cancel'), { stateEffect: true })
                  .onClick(() => {
                    globalThis.session?.terminateSelf?.();
                    this.textValue = '';
                    this.inputValue = ' ';
                  })
                  .backgroundColor(Color.Transparent)
                  .height($r('app.float.btn_height'))
                  .width('50%')
                  .margin({ top: $r('app.float.element_margin'), bottom: $r('app.float.content_padding') })
                  .fontSize($r('sys.float.ohos_id_text_size_button1'))
                  .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
                  .fontWeight(FontWeight.Medium)
                  .id('cancelBtnDialogSixPwd')
              }
            }
          }
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
    .margin({ bottom: this.SYSTEM_NAVIGATION_BAR_HEIGHT })
    .height('100%')
    .justifyContent(FlexAlign.End)
    .backgroundColor(Color.Transparent)
  }
}
