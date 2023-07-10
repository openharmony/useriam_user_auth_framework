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

import account_osAccount from '@ohos.account.osAccount';
import userAuth from '@ohos.userIAM.userAuth';
import CustomPSD from '../../common/components/CustomPSD'
import FuncUtils from '../../common/utils/FuncUtils';
import LogUtils from '../../common/utils/LogUtils';
import Constants from '../../common/vm/Constants';

const TAG = 'CustomPassword';
const WHITE_OPACITY = 1;
const BLUR_OPACITY = 0.2;
const BTN_BORDER_RADIUS = 25;

let pinAuthManager;
let pinData = '';

@Component
export default struct CustomPassword {
  @Link pinSubType: string;
  @Link themeType: number;
  @Link authType: Array<userAuth.UserAuthType>;
  @Link cmdData: [];
  @State isBackTouched: boolean = false
  @State @Watch('onFlagChange') controllerFlag: boolean = false;
  @State @Watch('onTextValueChange') textValue: string = '';

  onFlagChange(): void {
    LogUtils.i(TAG, 'onFlagChange controllerFlag: ' + this.controllerFlag);
    if (this.controllerFlag) {
      globalThis.session?.terminateSelf?.();
    }
  }

  onTextValueChange(): void {
    pinData = this.textValue;
  }

  aboutToAppear(): void {
    // register input
    try {
      LogUtils.i(TAG, 'aboutToAppear PINAuth start');
      pinAuthManager = new account_osAccount.PINAuth();
      LogUtils.i(TAG, 'aboutToAppear PINAuth pinAuthManager： ' + JSON.stringify(pinAuthManager));
      pinAuthManager.registerInputer({
        onGetData: (authSubType, callback) => {
          const uint8PW = FuncUtils.getUint8PW(pinData);
          LogUtils.i(TAG, 'PINAuth onGetData pinData');
          callback.onSetData(authSubType, uint8PW);
        }
      });
    } catch (error) {
      LogUtils.e(TAG, 'aboutToAppear PINAuth catch error: ' + JSON.stringify(error));
    }
  }

  aboutToDisappear(): void {
    LogUtils.i(TAG, 'aboutToDisappear PINAuth unregisterInputer');
    pinAuthManager?.unregisterInputer?.();
  }

  build() {
    Stack() {
      Text().width(Constants.fullContainerWidth)
        .height(Constants.fullContainerWidth)
        .backgroundColor($r('sys.color.ohos_id_color_dialog_bg'))
        .opacity(this.themeType === Constants.themeTypeWhite ? WHITE_OPACITY : BLUR_OPACITY)
      Column() {
        Flex({ direction: FlexDirection.Row }) {
          if (this.themeType === Constants.themeTypeWhite) {
            Flex() {
              Text('←')
                .borderRadius(8)
                .fontSize($r('app.float.title_size'))
                .backgroundColor(Color.Transparent)
                .fontColor(Color.Black)
              Text($r('app.string.unified_authwidget_back'))
                .fontSize($r('app.float.title_size'))
                .fontWeight(FontWeight.Medium)
                .fontColor(Color.Black)
                .textAlign(TextAlign.Center)
                .textOverflow({ overflow: TextOverflow.None })
                .margin({ left: 12 })
            }
            .id('cancelIcon_customPwd')
            .margin({ left: $r('sys.float.ohos_id_max_padding_start'), right: $r('app.float.element_margin'), top:
            '2vp' })
            .padding($r('app.float.back_padding'))
            .width($r('app.float.back_width'))
            .backgroundColor(this.isBackTouched ? $r('sys.color.ohos_id_color_hover') : Color.Transparent)
            .borderRadius(BTN_BORDER_RADIUS)
            .onClick(() => {
              globalThis.session?.terminateSelf?.();
            })
            .onTouch((event: TouchEvent) => {
              if (event.type === TouchType.Down) {
                this.isBackTouched = true;
              }
              if (event.type === TouchType.Up) {
                this.isBackTouched = false;
              }
            });
          } else {
            Image($r('app.media.ic_white_cancel'))
              .id('cancelImg_customPwd')
              .width($r('app.float.image_small'))
              .height($r('app.float.image_small'))
              .margin({ left: $r('app.float.element_margin'), top: $r('app.float.element_margin') })
              .backgroundColor(this.isBackTouched ? $r('sys.color.ohos_id_color_hover') : Color.Transparent)
              .onClick(() => {
                globalThis.session?.terminateSelf?.();
              })
              .onTouch((event: TouchEvent) => {
                if (event.type === TouchType.Down) {
                  this.isBackTouched = true;
                }
                if (event.type === TouchType.Up) {
                  this.isBackTouched = false;
                }
              });
          }
        }

        GridRow({
          columns: 8,
          gutter: { x: 5, y: 10 },
          breakpoints: { value: Constants.deviceDpi,
            reference: BreakpointsReference.WindowSize },
          direction: GridRowDirection.Row
        }) {
          GridCol({ span: { xs: 0, sm: 1, md: 1, lg: 1 } })
            .visibility(Visibility.Hidden)
          GridCol({
            span: { xs: 8, sm: 6, md: 6, lg: 6 },
          }) {
            CustomPSD({
              themeType: $themeType,
              textValue: $textValue,
              controllerFlag: $controllerFlag,
              authType: $authType,
              pinSubType: $pinSubType,
              cmdData: $cmdData
            })
          }.margin({ left: 'auto', right: 'auto' })
        }
      }
      .justifyContent(FlexAlign.SpaceBetween)
      .width(Constants.fullContainerWidth)
      .height(Constants.fullContainerWidth)
    }
    .width(Constants.fullContainerWidth)
    .height(Constants.fullContainerWidth)
    .backdropBlur(80)
  }
}