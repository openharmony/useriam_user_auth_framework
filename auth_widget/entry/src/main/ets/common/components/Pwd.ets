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

import Constants from '../../common/vm/Constants';

@Component
export default struct Pwd {
  @Link pinSubType: string;
  @Link @Watch('onTextValueChange') textValue: string;
  @Link inputValue: string;
  @Link isEdit: boolean;
  @StorageLink('passwordArrNumber') passwordArrNumber: string[] = [];
  controller: CustomDialogController;
  cancel: () => void;
  confirm: () => void;

  onTextValueChange(): void {
    this.passwordArrNumber = this.textValue.replace(/[^\d]/g, '').split('');
  }

  clearPassword(): void {
    this.passwordArrNumber = [];
    this.textValue = '';
    this.inputValue = ' ';
  }

  aboutToDisappear(): void {
    this.clearPassword();
  }

  build() {
    Column() {
      Text(globalThis.wantParams?.title)
        .margin({ top: $r('app.float.content_padding_top') })
        .fontSize($r('sys.float.ohos_id_text_size_body1'))
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .fontWeight(FontWeight.Medium)
      TextInput({
        placeholder: '',
        text: this.pinSubType === Constants.pinNumber ? this.passwordArrNumber.join('') : this.textValue
      })
        .maxLength(32)
        .enabled(this.isEdit)
        .height($r('app.float.input_height'))
        .type(InputType.Password)
        .margin({
          top: $r('app.float.content_padding'),
          left: $r('app.float.content_padding'),
          right: $r('app.float.content_padding')
        })
        .textAlign(TextAlign.Center)
        .fontColor($r('sys.color.ohos_id_color_text_primary'))
        .border({
          width: this.inputValue === ' ' ? '' : $r('app.float.input_border'),
          color: this.inputValue === ' ' ? '' : ($r('sys.color.ohos_id_color_warning'))
        })
        .onChange((value: string) => {
          if (this.pinSubType === Constants.pinNumber) {
            this.passwordArrNumber = value.replace(/[^\d]/g, '').split('');
          }
          this.textValue = value;
        })
        .id('pinInput_mix')
      Text(this.inputValue)
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .margin({ top: $r('app.float.element_margin') })
        .fontColor($r('sys.color.ohos_id_color_warning'))
    }
  }
}