// Devhub
//
// Copyright © 2018 Province of British Columbia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Adapted by Patrick Simonian on 2018-09-28.
//

/**
 * A dependable Type Checking Utility
 * Type checking using the native typeof or instanceof can cause issues at times
 * as explained by https://juhukinners.wordpress.com/2009/01/11/typeof-considered-useless-or-how-to-write-robust-type-checks/
 */
export default class TypeCheck {
  static getClass(object) {
    // eslint-disable-next-line no-console
    console.warn(
      'TypeCheck is deprecated in favor of better supported type checking libraries.\n Consider using lodash https://lodash.com as TypeCheck will no longer be supported as of v1.0.0'
    );
    return Object.prototype.toString.call(object).slice(8, -1);
  }

  static isArray(object) {
    return TypeCheck.getClass(object) === 'Array';
  }

  static isObject(object) {
    return TypeCheck.getClass(object) === 'Object';
  }

  static isFunction(object) {
    return TypeCheck.getClass(object) === 'Function';
  }

  static isBoolean(object) {
    return TypeCheck.getClass(object) === 'Boolean';
  }

  static isNumber(object) {
    return TypeCheck.getClass(object) === 'Number';
  }

  static isString(object) {
    return TypeCheck.getClass(object) === 'String';
  }

  static isAsyncFunction(object) {
    return object[Symbol.toStringTag] === 'AsyncFunction';
  }

  static isDate(object) {
    return TypeCheck.getClass(object) === 'Date';
  }

  static isMap(object) {
    return TypeCheck.getClass(object) === 'Map';
  }

  static isRegExp(object) {
    return TypeCheck.getClass(object) === 'RegExp';
  }

  static isArrayOf(objectContructor, object) {
    if (!TypeCheck.isArray(object)) return false;

    return object.every(item => TypeCheck.isA(objectContructor, item));
  }

  /**
   * helper to match an object with a referer
   * @param {Object} ObjectConstructor one of the javascript data type constructors
   * @param {Object} object
   * @returns {Boolean}
   * TypeCheck.isA(String, "this is a string"); => true
   * TypeCheck.isA(Array, [1, 3, 5]); => true
   */
  static isA(ObjectContstructor, object) {
    if (!TypeCheck.isFunction(ObjectContstructor)) {
      throw new Error(
        'objectContructor must be one of the javascript object constructors: String, Function, Boolean etc.'
      );
    }
    return TypeCheck.getClass(object) === TypeCheck.getClass(new ObjectContstructor());
  }
}
