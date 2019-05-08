//
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
// Created by Jason Leach on 2018-11-05.
//

/* eslint-env es6 */

'use strict';
global.console.warn = jest.fn();
import fs from 'fs';
import path from 'path';
import { ImplicitAuthManager } from '../src/libs/ImplicitAuthManager';

const path0 = path.join(__dirname, 'fixtures/jwt-rs256-20181205.txt');
const encoded = fs.readFileSync(path0, 'utf8')

const path1 = path.join(__dirname, 'fixtures/jwt-decoded-20181105.json');
const decoded = JSON.parse(fs.readFileSync(path1, 'utf8'));

describe('Test ImplicitAuthManager', () => {
    let im;
  
    beforeEach(() => {
      im = new ImplicitAuthManager({
        clientId: decoded.aud, 
        realmName: 'blarb', 
        baseURL: 'https://example.com'
      });

      ImplicitAuthManager.isAReplayAttack = (key) => false;
      im.saveAuthDataInLocal(encoded, encoded);
    });
  
    test('The correct roles are parsed from the JWT', () => {
      expect(im.roles).toEqual(decoded.roles);
    });
  });