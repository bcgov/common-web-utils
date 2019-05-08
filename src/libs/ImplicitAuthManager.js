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
// Created by Patrick Simonian on 2018-09-28.
//

'use strict';

import hashJs from 'hash.js';
import jwtDecode from 'jwt-decode';
import moment from 'moment';
import {
  deleteDataFromLocalStorage,
  getDataFromLocalStorage,
  saveDataInLocalStorage,
} from './localStorage';
import TypeCheck from './TypeCheck';

// stub crypto if doesn't exist
if (typeof window !== 'undefined' && window.crypto === undefined) {
  window.crypto = {
    getRandomValues: () => [],
  };
}
/**
 * A wrapper around some basic crypto methods
 */

export class CryptoUtils {
  static genCryptographicRandomValue() {
    const charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._~';
    const result = [];
    window.crypto
      .getRandomValues(new Uint8Array(32))
      .forEach(c => result.push(charset[c % charset.length]));
    return result.join('');
  }

  static hashSHA256(value) {
    if (typeof value !== 'string') {
      throw new Error('Value must be of type String in order to hash');
    }
    return hashJs
      .sha256()
      .update(value)
      .digest('hex');
  }

  /**
   * hashes the value and checks against a hash to see if they match
   * @param {string} value
   * @param {string} hashedValue
   * @returns {boolean} true if value matches hash
   */
  static checkAgainstHash(value, hashedValue) {
    return this.hashSHA256(value) === hashedValue;
  }
}
/**
 * Utility Class for Management of OCID Implicit Auth Flow
 * @param {Object} config the config object, * = optional properties
 * @param {String} config.kcIDPHint * identity provider hint so that sso boots you straight to the provider
 * @param {String} config.baseURL  your sso providers base url eg https://something.sso.com/
 * @param {String} config.clientId  client id within your sso realm
 * @param {String} config.realmName  name of your sso realm
 * @param {String | Function} config.redirectURI * Defaults to window.location.origin + intention
 * if redirect URI is a string, during login/logout processes the redirectURI will have a query param appended to it
 * based on the intention of the process: ie if the call to the authorization server is intended for logging in
 * the redirect uri will = redirect_uri + ?intention=LOGIN
 * --
 * you may make the redirect URI a call back function that receives the intention as an argument
 * view the validAPIIntentions static function for all the possible intentions that you may want to handle
 * @param {String} loginURIResponseType * defaults to id_token, options are ['token', 'id_token', 'id_token token']
 * @param {Object} hooks * a set of callback functions that may be utilized to tie in ImplicitAuth Processes to your
 * code
 * @param {Function} hooks.onBeforeAuthRedirect called before a redirect occurs
 * @param {Function} hooks.onAfterAuthRedirect: called after a successful redirect back to your client has occured
 * @param {Function} hooks.onAuthLocalStorageCleared
 * @param {Function} hooks.onTokenExpired
 * @param {Function} hooks.onAuthenticateSuccess
 * @param {Function} hooks.onAuthenticateFail
 */

// ImplicitAuthManager takes two names in the local storage space
// sso and auth. Please ensure these are not being overwritten by other functions.
export class ImplicitAuthManager {
  constructor(config = {}) {
    // default config
    const defaultConfig = this.defaultConfig; // eslint-disable-line
    // validate config
    this.validateConfig(config);
    // merge defaults with config
    this.config = {
      ...defaultConfig,
      ...config,
      hooks: { ...defaultConfig.hooks, ...config.hooks },
    };
    this.baseAuthEndpoint = this.createBaseAuthEndpointFromConfig();
    this.baseLogoutEndpoint = this.createBaseLogoutEndpointFromConfig();
  }

  /**
   * returns the default configuration for the instance
   * usage: instance.defaultConfig
   * @returns {Object}
   * @private
   */
  // eslint-disable-next-line
  get defaultConfig() {
    return {
      loginURIResponseType: 'id_token',
      hooks: {
        onBeforeAuthRedirect: () => undefined,
        onAfterAuthRedirect: () => undefined,
        onAuthLocalStorageCleared: () => undefined,
        onTokenExpired: () => undefined,
        onAuthenticateSuccess: () => undefined,
        onAuthenticateFail: () => undefined,
      },
    };
  }

  /**
   * returns all hooks
   * usage: instance.hooks;
   * @returns {Object}
   * @private
   */
  get hooks() {
    return this.config.hooks;
  }

  /**
   * returns the redirect uri
   * @returns {String}
   */
  get redirectURI() {
    return this.config.redirectURI || window.location.origin;
  }

  /**
   * returns the sso logout uri to be implemented by something like an anchor tag
   * or a 'navigate' function call
   * usage: instance.ssoLogoutURI;
   * @returns {String}
   */
  get ssoLogoutURI() {
    return this.getSSOLogoutURI();
  }

  /**
   * returns the sso login uri to be implemented by something like an anchor tag
   * or a 'navigate' function call
   * * usage: instance.ssoLoginURI;
   * @returns {String}
   */
  get ssoLoginURI() {
    return this.getSSOLoginURI();
  }

  /**
   * returns the access token if exists in local storage
   * @returns {Object | Null}
   */
  get accessToken() {
    return this.getAccessTokenFromLocal();
  }

  /**
   * returns the id token if exists in local storage
   * @returns {Object | Null}
   */
  get idToken() {
    return this.getIdTokenFromLocal();
  }

  /**
   * returns a bearer id token to leverage in an API request header
   * @returns {String}
   */
  get idTokenForRequestHeader() {
    const token = this.getIdTokenFromLocal();
    if (token && token.bearer) {
      return `Bearer ${token.bearer}`;
    }
    return null;
  }

  /**
   * returns a bearer access token to leverage in an API request header
   * @returns {String}
   */
  get accessTokenForRequestHeader() {
    const token = this.getAccessTokenFromLocal();
    if (token && token.bearer) {
      return `Bearer ${token.bearer}`;
    }
    return null;
  }

  /**
   * returns a list of roles from the id token if exists
   * @returns {Array}
   */
  get roles() {
    const { data } = this.getIdTokenFromLocal();
    return data && data.roles ? data.roles : [];
  }

  /**
   *  returns the valid response types for implicit auth flow response_type query param
   *  @returns {Array}
   *  @private
   * */
  static validResponseTypes() {
    return ['id_token', 'token', 'id_token token'];
  }

  /**
   *  returns the valid prompt types for implicit auth flow response_type query param
   *  @returns {Array}
   *  @private
   * */
  static validPromptTypes() {
    return ['none', 'login', 'consent', 'select_account'];
  }

  /**
   *
   * returns valid api intentions which are bound the the redirect uri as a queryparam
   * ?intention=[intention], if redirectURI is a function, the intention is passed in to
   * the redirectURI function so that you may choose how you want to construct your redirectURI
   * @returns {Object}
   * @private
   */
  static validAPIIntentions() {
    return {
      LOGIN: 'LOGIN',
      LOGOUT: 'LOGOUT',
    };
  }

  /**
   * returns valid hooks for validation purposes
   * @returns {Object}
   * @private
   */
  static validHooks() {
    return [
      'onBeforeAuthRedirect',
      'onAuthLocalStorageCleared',
      'onTokenExpired',
      'onAuthenticateSuccess',
      'onAuthenticateFail',
      'onAfterAuthRedirect',
    ];
  }

  /**
   * clears all data from local storage relevant to the implicit auth manager
   * the localstorage keys that are cleared are 'sso' and 'auth'
   * @returns {void}
   */
  clearAuthLocalStorage() {
    this.hooks.onAuthLocalStorageCleared();
    // delete sso information and token information
    deleteDataFromLocalStorage('sso');
    deleteDataFromLocalStorage('auth');
  }

  /**
   * creates the sso base endpoint
   * @private
   * @returns {String}
   */
  createBaseAuthEndpointFromConfig() {
    const uriConf = this.config;
    return `${uriConf.baseURL}/auth/realms/${uriConf.realmName}/protocol/openid-connect/auth`;
  }

  /**
   * creates the sso base logout endpoint
   * @private
   * @returns {String}
   */
  createBaseLogoutEndpointFromConfig() {
    const uriConf = this.config;
    return `${uriConf.baseURL}/auth/realms/${uriConf.realmName}/protocol/openid-connect/logout`;
  }

  /**
   * validates the configuration, throws if any checks fail
   * @private
   * @returns {Void}
   */
  // eslint-disable-next-line
  validateConfig(config) {
    if (!TypeCheck.isObject(config)) {
      throw new Error('config must be an object');
    }
    if (!config.clientId || !TypeCheck.isString(config.clientId)) {
      throw new Error('client id in config must be present and typeof [string]');
    }
    if (!config.baseURL || !TypeCheck.isString(config.baseURL)) {
      throw new Error('base url in config must be present and typeof [string]');
    }

    if (!/^https:\/\//.test(config.baseURL)) {
      throw new Error('base url must start with https://');
    }

    if (!config.realmName || !TypeCheck.isString(config.realmName)) {
      throw new Error('realm name in config must be present and typeof [string]');
    }

    if (config.kcIDPHint && !TypeCheck.isString(config.kcIDPHint)) {
      throw new Error('kcIDPHint in config must be typeof [string]');
    }

    if (config.redirectURI) {
      // if its a function, test if the function returns a string
      if (
        TypeCheck.isFunction(config.redirectURI) &&
        !TypeCheck.isString(config.redirectURI(ImplicitAuthManager.validAPIIntentions.LOGIN))
      ) {
        throw new Error('If passing in a custom redirectURI as a function it must return a string');
        // otherwise make sure redirectURI is a string
      } else if (
        !TypeCheck.isFunction(config.redirectURI) &&
        !TypeCheck.isString(config.redirectURI)
      ) {
        throw new Error(
          'If passing in a custom redirectURI it must either be a function or a string'
        );
      }
    }
    // if login URI responseType was passed in
    if (config.loginURIResponseType && !TypeCheck.isString(config.loginURIResponseType)) {
      throw new Error('loginURIResponseType in config must be typeof [string]');
    }

    if (
      config.loginURIResponseType &&
      !ImplicitAuthManager.validResponseTypes().includes(config.loginURIResponseType)
    ) {
      throw new Error(
        "loginURIResponseType isn't valid, please view https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest for details"
      );
    }
    // validate hooks
    if (config.hooks) {
      this.areHooksValid(config.hooks);
    }
  }

  /**
   * validates the hook objects
   * @private
   * @returns {Void}
   */
  // eslint-disable-next-line
  areHooksValid(hooks) {
    if (!TypeCheck.isObject(hooks)) {
      throw new Error('hooks in config must be typeof [object]');
    }
    const validHooks = ImplicitAuthManager.validHooks();
    // loop over object and validate keys and their type
    Object.keys(hooks).forEach(hook => {
      if (!validHooks.includes(hook)) {
        throw new Error(
          `${hook} in config.hooks is not a valid hook, please see API Docs for information on valid hooks`
        );
      }
      if (!TypeCheck.isFunction(hooks[hook])) {
        throw new Error(`config.hooks.${hook} must be typeof [function]`);
      }
    });
  }

  /**
   * allows you to subscribe to hooks that will be called in the future
   * this replaces an preexisting hooks
   * it is not required that you register to all hooks
   * @param {Object} hooks the hook callbacks that you are subscribing too
   * @returns {Void}
   */
  registerHooks(hooks) {
    try {
      this.areHooksValid(hooks);
      this.config.hooks = { ...this.config.hooks, ...hooks };
    } catch (e) {
      // eslint-disable-next-line
      console.error("hooks are invalid and weren't registered");
    }
  }

  /**
   * creates a cryptographically random request key for the generation of the nonce
   * @returns {String} a request key for the implicit auth nonce creation routine
   * @private
   */
  static createRequestKey() {
    return CryptoUtils.genCryptographicRandomValue();
  }

  /**
   * creates a nonce which is based off the open id connect spec for implicit auth requests
   * @returns {String} the hashed nonce
   * @private
   */
  static createNonce() {
    const requestKey = ImplicitAuthManager.createRequestKey();
    // save request key in local storage for reference on auth redirect
    saveDataInLocalStorage('sso', { requestKey });
    // hash requestKey and return as nonce
    return CryptoUtils.hashSHA256(requestKey);
  }

  /**
   * deletes the nonce from local storage
   * @private
   * @returns {Void}
   */
  static clearNonce() {
    deleteDataFromLocalStorage('sso');
  }

  /**
   * detects replay attacks by comparing nonce coming from url with one in local storage
   * @private
   * @param {String} nonce
   * @returns {Boolean} true if this could be a replay attack
   */
  static isAReplayAttack(nonce) {
    // this could be a replay attack if the nonce contained with the jwt doesn't match
    // the hashed request key that SHOULD be in local storage
    const sso = getDataFromLocalStorage('sso');
    if (TypeCheck.isObject(sso) && sso.requestKey) {
      return !CryptoUtils.checkAgainstHash(sso.requestKey, nonce);
    }
    return true;
  }

  /**
   * checks if the jwt has expired
   * @private
   * @param {Object} token the decoded jwt token
   * @param {String | Number} token.exp the tokens expiry date
   * @returns {Boolean} true if the token is expired
   */
  static isTokenExpired(token) {
    return new Date() / 1000 > token.exp;
  }

  /**
   * checks if stored jwt tokens have expired
   * @returns {Boolean} true if the token is expired
   */
  areTokensExpired() {
    // get tokens
    const tokens = this.getAuthDataFromLocal();

    if (!tokens) {
      return true;
    }

    return (
      Object.keys(tokens).filter(item => ImplicitAuthManager.isTokenExpired(tokens[item].data))
        .length > 0
    );
  }

  /**
   * returns a parameter that exists within the hash '#' of a uri from the implicit auth redirect
   * @param {String} urlHash
   * @param {String} name
   * @private
   * @returns {String} the paramater value
   */
  static getParameterByName(urlHash, name) {
    const match = RegExp(`[#&]${name}=([^&]*)`).exec(urlHash);
    return match && decodeURIComponent(match[1].replace(/\+/g, ' '));
  }

  /**
   * returns the access token string
   * @param {String} urlHash
   * @private
   * @returns {String} the access token string
   */
  static getAccessTokenFromHash(urlHash) {
    return ImplicitAuthManager.getParameterByName(urlHash, 'access_token');
  }

  /**
   * returns the id token string
   * @param {String} urlHash
   * @private
   * @returns {String} the id token string
   */
  static getIdTokenFromHash(urlHash) {
    return ImplicitAuthManager.getParameterByName(urlHash, 'id_token');
  }

  /**
   * returns the error string
   * @param {String} urlHash
   * @private
   * @returns {String} the error
   */
  static getErrorFromHash(urlHash) {
    return ImplicitAuthManager.getParameterByName(urlHash, 'error');
  }

  /**
   * returns the session state
   * @param {String} urlHash
   * @private
   * @returns {String} the session state
   */
  static getSessionStateFromHash(urlHash) {
    return ImplicitAuthManager.getParameterByName(urlHash, 'session_state');
  }

  /**
   * gets access token that exists in local storage
   * @returns {Object} the access token if exists, otherwise undefined
   */
  // eslint-disable-next-line class-methods-use-this
  getAccessTokenFromLocal() {
    const authData = getDataFromLocalStorage('auth');
    if (authData) {
      return authData.accessToken;
    }
    return undefined;
  }

  /**
   * gets id token that exists in local storage
   * @returns {Object} the id token if exists, otherwise undefined
   */
  // eslint-disable-next-line
  getIdTokenFromLocal() {
    const authData = getDataFromLocalStorage('auth');
    if (authData) {
      return authData.idToken;
    }
  }

  /**
   * verifies access and id tokens and saves them in local storage if all checks pass
   * @param {String} accessToken
   * @param {String} idToken
   * @private
   * @returns {Void}
   */
  // eslint-disable-next-line
  saveAuthDataInLocal(accessToken, idToken) {
    try {
      const auth = {};

      // eslint-disable-next-line
      if (accessToken) {
        auth.accessToken = {
          data: jwtDecode(accessToken),
          bearer: accessToken,
        };

        // ensure access token nonce matches
        if (ImplicitAuthManager.isAReplayAttack(auth.accessToken.data.nonce)) {
          throw new Error('Authentication failed due to possible replay attack');
        }
      }

      // eslint-disable-next-line
      if (idToken) {
        auth.idToken = {
          data: jwtDecode(idToken),
          bearer: idToken,
        };

        if (ImplicitAuthManager.isAReplayAttack(auth.idToken.data.nonce)) {
          throw new Error('Authentication failed due to possible replay attack');
        }
      }

      // if auth is empty at this point that means accessToken, idToken were
      // null and we should throw to avoid garbage data being saved in local storage
      if (Object.keys(auth).length === 0) {
        throw new Error('unable to save invalid tokens');
      }

      saveDataInLocalStorage('auth', auth);

      return true;
    } catch (e) {
      // need to figure out what would be appropriate here
      return false;
    }
  }

  /**
   * gets the sso logout uri to be used by your front end
   * @returns {String} the logout uri
   */
  getSSOLogoutURI() {
    const apiIntentions = ImplicitAuthManager.validAPIIntentions();
    const redirectURI = this.getSSORedirectURI(apiIntentions.LOGOUT);
    const logoutURI = `${this.baseLogoutEndpoint}?redirect_uri=${redirectURI}`;
    return encodeURI(logoutURI);
  }

  /**
   * returns the sso login uri, this function accepts a prompt to modify the behaviour of logging in
   * @param {String} prompt ['none', 'login', 'consent', 'select_account']
   * as per open id spec the prompt is OPTIONAL and default to login
   * more info can be found here https://openid.net/specs/openid-connect-core-1_0.html (search for prompt)
   * @returns {String} the login uri
   */
  getSSOLoginURI(prompt = 'login') {
    if (!ImplicitAuthManager.validPromptTypes().includes(prompt)) {
      throw new Error(`Prompt type must one of ${ImplicitAuthManager.validPromptTypes()}`);
    }

    const apiIntentions = ImplicitAuthManager.validAPIIntentions();
    const uriConf = this.config;
    const redirectURI = this.getSSORedirectURI(apiIntentions.LOGIN);
    const nonce = ImplicitAuthManager.createNonce();
    const kcIDPHint = uriConf.kcIDPHint ? `&kc_idp_hint=${uriConf.kcIDPHint}` : '';
    const loginURI = `${this.baseAuthEndpoint}?response_type=${
      uriConf.loginURIResponseType
    }&prompt=${prompt}&client_id=${
      uriConf.clientId
    }&nonce=${nonce}${kcIDPHint}&redirect_uri=${redirectURI}`; // need to finish createBASE URL fn
    return encodeURI(loginURI);
  }

  /**
   * gets the login uri to be used by implicit auth manager itself, the prompt is none
   * so that on authentication fail, the user is redirected back to the client
   * @private
   * @returns {String} the login uri
   */
  getSSOLoginURIForPageLoadRedirect() {
    return this.getSSOLoginURI('none');
  }

  /**
   * creates the sso redirect uri
   * @param {String} apiIntention LOGIN | LOGOUT
   * @private
   * @returns {String} the redirect uri
   */
  getSSORedirectURI(apiIntention) {
    // this.redirectURI via getter
    return TypeCheck.isFunction(this.redirectURI)
      ? this.redirectURI(apiIntention)
      : `${this.redirectURI}?intention=${apiIntention}&sso=true`;
  }

  /**
   * this is the main routine for the manager, it should be called on page load at all times
   * it detects a implicit authentication in the browsers url and stores tokens when verified
   * @private
   * @returns {Void}
   */
  handleOnPageLoad() {
    if (this.isAuthenticated()) {
      // set expiry timers
      this.setTokenExpiryTimers();
      this.hooks.onAuthenticateSuccess();
      // fire user authenticated hook
    } else if (!ImplicitAuthManager.isPageLoadFromSSORedirect()) {
      // this definition should and will change as a better method for detecting a redirect
      // is made apparent
      this.hooks.onBeforeAuthRedirect();
      // force redirect to get authenticated
      const ssoLoginURI = this.getSSOLoginURIForPageLoadRedirect();

      window.location.replace(ssoLoginURI);
    } else {
      this.hooks.onAfterAuthRedirect();

      const { hash } = window.location;

      const accessToken = ImplicitAuthManager.getAccessTokenFromHash(hash);

      const idToken = ImplicitAuthManager.getIdTokenFromHash(hash);
      const authenticated = this.saveAuthDataInLocal(accessToken, idToken);
      if (authenticated) {
        // fire authenticated eventt
        this.hooks.onAuthenticateSuccess();
        // set expiry timers
        this.setTokenExpiryTimers();
      } else {
        this.hooks.onAuthenticateFail();
        // fire authentication failed event
        this.clearAuthLocalStorage();
      }
      // clear nonce
      ImplicitAuthManager.clearNonce();
    }
  }

  /**
   * gets the auth data from local storage
   * @returns {Object}
   * @private
   */
  // eslint-disable-next-line
  getAuthDataFromLocal() {
    return getDataFromLocalStorage('auth');
  }

  /**
   * validates the redirect hash has session state and an id token or access token
   * @returns {Boolean} true if valid
   */
  static isPageLoadHashValidForAuthentication() {
    const urlHash = window.location.hash;

    const sessionState = ImplicitAuthManager.getSessionStateFromHash(urlHash);

    const idToken = ImplicitAuthManager.getIdTokenFromHash(urlHash);

    const accessToken = ImplicitAuthManager.getAccessTokenFromHash(urlHash);

    return !sessionState || (!idToken || !accessToken);
  }

  /**
   * detects whether page was loaded because of a redirect from the sso provider
   * @returns {Boolean} true if from a sso redirect
   */
  static isPageLoadFromSSORedirect() {
    const { hash } = window.location;

    const idToken = ImplicitAuthManager.getAccessTokenFromHash(hash);

    const accessToken = ImplicitAuthManager.getIdTokenFromHash(hash);
    const error = ImplicitAuthManager.getErrorFromHash(hash);

    return idToken !== null || accessToken !== null || error !== null;
  }

  /**
   * checks if session is considered to be authenticated
   * * when tokens exist and are not expired
   * @returns {Boolean} true if session is considered authenticated
   * @private
   */
  // eslint-disable-next-line class-methods-use-this
  isAuthenticated() {
    // do we have auth data saved in local storage and are tokens not expired
    const auth = getDataFromLocalStorage('auth');
    if (!auth) {
      return false;
    }
    // do any tokens exist
    if (!auth.idToken && !auth.accessToken) {
      return false;
    }
    // if either token is expired user is not authenticated
    return !(
      (auth.idToken && ImplicitAuthManager.isTokenExpired(auth.idToken.data)) ||
      (auth.accessToken && ImplicitAuthManager.isTokenExpired(auth.accessToken.data))
    );
  }

  /**
   * sets a timer to expire tokens
   * @private
   * @returns {Void}
   */
  setTokenExpiryTimers() {
    // get tokens
    const tokens = this.getAuthDataFromLocal();
    Object.keys(tokens).forEach(token => {
      const now = moment();
      const then = moment(tokens[token].data.exp * 1000);
      const expiresIn = then.diff(now, 'millisecond');
      setTimeout(() => {
        // eslint-disable-next-line
        console.log('%cToken Expired...clearing session', 'color: orange');
        this.hooks.onTokenExpired();
        // this.clearAuthLocalStorage();
        // fire logged out event;
      }, expiresIn);
    });
  }
}
