# TypeCheck

This is a light weight type checking API that goes over hurdles of doing javascript typechecking using native solutions.

https://juhukinners.wordpress.com/2009/01/11/typeof-considered-useless-or-how-to-write-robust-type-checks/
## Installation

```npm install --save @bcgov/common-web-utils```

## Usage


```javascript
// somewhere in a root level script
import { TypeCheck } from '@bcgov/common-web-utils';
const notAFunction = null;
if(TypeCheck.isFunction(notAFunction)) {
    notAFunction();
}
```  
## API

### static methods
```javascript
  TypeCheck.isObject(value) { boolean }  // TypeCheck.isObject({});
  TypeCheck.isMap(value) { boolean }  // TypeCheck.isObject({});
  TypeCheck.isString(value) { boolean } // TypeCheck.isString('hello world');
  TypeCheck.isArray(value) { boolean }  // TypeCheck.isArray([1, 2, 3]);
  TypeCheck.isFunction(value) { boolean } // TypeCheck.isFunction(() => null);
  TypeCheck.isBoolean(value) { boolean } // TypeCheck.isBoolean(true);
  TypeCheck.isNumber(value) { boolean } // TypeCheck.isNumber(123);
  TypeCheck.isDate(value) { boolean } // TypeCheck.isDate(new Date());
  TypeCheck.isRegExp(value) { boolean } // TypeCheck.isRegExp(/foo/);
  // please not is async function only works with es6 'async function' syntax
  TypeCheck.isAsyncFunction(value) { boolean } // TypeCheck.isAsyncFunction(async () => null);
  TypeCheck.isA(objectType, value) { boolean } // TypeCheck.isA(String, 'hello world');
  TypeCheck.isArrayOf(objectType, value) { boolean } // TypeCheck.isArrayOf(String, ['hello', 'world']);
```

