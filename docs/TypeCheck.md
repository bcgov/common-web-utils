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
these are mostly providers of constants that are attached to this class. They are consumed by the instance but may also be helpful outisde.
```javascript
  TypeCheck.isObject(value) { boolean } 
  TypeCheck.isString(value) { boolean } 
  TypeCheck.isArray(value) { boolean } 
  TypeCheck.isFunction(value) { boolean }
  TypeCheck.isBoolean(value) { boolean }
  TypeCheck.isNumber(value) { boolean }
  TypeCheck.isDate(value) { boolean }
  TypeCheck.isRegExp(value) { boolean }
  TypeCheck.isAsyncFunction(value) { boolean }
  TypeCheck.isA(objectType, value) { boolean }
```

