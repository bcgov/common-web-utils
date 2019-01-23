import TypeCheck from '../src/libs/TypeCheck';
describe('TypeCheck class', () => {
  it('checks for objects', () => {
    const value = {};
    const badValue = 9;
    expect(TypeCheck.isObject(value)).toBe(true);
    expect(TypeCheck.isObject(badValue)).toBe(false);
  });

  it('checks for numbers', () => {
    const value = 0;
    const badValue = false;
    expect(TypeCheck.isNumber(value)).toBe(true);
    expect(TypeCheck.isNumber(badValue)).toBe(false);
  });

  it('checks for functions', () => {
    const value = () => null;
    const badValue = 9;
    expect(TypeCheck.isFunction(value)).toBe(true);
    expect(TypeCheck.isFunction(badValue)).toBe(false);
  });

  it('checks for Dates', () => {
    const value = new Date();
    const badValue = 9;
    expect(TypeCheck.isDate(value)).toBe(true);
    expect(TypeCheck.isDate(badValue)).toBe(false);
  });

  it('checks for RegExp', () => {
    const value = new RegExp('d');
    const badValue = 9;
    expect(TypeCheck.isRegExp(value)).toBe(true);
    expect(TypeCheck.isRegExp(badValue)).toBe(false);
  });

  it('checks for Strings', () => {
    const value = '123';
    const badValue = 9;
    expect(TypeCheck.isString(value)).toBe(true);
    expect(TypeCheck.isString(badValue)).toBe(false);
  });

  it('checks for Boolean', () => {
    const value = true;
    const badValue = 9;
    expect(TypeCheck.isBoolean(value)).toBe(true);
    expect(TypeCheck.isBoolean(badValue)).toBe(false);
  });

  it('throws if object contructor is invalid', () => {
    expect(() => {
      TypeCheck.isA(false, '123');
    }).toThrow(
      'objectContructor must be one of the javascript object constructors: String, Function, Boolean etc.'
    );
  });
  
  it('checks for object against value', () => {
    const obj1 = String;
    const obj2 = Function;
    const obj3 = Map;
    const value1 = 'true';
    const value2 = () => null;
    const value3 = new Map();

    expect(TypeCheck.isA(obj1, value1)).toBe(true);
    expect(TypeCheck.isA(obj1, value2)).toBe(false);
    expect(TypeCheck.isA(obj2, value2)).toBe(true);
    expect(TypeCheck.isA(obj2, value1)).toBe(false);
    expect(TypeCheck.isA(obj3, value1)).toBe(false);
    expect(TypeCheck.isA(obj3, value3)).toBe(true);
  });

  it('can check for an array of strings', () => {
    const array = ['1', '2'];
    expect(TypeCheck.isArrayOf(String, array)).toBe(true);
  });

  it('returns false if not array', () => {
    const array = null;
    expect(TypeCheck.isArrayOf(String, array)).toBe(false);
  });


  it('returns false if array but object is incorrect', () => {
    const array = [1, 2, 3];
    expect(TypeCheck.isArrayOf(String, array)).toBe(false);
  });

  it('returns false if array but one value isn\'t correct', () => {
    const array = [1, '2', 3];
    expect(TypeCheck.isArrayOf(Number, array)).toBe(false);
  });

  it('checks for Map', () => {
    expect(TypeCheck.isMap(new Map())).toBe(true);
    expect(TypeCheck.isMap({})).toBe(false);
  });
});
