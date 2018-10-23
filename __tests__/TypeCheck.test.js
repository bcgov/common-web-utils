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
  test('isA throws if object contructor is invalid', () => {
    expect(() => {
      TypeCheck.isA(false, '123');
    }).toThrow(
      'objectContructor must be one of the javascript object constructors: String, Function, Boolean etc.'
    );
  });
  it('checks for object against value', () => {
    const obj1 = String;
    const obj2 = Function;
    const value1 = 'true';
    const value2 = () => null;

    expect(TypeCheck.isA(obj1, value1)).toBe(true);
    expect(TypeCheck.isA(obj1, value2)).toBe(false);
    expect(TypeCheck.isA(obj2, value2)).toBe(true);
    expect(TypeCheck.isA(obj2, value1)).toBe(false);
  });
});
