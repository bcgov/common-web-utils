
const storage = {};

export const saveDataInLocalStorage = (key, data) => {
    console.log('called!!');
    storage[key] = data;
};

export const getDataFromLocalStorage = key => {
    console.log('called!!');
    console.log(`key is ${key} value = ${storage[key]}`);
    return key in storage ? storage[key] : undefined;
}

export const deleteDataFromLocalStorage = key => {};
