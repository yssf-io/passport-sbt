/// UUID
function hexToBigInt(hex: string): bigint {
    return BigInt(`0x${hex}`);
}

function checkBigInt(bigInt: bigint) {
    const max253BitValue = BigInt(2n ** 253n - 1n);
    if (bigInt > max253BitValue) {
        throw new Error('Input should be < 2^253 - 1');
    }
}

function uuidToBigInt(uuid: string): bigint {
    const hexString = uuid.replace(/-/g, '');
    const bigInt = hexToBigInt(hexString);
    return bigInt;
}

export function castFromUUID(uuid: string): string {
    const bigInt = uuidToBigInt(uuid);
    checkBigInt(bigInt);
    return bigInt.toString();
}

export function bigIntToHex(bigInt: bigint): string {
    return bigInt.toString(16).padStart(32, '0');
}

export function hexToUUID(hex: string): string {
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function castToUUID(bigInt: bigint): string {
    const hex = bigIntToHex(bigInt);
    return hexToUUID(hex);
}

/// scope
function checkStringLength(str: string) {
    if (str.length > 25) {
        throw new Error('Input string must not exceed 25 characters');
    }
}

function stringToBigInt(str: string): bigint {
    return BigInt(
        '1' +
        Array.from(str)
            .map((char) => char.charCodeAt(0).toString().padStart(3, '0'))
            .join('')
    );
}

export function castFromScope(scope: string): string {
    checkStringLength(scope);
    return stringToBigInt(scope).toString();
}

export function castToScope(num: bigint): string {
    const str = num.toString().slice(1); // Remove leading '1'
    const charCodes = str.match(/.{1,3}/g) || [];
    return String.fromCharCode(...charCodes.map((code) => parseInt(code, 10)));
}

export function stringToAsciiBigIntArray(str: string): bigint[] {
    let asciiBigIntArray = [];
    for (let i = 0; i < str.length; i++) {
        asciiBigIntArray.push(BigInt(str.charCodeAt(i)));
    }
    return asciiBigIntArray;
}


// custom user_identifier type validation
export type UserIdType = 'ascii' | 'hex' | 'uuid';

const validateUserId = (userId: string, type: UserIdType): boolean => {
    switch (type) {
        case 'ascii':
            return /^[\x00-\xFF]+$/.test(userId);
        case 'hex':
            return /^[0-9A-Fa-f]+$/.test(userId);
        case 'uuid':
            return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
                userId
            );
        default:
            return false;
    }
};

const getMaxLenght = (idType: UserIdType) => {
    switch (idType) {
        case 'ascii':
            return 25;
        default:
            return 63;
    }
};

export const parseUIDToBigInt = (
    user_identifier: string,
    user_identifier_type: UserIdType
): string => {
    if (!validateUserId(user_identifier, user_identifier_type)) {
        throw new Error(`User identifier of type ${user_identifier_type} is not valid`);
    }

    const maxLength = getMaxLenght(user_identifier_type);
    if (user_identifier.length > maxLength) {
        throw new Error(
            `User identifier of type ${user_identifier_type} exceeds maximum length of ${maxLength} characters`
        );
    }

    switch (user_identifier_type) {
        case 'ascii':
            return stringToBigInt(user_identifier).toString();
        case 'hex':
            return hexToBigInt(user_identifier).toString();
        case 'uuid':
            return uuidToBigInt(user_identifier).toString();
    }
};
