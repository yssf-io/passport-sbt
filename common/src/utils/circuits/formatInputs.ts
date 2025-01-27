import { MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH } from "../../constants/constants";

export function formatCountriesList(countries: string[]) {
    if (countries.length > MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH) {
        throw new Error(`Countries list must be inferior or equals to ${MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH}`);
    }
    const paddedCountries = countries.concat(Array(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH - countries.length).fill(''));
    const result = paddedCountries.flatMap((country) => {
        const chars = country
            .padEnd(3, '\0')
            .split('')
            .map((char) => char.charCodeAt(0));
        return chars;
    });
    return result;
}