import chai, { expect, assert } from 'chai';
import path from 'path';
import { wasm as wasm_tester } from 'circom_tester';

describe('DateIsLessChecker Circuit Test', function () {
  this.timeout(0); // Disable timeout

  let circuit;

  /**
   *  Test parameters
   *
   *  n: number of dates to test
   *  yearStart: start year for random current dates
   *  yearEnd: end year for random current dates
   *
   *
   *
   */

  const n = 10;

  const yearStart = 2023;
  const yearEnd = 2049;
  const maxDiff = 20; // Maximum date difference

  // Helper function to generate a random date within a given range
  function generateRandomDate(yearStart, yearEnd) {
    const year = Math.floor(Math.random() * (yearEnd - yearStart + 1)) + yearStart;
    const month = Math.floor(Math.random() * 12) + 1;
    const day = Math.floor(Math.random() * 28) + 1; // Simplification for month lengths
    return { year, month, day };
  }

  // Generate arrays for current dates
  const currentDates = Array(n)
    .fill(0)
    .map(() => generateRandomDate(yearStart, yearEnd));

  // Generate majority birthDates ensuring the age difference is at least minDiff
  const unvalidExpiryDates = currentDates.map((currentDate) => {
    // Subtract a random number of years within the allowed age difference, plus a random number of days and months for additional variance
    const yearDiff = Math.floor(Math.random() * (maxDiff - 0)) + 0;
    const monthDiff = Math.floor(Math.random() * 12);
    const dayDiff = Math.floor(Math.random() * 28) + 1;
    return {
      year: currentDate.year - yearDiff,
      month: Math.max(1, currentDate.month - monthDiff), // Ensure month is within valid range
      day: Math.max(1, currentDate.day - dayDiff), // Ensure day is within valid range
    };
  });

  // Generate minority birthDates ensuring the age difference is less than minDiff
  const validExpiryDates = currentDates.map((currentDate) => {
    const yearDiff = Math.floor(Math.random() * -maxDiff);
    const monthDiff = Math.floor(Math.random() * 12);
    const dayDiff = Math.floor(Math.random() * 28);
    return {
      year: currentDate.year - yearDiff,
      month: Math.max(1, currentDate.month - monthDiff), // Ensure month is within valid range
      day: Math.max(1, currentDate.day - dayDiff), // Ensure day is within valid range
    };
  });

  before(async () => {
    circuit = await wasm_tester(
      path.join(__dirname, '../../circuits/tests/utils/isValid_tester.circom'),
      {
        include: ['node_modules'],
      }
    );
  });

  it('compile and load the circuit', async function () {
    expect(circuit).to.not.be.undefined;
  });

  describe('Unvalidity Tests', function () {
    unvalidExpiryDates.forEach((date, index) => {
      it(`unvalidity check for expiry date ${genDateStr(unvalidExpiryDates[index])} and current date ${genDateStr(currentDates[index])}, expired since: ${getAgeFromDates(unvalidExpiryDates[index], currentDates[index])}`, async function () {
        const inputs = {
          currDate: [
            Math.floor(currentDates[index].year / 10) % 10,
            currentDates[index].year % 10,
            Math.floor(currentDates[index].month / 10),
            currentDates[index].month % 10,
            Math.floor(currentDates[index].day / 10),
            currentDates[index].day % 10,
          ],
          validityDateASCII: [
            Math.floor(date.year / 10) % 10,
            date.year % 10,
            Math.floor(date.month / 10),
            date.month % 10,
            Math.floor(date.day / 10),
            date.day % 10,
          ].map((n) => n + 48), // Convert to ASCII for the circuit input
        };
        /*
                console.log("current date: " + JSON.stringify(currentDates[index]));
                console.log("majority birth date: " + JSON.stringify(majorityBirthDates[index]));
                console.log("yearDiff: " + (currentDates[index].year - majorityBirthDates[index].year) + " monthDiff: " + (currentDates[index].month - majorityBirthDates[index].month) + " dayDiff: " + (currentDates[index].day - majorityBirthDates[index].day));
                */

        try {
          const witness = await circuit.calculateWitness(inputs, true);
          const output = await circuit.getOutput(witness, ['out']);
          expect.fail('Expected an error but none was thrown.');
        } catch (error) {
          expect(error.message).to.include('Assert Failed');
        }
      });
    });
  });

  describe('Validity Tests', function () {
    validExpiryDates.forEach((date, index) => {
      it(`validity check for expiry date ${genDateStr(validExpiryDates[index])} and current date ${genDateStr(currentDates[index])} valid until: ${getAgeFromDates(currentDates[index], validExpiryDates[index])}`, async function () {
        const inputs = {
          currDate: [
            Math.floor(currentDates[index].year / 10) % 10,
            currentDates[index].year % 10,
            Math.floor(currentDates[index].month / 10),
            currentDates[index].month % 10,
            Math.floor(currentDates[index].day / 10),
            currentDates[index].day % 10,
          ],
          validityDateASCII: [
            Math.floor(date.year / 10) % 10,
            date.year % 10,
            Math.floor(date.month / 10),
            date.month % 10,
            Math.floor(date.day / 10),
            date.day % 10,
          ].map((n) => n + 48), // Convert to ASCII for the circuit input
        };
        /*
                console.log("current date: " + JSON.stringify(currentDates[index]));
                console.log("minority birth date: " + JSON.stringify(minorityBirthDates[index]));
                console.log("yearDiff: " + (currentDates[index].year - minorityBirthDates[index].year) + " monthDiff: " + (currentDates[index].month - minorityBirthDates[index].month) + " dayDiff: " + (currentDates[index].day - minorityBirthDates[index].day));
                */
        const witness = await circuit.calculateWitness(inputs, true);
        // const output = await circuit.getOutput(witness, ['out']);
        // assert.strictEqual(output.out, '1', 'Passport should be valid');
      });
    });
  });

  function genDateStr(currentDate: { year: number; month: number; day: number }): string {
    // Ensure month and day are two digits by padding with '0' if necessary
    const formattedMonth = currentDate.month.toString().padStart(2, '0');
    const formattedDay = currentDate.day.toString().padStart(2, '0');
    return `${currentDate.year}${formattedMonth}${formattedDay}`;
  }

  function getAgeFromDates(
    birthDate: { year: number; month: number; day: number },
    currentDate: { year: number; month: number; day: number }
  ): string {
    let years = currentDate.year - birthDate.year;
    let months = currentDate.month - birthDate.month;
    let days = currentDate.day - birthDate.day;

    if (days < 0) {
      months -= 1;
      const lastDayOfPreviousMonth = new Date(currentDate.year, currentDate.month - 1, 0).getDate();
      days += lastDayOfPreviousMonth;
    }

    if (months < 0) {
      years -= 1;
      months += 12;
    }

    // Add 's' at the end of year, month, and day if they are greater than 1
    const yearStr = years > 1 ? 'years' : 'year';
    const monthStr = months > 1 ? 'months' : 'month';
    const dayStr = days > 1 ? 'days' : 'day';

    return `${years} ${yearStr}, ${months} ${monthStr}, ${days} ${dayStr}`;
  }
});
