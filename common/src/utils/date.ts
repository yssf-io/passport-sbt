export function getAdjustedTimestampBytes(y: number = 0, m: number = 0, d: number = 0): number[] {
  // Get the current date/time
  let currentDate: Date = new Date();

  // Optionally adjust the date
  if (y !== 0) currentDate.setFullYear(currentDate.getFullYear() + y);
  if (m !== 0) currentDate.setMonth(currentDate.getMonth() + m);
  if (d !== 0) currentDate.setDate(currentDate.getDate() + d);

  // Get the Unix timestamp (in seconds)
  const timestamp: number = Math.floor(currentDate.getTime() / 1000);

  // Convert the timestamp to 4 bytes
  const bytes: number[] = [
    (timestamp >> 24) & 0xff,
    (timestamp >> 16) & 0xff,
    (timestamp >> 8) & 0xff,
    timestamp & 0xff,
  ];

  return bytes;
}
export function getTimestampBytesFromYearFraction(yearFraction: number): number[] {
  // Separate the year and the fractional part
  const year = Math.floor(yearFraction);
  const fraction = yearFraction - year;

  // Convert the fractional part into months (0-11)
  const monthsFromFraction = Math.floor(fraction * 12);

  // Create a date object from the year and the calculated month
  // Assuming the first day of the month for simplicity
  const date = new Date(year, monthsFromFraction, 1);

  // Get the Unix timestamp (in seconds)
  const timestamp: number = Math.floor(date.getTime() / 1000);

  // Convert the timestamp to 4 bytes
  const bytes: number[] = [
    (timestamp >> 24) & 0xff,
    (timestamp >> 16) & 0xff,
    (timestamp >> 8) & 0xff,
    timestamp & 0xff,
  ];

  return bytes;
}

export function unixTimestampToYYMMDD(timestamp: number): string {
  console.log('timestamp: ' + timestamp);
  const date = new Date(timestamp * 1000);
  console.log('date: ' + date);
  const year = date.getUTCFullYear();
  console.log('year: ' + year);
  const month = date.getUTCMonth() + 1;
  const day = date.getUTCDate();

  // Ensure the year is correctly formatted as two digits
  const YY = `0${year % 100}`.slice(-2);
  const MM = `0${month}`.slice(-2);
  const DD = `0${day}`.slice(-2);

  return `${YY}${MM}${DD}`;
}

export function yearFractionToYYMMDD(yearFraction: number): string {
  // Separate the year and the fractional part
  const year = yearFraction;
  const fraction = yearFraction - Math.floor(yearFraction);

  // Convert the fractional part into months (0-11)
  const monthsFromFraction = Math.floor(fraction * 12);

  // Assuming the first day of the month for simplicity
  const day = 1;

  // Format year, month, and day into YYMMDD string
  const YY = `0${Math.floor(year) % 100}`.slice(-2);
  const MM = `0${monthsFromFraction + 1}`.slice(-2); // +1 because months are 1-indexed in this format
  const DD = `0${day}`.slice(-2);

  return `${YY}${MM}${DD}`;
}

export function yymmddToByteArray(yymmdd: string): number[] {
  // Convert each character in the string to its ASCII value
  const byteArray = Array.from(yymmdd).map((char) => char.charCodeAt(0));
  return byteArray;
}

export function getCurrentDateYYMMDD(dayDiff: number = 0): number[] {
  const date = new Date();
  date.setDate(date.getDate() + dayDiff); // Adjust the date by the dayDiff
  const year = date.getUTCFullYear();
  const month = date.getUTCMonth() + 1;
  const day = date.getUTCDate();
  const YY = `0${year % 100}`.slice(-2);
  const MM = `0${month}`.slice(-2);
  const DD = `0${day}`.slice(-2);

  const yymmdd = `${YY}${MM}${DD}`;
  return Array.from(yymmdd).map((char) => parseInt(char));
}