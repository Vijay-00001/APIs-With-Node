/**
 * Generate a random six-digit number.
 * @returns A random six-digit number as a string.
 */
export function generateRandomSixDigitNumber(): string {
   // Generate a random number between 100000 and 999999
   const randomNumber = Math.floor(100000 + Math.random() * 900000);
   return randomNumber.toString();
}
