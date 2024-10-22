import crypto from 'crypto';

// AES-256-CBC for encryption
const encryptionAlgorithm = 'aes-256-cbc';
const encodingAlgorithm = 'base64';

// Auto-generate a 32-byte encryption key for AES-256
const encryptionKey = crypto.randomBytes(32); // 32-byte key for AES-256

// Auto-generate a separate key for HMAC (we use 64 bytes for stronger integrity checking)
const hmacKey = crypto.randomBytes(64); // 64-byte HMAC key

// Function to securely encrypt data
export const encryptData = (value: string): string => {
   const iv = crypto.randomBytes(16); // Ensure IV is exactly 16 bytes
   const cipher = crypto.createCipheriv(encryptionAlgorithm, encryptionKey, iv);
   let encrypted = cipher.update(value, 'utf-8');
   encrypted = Buffer.concat([encrypted, cipher.final()]);

   // Combine IV and encrypted data into one string
   const combined =
      iv.toString(encodingAlgorithm) +
      ':' +
      encrypted.toString(encodingAlgorithm);

   // Generate HMAC-SHA256 to protect the encrypted data's integrity
   const hmac = crypto
      .createHmac('sha256', hmacKey)
      .update(combined)
      .digest('hex');

   // Return IV + encrypted data + HMAC for integrity checking
   return combined + ':' + hmac;
};

// Function to securely decrypt data
export const decryptData = (encryptedValue: string): string => {
   const parts = encryptedValue.split(':');

   // Extract IV, encrypted text, and HMAC
   const iv = Buffer.from(parts.shift()!, encodingAlgorithm);
   const encryptedText = Buffer.from(parts.shift()!, encodingAlgorithm);
   const hmacReceived = parts.pop(); // Extract the HMAC
   const combined =
      iv.toString(encodingAlgorithm) +
      ':' +
      encryptedText.toString(encodingAlgorithm);

   // Verify the HMAC to check the integrity of the data
   const hmacCalculated = crypto
      .createHmac('sha256', hmacKey)
      .update(combined)
      .digest('hex');
   if (hmacReceived !== hmacCalculated) {
      throw new Error(
         'Data integrity check failed. The data may have been tampered with.'
      );
   }

   const decipher = crypto.createDecipheriv(
      encryptionAlgorithm,
      encryptionKey,
      iv
   );

   let decrypted = decipher.update(encryptedText);
   decrypted = Buffer.concat([decrypted, decipher.final()]);

   // Return the decrypted original text in utf-8
   return decrypted.toString('utf-8');
};

/**
 * Generates a strong cryptographically secure token.
 * This function doesn't take any input; it always generates a token of fixed length.
 * @returns A strong token as a hexadecimal string.
 */
export const generateRandomToken = (): string => {
   // Generate 64 bytes of secure random bytes
   const randomBytes = crypto.randomBytes(64);

   // Hash the random bytes using SHA-256 to create a secure token
   const randomToken = crypto
      .createHash('sha256')
      .update(randomBytes)
      .digest('hex');

   return randomToken; // Return the strong token
};
