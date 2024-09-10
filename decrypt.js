#!/usr/bin/env node
const crypto = require('crypto');
const fs = require('fs');

const BLOCK_SIZE = 16; // AES block size for CBC mode

function padKey(key) {
  let keyBuffer = Buffer.from(key, 'utf-8');
  if (keyBuffer.length > 32) {
    return keyBuffer.subarray(0, 32); // Trim if the key is too long
  } else if (keyBuffer.length < 32) {
    const paddedKey = Buffer.alloc(32, 0);
    keyBuffer.copy(paddedKey);
    return paddedKey; // Pad with null bytes if too short
  }
  return keyBuffer;
}

function decryptAES(encryptedData, key) {
  // Prepare the key and decode the base64 data
  const keyBuffer = padKey(key);
  const data = Buffer.from(encryptedData, 'base64');

  // Extract the IV and the encrypted data
  const iv = data.subarray(0, BLOCK_SIZE);
  const encryptedText = data.subarray(BLOCK_SIZE);

  // Create a decipher object with the key and the IV
  const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, iv);

  // Decrypt the data
  let decrypted = decipher.update(encryptedText, 'binary', 'utf-8');
  decrypted += decipher.final('utf-8');

  // Return the JSON data
  return decrypted;
}

if (process.argv.length !== 4) {
  console.error(
    'Usage: node decrypt.js <input_encrypted_file> <encryption_key>'
  );
  process.exit(1);
}

const inputFile = process.argv[2];
const key = process.argv[3];

try {
  // Read the encrypted data from the input file
  const encryptedData = fs.readFileSync(inputFile, 'utf-8');

  // Decrypt the data
  const decryptedData = decryptAES(encryptedData, key);

  // Parse and print the decrypted JSON data
  const jsonData = JSON.parse(decryptedData);
  console.log('Decrypted data:', jsonData);
} catch (err) {
  console.error('Error:', err.message);
}
