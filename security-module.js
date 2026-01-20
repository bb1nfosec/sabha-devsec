// ============================================================================
// SABHA Client-Side Encryption & Security Module
// AES-256-GCM Encryption, SHA-256 Integrity, Digital Signatures
// ============================================================================

class SecurityModule {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.keyLength = 256;
        this.ivLength = 12; // 96 bits for GCM
    }

    // ========================================================================
    // AES-256-GCM Encryption
    // ========================================================================

    /**
     * Generate a random encryption key
     * @returns {Promise<CryptoKey>}
     */
    async generateKey() {
        return await crypto.subtle.generateKey(
            {
                name: this.algorithm,
                length: this.keyLength
            },
            true, // extractable
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Export key to JWK format for storage
     * @param {CryptoKey} key
     * @returns {Promise<Object>}
     */
    async exportKey(key) {
        return await crypto.subtle.exportKey('jwk', key);
    }

    /**
     * Import key from JWK format
     * @param {Object} jwk
     * @returns {Promise<CryptoKey>}
     */
    async importKey(jwk) {
        return await crypto.subtle.importKey(
            'jwk',
            jwk,
            {
                name: this.algorithm,
                length: this.keyLength
            },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt data using AES-256-GCM
     * @param {string} data - Data to encrypt
     * @param {CryptoKey} key - Encryption key
     * @returns {Promise<Object>} Encrypted data with IV
     */
    async encrypt(data, key) {
        // Generate random IV
        const iv = crypto.getRandomValues(new Uint8Array(this.ivLength));

        // Convert data to ArrayBuffer
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);

        // Encrypt
        const encrypted = await crypto.subtle.encrypt(
            {
                name: this.algorithm,
                iv: iv
            },
            key,
            dataBuffer
        );

        return {
            ciphertext: this.arrayBufferToBase64(encrypted),
            iv: this.arrayBufferToBase64(iv),
            algorithm: this.algorithm,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Decrypt data using AES-256-GCM
     * @param {Object} encryptedData - Encrypted data object
     * @param {CryptoKey} key - Decryption key
     * @returns {Promise<string>} Decrypted data
     */
    async decrypt(encryptedData, key) {
        // Convert from base64 to ArrayBuffer
        const ciphertext = this.base64ToArrayBuffer(encryptedData.ciphertext);
        const iv = this.base64ToArrayBuffer(encryptedData.iv);

        // Decrypt
        const decrypted = await crypto.subtle.decrypt(
            {
                name: this.algorithm,
                iv: iv
            },
            key,
            ciphertext
        );

        // Convert back to string
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    // ========================================================================
    // SHA-256 Integrity Verification
    // ========================================================================

    /**
     * Calculate SHA-256 hash of data
     * @param {string} data
     * @returns {Promise<string>} Hex-encoded hash
     */
    async calculateHash(data) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
        return this.arrayBufferToHex(hashBuffer);
    }

    /**
     * Verify data integrity using SHA-256
     * @param {string} data
     * @param {string} expectedHash
     * @returns {Promise<boolean>}
     */
    async verifyIntegrity(data, expectedHash) {
        const actualHash = await this.calculateHash(data);
        return actualHash === expectedHash;
    }

    /**
     * Create integrity manifest for multiple files
     * @param {Object} files - Object with filename: content pairs
     * @returns {Promise<Object>} Manifest with hashes
     */
    async createIntegrityManifest(files) {
        const manifest = {
            version: '1.0',
            algorithm: 'SHA-256',
            created: new Date().toISOString(),
            files: {}
        };

        for (const [filename, content] of Object.entries(files)) {
            manifest.files[filename] = {
                hash: await this.calculateHash(content),
                size: content.length,
                modified: new Date().toISOString()
            };
        }

        // Hash the manifest itself
        const manifestJson = JSON.stringify(manifest, null, 2);
        manifest.manifestHash = await this.calculateHash(manifestJson);

        return manifest;
    }

    /**
     * Verify all files in manifest
     * @param {Object} files
     * @param {Object} manifest
     * @returns {Promise<Object>} Verification results
     */
    async verifyIntegrityManifest(files, manifest) {
        const results = {
            valid: true,
            files: {},
            errors: []
        };

        for (const [filename, manifestEntry] of Object.entries(manifest.files)) {
            if (!files[filename]) {
                results.valid = false;
                results.errors.push(`Missing file: ${filename}`);
                results.files[filename] = { status: 'missing' };
                continue;
            }

            const actualHash = await this.calculateHash(files[filename]);
            const isValid = actualHash === manifestEntry.hash;

            results.files[filename] = {
                status: isValid ? 'valid' : 'tampered',
                expectedHash: manifestEntry.hash,
                actualHash: actualHash
            };

            if (!isValid) {
                results.valid = false;
                results.errors.push(`Hash mismatch for ${filename}`);
            }
        }

        return results;
    }

    // ========================================================================
    // Digital Signatures (ECDSA)
    // ========================================================================

    /**
     * Generate ECDSA key pair for signing
     * @returns {Promise<CryptoKeyPair>}
     */
    async generateSigningKeyPair() {
        return await crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            true,
            ['sign', 'verify']
        );
    }

    /**
     * Sign data with private key
     * @param {string} data
     * @param {CryptoKey} privateKey
     * @returns {Promise<string>} Base64-encoded signature
     */
    async sign(data, privateKey) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);

        const signature = await crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: 'SHA-256'
            },
            privateKey,
            dataBuffer
        );

        return this.arrayBufferToBase64(signature);
    }

    /**
     * Verify signature with public key
     * @param {string} data
     * @param {string} signature
     * @param {CryptoKey} publicKey
     * @returns {Promise<boolean>}
     */
    async verifySignature(data, signature, publicKey) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        const signatureBuffer = this.base64ToArrayBuffer(signature);

        return await crypto.subtle.verify(
            {
                name: 'ECDSA',
                hash: 'SHA-256'
            },
            publicKey,
            signatureBuffer,
            dataBuffer
        );
    }

    /**
     * Export public key in PEM format
     * @param {CryptoKey} publicKey
     * @returns {Promise<string>}
     */
    async exportPublicKeyPEM(publicKey) {
        const exported = await crypto.subtle.exportKey('spki', publicKey);
        const exportedAsBase64 = this.arrayBufferToBase64(exported);
        return `-----BEGIN PUBLIC KEY-----\n${this.chunkString(exportedAsBase64, 64)}\n-----END PUBLIC KEY-----`;
    }

    // ========================================================================
    // Secure Storage Integration
    // ========================================================================

    /**
     * Save encrypted scan results to localStorage
     * @param {string} key - Storage key
     * @param {Object} data - Data to store
     * @param {CryptoKey} encryptionKey - Encryption key
     * @returns {Promise<void>}
     */
    async saveSecure(key, data, encryptionKey) {
        const jsonData = JSON.stringify(data);
        const encrypted = await this.encrypt(jsonData, encryptionKey);
        const hash = await this.calculateHash(jsonData);

        const securePackage = {
            encrypted,
            hash,
            version: '1.0',
            timestamp: new Date().toISOString()
        };

        localStorage.setItem(key, JSON.stringify(securePackage));
    }

    /**
     * Load and decrypt from local Storage
     * @param {string} key - Storage key
     * @param {CryptoKey} encryptionKey - Decryption key
     * @returns {Promise<Object|null>} Decrypted data or null
     */
    async loadSecure(key, encryptionKey) {
        const stored = localStorage.getItem(key);
        if (!stored) return null;

        try {
            const securePackage = JSON.parse(stored);
            const decrypted = await this.decrypt(securePackage.encrypted, encryptionKey);

            // Verify integrity
            const isValid = await this.verifyIntegrity(decrypted, securePackage.hash);
            if (!isValid) {
                console.error('Data integrity check failed');
                return null;
            }

            return JSON.parse(decrypted);
        } catch (error) {
            console.error('Failed to decrypt data:', error);
            return null;
        }
    }

    // ========================================================================
    // Utility Functions
    // ========================================================================

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    arrayBufferToHex(buffer) {
        const bytes = new Uint8Array(buffer);
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    chunkString(str, size) {
        const chunks = [];
        for (let i = 0; i < str.length; i += size) {
            chunks.push(str.slice(i, i + size));
        }
        return chunks.join('\n');
    }

    /**
     * Generate user-friendly encryption key from password
     * @param {string} password
     * @param {string} salt
     * @returns {Promise<CryptoKey>}
     */
    async deriveKeyFromPassword(password, salt = 'sabha-salt-v1') {
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);
        const saltBuffer = encoder.encode(salt);

        // Import password as key material
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        // Derive AES key
        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: saltBuffer,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            {
                name: this.algorithm,
                length: this.keyLength
            },
            true,
            ['encrypt', 'decrypt']
        );
    }
}

// ============================================================================
// Export & Usage Examples
// ============================================================================

if (typeof window !== 'undefined') {
    window.SecurityModule = SecurityModule;

    // Console helper
    console.log(`%c🔒 SABHA Security Module Loaded`, 'color: #10B981; font-weight: bold;');
    console.log(`Features: AES-256-GCM | SHA-256 Integrity | ECDSA Signatures`);
}

/**
 * USAGE EXAMPLES:
 * 
 * // 1. Encrypt scan results
 * const security = new SecurityModule();
 * const key = await security.generateKey();
 * const encrypted = await security.encrypt(JSON.stringify(scanResults), key);
 * 
 * // 2. Calculate file integrity hash
 * const hash = await security.calculateHash(fileContent);
 * 
 * // 3. Create signed manifest
 * const keyPair = await security.generateSigningKeyPair();
 * const manifest = await security.createIntegrityManifest(files);
 * const signature = await security.sign(JSON.stringify(manifest), keyPair.privateKey);
 * 
 * // 4. Secure storage
 * await security.saveSecure('sabha-analysis', analysisData, key);
 * const loaded = await security.loadSecure('sabha-analysis', key);
 */
