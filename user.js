const { MongoClient } = require('mongodb');
const sodium = require('libsodium-wrappers');
const { mnemonicToSeedSync, generateMnemonic } = require('bip39');

const mongoUrl = 'mongodb://localhost:27017';
const dbName = 'diamond';

class User {
    static async createWallet(telegramId, phoneNumber, username) {
        await sodium.ready;
        const seedPhrase = generateMnemonic(256);
        const seed = mnemonicToSeedSync(seedPhrase);
        const address = sodium.crypto_sign_seed_keypair(seed).publicKey.toString('hex');
        const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
        const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
        const encryptedAddress = sodium.crypto_secretbox_easy(address, nonce, key);

        const client = new MongoClient(mongoUrl);
        try {
            await client.connect();
            const db = client.db(dbName);
            const user = { 
                id: new Date().getTime(), 
                telegramId, 
                phoneNumber: phoneNumber || '', 
                address: encryptedAddress.toString('hex'), 
                nonce: nonce.toString('hex'), 
                seedPhrase, 
                balances: { onchain: 0, offchain: 0, available: 0, inOrder: 0 }, 
                history: [], 
                openOrders: [] 
            };
            await db.collection('users').insertOne(user);
            return { seedPhrase, user };
        } finally {
            await client.close();
        }
    }

    static async importWallet(telegramId, phoneNumber, seedPhrase, username) {
        await sodium.ready;
        const seed = mnemonicToSeedSync(seedPhrase);
        const address = sodium.crypto_sign_seed_keypair(seed).publicKey.toString('hex');
        const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
        const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
        const encryptedAddress = sodium.crypto_secretbox_easy(address, nonce, key);

        const client = new MongoClient(mongoUrl);
        try {
            await client.connect();
            const db = client.db(dbName);
            const users = db.collection('users');
            const existing = await users.findOne({ address: encryptedAddress });
            if (!existing) {
                const user = { 
                    id: new Date().getTime(), 
                    telegramId, 
                    phoneNumber: phoneNumber || '', 
                    address: encryptedAddress.toString('hex'), 
                    nonce: nonce.toString('hex'), 
                    seedPhrase, 
                    balances: { onchain: 0, offchain: 0, available: 0, inOrder: 0 }, 
                    history: [], 
                    openOrders: [] 
                };
                await users.insertOne(user);
                return { message: 'Wallet imported! New ID created.', user };
            }
            return { message: 'Wallet imported! Existing data loaded.', user: existing };
        } finally {
            await client.close();
        }
    }

    static async findByTelegramId(telegramId) {
        const client = new MongoClient(mongoUrl);
        try {
            await client.connect();
            const db = client.db(dbName);
            return await db.collection('users').findOne({ telegramId });
        } finally {
            await client.close();
        }
    }
}

module.exports = User;
