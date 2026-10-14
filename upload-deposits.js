'use strict';

process.loadEnvFile('.env');

const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const storage = require('./supabase-storage');

async function main() {
    if (process.env.SUPABASE_BUCKET !== 'national-trade-private') {
        throw new Error('Wrong Supabase bucket');
    }

    const folder = path.join(
        os.homedir(),
        'national-trade-backend',
        'private',
        'deposit-uploads'
    );

    const entries = await fs.readdir(folder, {
        withFileTypes: true
    });

    if (entries.length !== 13 || entries.some(e => !e.isFile())) {
        throw new Error('Expected exactly 13 deposit files');
    }

    const validName = /^[0-9a-f-]{36}\.(jpg|png)$/i;

    for (const entry of entries) {
        if (!validName.test(entry.name)) {
            throw new Error('Unexpected deposit filename');
        }
    }

    let verified = 0;

    for (const entry of entries) {
        const original = await fs.readFile(
            path.join(folder, entry.name)
        );

        try {
            await storage.save('deposits', entry.name, original);
        } catch (error) {
            // Never overwrite an existing Cloud file.
            const existing = await storage.read('deposits', entry.name);

            if (!existing.equals(original)) {
                throw new Error('Cloud file differs from original');
            }
        }

        const cloudFile = await storage.read(
            'deposits',
            entry.name
        );

        if (!cloudFile.equals(original)) {
            throw new Error('Upload verification failed');
        }

        verified++;
        console.log(`VERIFIED: ${verified}/13`);
    }

    console.log('DEPOSIT CLOUD MIGRATION: PASS');
}

main().catch(error => {
    console.error('MIGRATION STOPPED:', error.message);
    process.exitCode = 1;
});