'use strict';

process.loadEnvFile('.env');

const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const storage = require('./supabase-storage');

const sourceRoot = path.join(
    os.homedir(),
    'national-trade-backend',
    'private'
);

const categories = [
    { type: 'kyc', folder: 'kyc-uploads', expected: 10 },
    { type: 'loans', folder: 'loan-uploads', expected: 8 }
];

const validName =
    /^[0-9a-f-]{36}(?:-(?:jpg|png)\.enc|\.(?:jpg|png))$/i;

async function migrate(category) {
    const directory = path.join(sourceRoot, category.folder);
    const files = await fs.readdir(directory, {
        withFileTypes: true
    });

    if (
        files.length !== category.expected ||
        files.some(file => !file.isFile())
    ) {
        throw new Error(
            `${category.type}: Unexpected file count or file type`
        );
    }

    if (files.some(file => !validName.test(file.name))) {
        throw new Error(
            `${category.type}: Invalid filename found`
        );
    }

    let verified = 0;

    for (const file of files) {
        const original = await fs.readFile(
            path.join(directory, file.name)
        );

        try {
            await storage.save(
                category.type,
                file.name,
                original
            );
        } catch (error) {
            // Do not overwrite an existing Cloud file.
            const existing = await storage.read(
                category.type,
                file.name
            );

            if (!existing.equals(original)) {
                throw new Error(
                    `${category.type}: Existing Cloud file differs`
                );
            }
        }

        const downloaded = await storage.read(
            category.type,
            file.name
        );

        if (!downloaded.equals(original)) {
            throw new Error(
                `${category.type}: Verification failed`
            );
        }

        verified++;

        console.log(
            `${category.type.toUpperCase()} VERIFIED: ${verified}/${category.expected}`
        );
    }
}

async function main() {
    if (process.env.SUPABASE_BUCKET !== 'national-trade-private') {
        throw new Error('Wrong Supabase bucket');
    }

    for (const category of categories) {
        await migrate(category);
    }

    console.log('KYC + LOAN CLOUD MIGRATION: PASS');
}

main().catch(error => {
    console.error('MIGRATION STOPPED:', error.message);
    process.exitCode = 1;
});