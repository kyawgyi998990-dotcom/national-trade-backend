'use strict';

const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');

const categories = {
  deposits: {
    directory: 'deposit-uploads',
    filename: /^[0-9a-f-]{36}\.(?:jpg|png)$/i
  },
  kyc: {
    directory: 'kyc-uploads',
    filename: /^[0-9a-f-]{36}(?:-(?:jpg|png)\.enc|\.(?:jpg|png))$/i
  },
  loans: {
    directory: 'loan-uploads',
    filename: /^[0-9a-f-]{36}-(?:jpg|png)\.enc$/i
  }
};

function createPrivateStorage({
  root = process.env.PRIVATE_STORAGE_DIR ||
    path.join(__dirname, 'private'),
  legacyRoot = process.env.PRIVATE_STORAGE_LEGACY_DIR ||
    path.join(__dirname, 'private'),
  production = process.env.NODE_ENV === 'production'
} = {}) {
  const storageRoot = path.resolve(root);
  const oldRoot = path.resolve(legacyRoot);
  const publicRoot = path.resolve(__dirname, 'public');
  const relativeToPublic = path.relative(publicRoot, storageRoot);

  if (relativeToPublic === '' ||
      (!relativeToPublic.startsWith(`..${path.sep}`) && relativeToPublic !== '..') ||
      path.isAbsolute(relativeToPublic)) {
    throw new Error('PRIVATE_STORAGE_DIR must be outside the public web directory');
  }
  const cloudStorageEnabled =
    process.env.NT_USE_SUPABASE_STORAGE === 'true';

if (production && !cloudStorageEnabled &&
    !process.env.PRIVATE_STORAGE_DIR) {
    throw new Error(
        'PRIVATE_STORAGE_DIR must point to a mounted persistent private disk in production'
    );
}

  const directories = Object.fromEntries(
    Object.entries(categories).map(([key, category]) => [
      key,
      path.join(storageRoot, category.directory)
    ])
  );

  async function ensurePrivateDirectory(directory) {
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    const stat = await fs.lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error(`Private storage path is not a regular directory: ${directory}`);
    }
    const [resolvedPublicRoot, resolvedDirectory] = await Promise.all([
      fs.realpath(publicRoot),
      fs.realpath(directory)
    ]);
    const resolvedRelative = path.relative(resolvedPublicRoot, resolvedDirectory);
    if (resolvedRelative === '' ||
        (!resolvedRelative.startsWith(`..${path.sep}`) && resolvedRelative !== '..') ||
        path.isAbsolute(resolvedRelative)) {
      throw new Error('Private storage must resolve outside the public web directory');
    }
    if (process.platform !== 'win32') await fs.chmod(directory, 0o700);
  }

  async function importLegacyFiles(key, destination) {
    const source = path.join(oldRoot, categories[key].directory);
    if (source === destination) return;

    let sourceStat;
    try {
      sourceStat = await fs.lstat(source);
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
    if (!sourceStat.isDirectory() || sourceStat.isSymbolicLink()) {
      throw new Error(`Legacy private storage path is not a regular directory: ${source}`);
    }

    let entries;
    try {
      entries = await fs.readdir(source, { withFileTypes: true });
    } catch (error) {
      throw error;
    }

    for (const entry of entries) {
      if (!categories[key].filename.test(entry.name)) continue;
      if (entry.isSymbolicLink()) {
        throw new Error(`Refusing symbolic link in private document storage: ${entry.name}`);
      }
      if (!entry.isFile()) continue;
      const sourcePath = path.join(source, entry.name);
      const destinationPath = path.join(destination, entry.name);
      try {
        await fs.copyFile(sourcePath, destinationPath, constants.COPYFILE_EXCL);
        if (process.platform !== 'win32') await fs.chmod(destinationPath, 0o600);
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
      }
    }
  }

  async function secureExistingFiles(key, directory) {
    const entries = await fs.readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (!categories[key].filename.test(entry.name)) continue;
      if (entry.isSymbolicLink()) {
        throw new Error(`Refusing symbolic link in private document storage: ${entry.name}`);
      }
      if (entry.isFile() && process.platform !== 'win32') {
        await fs.chmod(path.join(directory, entry.name), 0o600);
      }
    }
  }

  async function initialize() {
    await ensurePrivateDirectory(storageRoot);
    for (const [key, directory] of Object.entries(directories)) {
      await ensurePrivateDirectory(directory);
      await importLegacyFiles(key, directory);
      await secureExistingFiles(key, directory);
    }
  }

  return {
    root: storageRoot,
    directories,
    initialize
  };
}

module.exports = createPrivateStorage();
module.exports.createPrivateStorage = createPrivateStorage;
