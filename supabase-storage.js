'use strict';

const { createClient } = require('@supabase/supabase-js');

const url = process.env.SUPABASE_URL;
const secret = process.env.SUPABASE_SECRET_KEY;
const bucket = process.env.SUPABASE_BUCKET;

if (!url || !secret || !bucket) {
  throw new Error('Supabase Storage configuration is missing');
}

const supabase = createClient(url, secret, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
    detectSessionInUrl: false
  }
});

const patterns = {
  deposits: /^[0-9a-f-]{36}\.(?:jpg|png)$/i,
  kyc: /^[0-9a-f-]{36}(?:-(?:jpg|png)\.enc|\.(?:jpg|png))$/i,
  loans: /^[0-9a-f-]{36}-(?:jpg|png)\.enc$/i
};

const folders = {
  deposits: 'deposit-uploads',
  kyc: 'kyc-uploads',
  loans: 'loan-uploads'
};

function objectPath(category, filename) {
  if (!patterns[category]?.test(filename)) {
    throw new Error('Invalid private storage path');
  }
  return folders[category] + '/' + filename;
}

async function save(category, filename, buffer) {
  const key = objectPath(category, filename);
  const contentType = filename.endsWith('.enc')
    ? 'application/octet-stream'
    : filename.endsWith('.png') ? 'image/png' : 'image/jpeg';

  const { error } = await supabase.storage.from(bucket).upload(
    key, buffer, { contentType, upsert: false }
  );
  if (error) throw error;
  return filename;
}

async function read(category, filename) {
  const key = objectPath(category, filename);
  const { data, error } = await supabase.storage.from(bucket).download(key);
  if (error) throw error;
  return Buffer.from(await data.arrayBuffer());
}

async function remove(category, filename) {
  const key = objectPath(category, filename);
  const { error } = await supabase.storage.from(bucket).remove([key]);
  if (error) throw error;
}

module.exports = { save, read, remove };