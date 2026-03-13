// Quick test: connect using native mongodb driver with different TLS settings
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function test() {
  const uri = process.env.MONGODB_URI;
  console.log('Test 1: Using tlsAllowInvalidCertificates...');
  try {
    const client = new MongoClient(uri, { 
      tls: true,
      tlsAllowInvalidCertificates: true,
      tlsAllowInvalidHostnames: true,
      minTLSVersion: 'TLSv1.2',
    });
    await client.connect();
    const db = client.db('projecttracker');
    const collections = await db.listCollections().toArray();
    console.log('✓ Connected! Collections:', collections.map(c => c.name));
    await client.close();
  } catch(e) {
    console.log('✗ Failed:', e.message);
  }

  console.log('\nTest 2: Without TLS options...');  
  try {
    const client = new MongoClient(uri);
    await client.connect();
    const db = client.db('projecttracker');
    const collections = await db.listCollections().toArray();
    console.log('✓ Connected! Collections:', collections.map(c => c.name));
    await client.close();
  } catch(e) {
    console.log('✗ Failed:', e.message);
  }

  console.log('\nTest 3: With tls=false in URI...');
  try {
    const modUri = uri.replace('retryWrites=true', 'retryWrites=true&tls=false');
    const client = new MongoClient(modUri);
    await client.connect();
    const db = client.db('projecttracker');
    const collections = await db.listCollections().toArray();
    console.log('✓ Connected! Collections:', collections.map(c => c.name));
    await client.close();
  } catch(e) {
    console.log('✗ Failed:', e.message);
  }

  process.exit(0);
}

test().catch(console.error);
