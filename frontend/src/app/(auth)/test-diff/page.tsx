'use client';
import { useState } from 'react';
import { BigInteger, SecureRandom } from 'jsbn';
import { ec } from 'elliptic';

const EC = new ec('secp256k1');

const generateECDHKeyPair = () => {
  return EC.genKeyPair();
};

const generatePrivateKey = (bitLength) => {
  const random = new SecureRandom();
  return new BigInteger(bitLength, random);
};

const modExp = (base, exp, mod) => {
  return base.modPow(exp, mod);
};

export default function DiffieHellmanTest() {
  const p = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
                           "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
                           "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
                           "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
                           "49286651ECE65381FFFFFFFFFFFFFFFF", 16);
  const g = new BigInteger("2");

  const [keys, setKeys] = useState(null);
  const [sharedSecrets, setSharedSecrets] = useState(null);

  const performKeyExchange = (numParticipants) => {
    if (numParticipants === 2) {
      // ECDH for 2 participants
      const alice = generateECDHKeyPair();
      const bob = generateECDHKeyPair();
      
      const sharedSecretAlice = alice.derive(bob.getPublic()).toString(16);
      const sharedSecretBob = bob.derive(alice.getPublic()).toString(16);
      
      setKeys({
        Alice: { privateKey: alice.getPrivate("hex"), publicKey: alice.getPublic("hex") },
        Bob: { privateKey: bob.getPrivate("hex"), publicKey: bob.getPublic("hex") }
      });
      setSharedSecrets({
        Alice: sharedSecretAlice,
        Bob: sharedSecretBob
      });
    } else {
      // Traditional DH for multiple participants
      const privateKeys = [];
      const publicKeys = [];
      
      for (let i = 0; i < numParticipants; i++) {
        let privKey;
        do {
          privKey = generatePrivateKey(256);
        } while (privateKeys.some(k => k.equals(privKey)));
        privateKeys.push(privKey);
        publicKeys.push(modExp(g, privKey, p));
      }
      
      let sharedSecret = publicKeys[0];
      for (let i = 1; i < numParticipants; i++) {
        sharedSecret = modExp(sharedSecret, privateKeys[i], p);
      }
      
      setKeys({ privateKeys, publicKeys });
      setSharedSecrets({ SharedSecret: sharedSecret.toString(16) });
    }
  };

  return (
    <div className="p-4 bg-gray-100 min-h-screen flex flex-col items-center">
      <h1 className="text-2xl font-bold mb-4">Diffie-Hellman & ECDH Test</h1>
      <button onClick={() => performKeyExchange(2)} className="px-4 py-2 bg-green-500 text-white rounded mb-4">
        Test ECDH (2 Participants)
      </button>
      <button onClick={() => performKeyExchange(3)} className="px-4 py-2 bg-blue-500 text-white rounded mb-4">
        Test Traditional DH (3+ Participants)
      </button>
      {keys && (
        <div className="bg-white p-4 rounded shadow w-96 text-center">
          <h2 className="text-lg font-semibold">Generated Keys</h2>
          {keys.Alice && <p><strong>Alice's Private Key:</strong> {keys.Alice.privateKey}</p>}
          {keys.Alice && <p><strong>Alice's Public Key:</strong> {keys.Alice.publicKey}</p>}
          {keys.Bob && <p><strong>Bob's Private Key:</strong> {keys.Bob.privateKey}</p>}
          {keys.Bob && <p><strong>Bob's Public Key:</strong> {keys.Bob.publicKey}</p>}
          {keys.privateKeys && keys.privateKeys.map((priv, idx) => (
            <p key={idx}><strong>Private Key {idx + 1}:</strong> {priv.toString(16)}</p>
          ))}
          {keys.publicKeys && keys.publicKeys.map((pub, idx) => (
            <p key={idx}><strong>Public Key {idx + 1}:</strong> {pub.toString(16)}</p>
          ))}
        </div>
      )}
      {sharedSecrets && (
        <div className="bg-white p-4 rounded shadow mt-4 w-96 text-center">
          <h2 className="text-lg font-semibold">Shared Secret</h2>
          <p><strong>Alice's Shared Secret:</strong> {sharedSecrets.Alice}</p>
          <p><strong>Bob's Shared Secret:</strong>
{sharedSecrets.Bob}</p>
          {sharedSecrets.SharedSecret && <p><strong>Common Shared Secret:</strong> {sharedSecrets.SharedSecret}</p>}
          <p className="mt-2 font-bold text-green-600">
            {Object.values(sharedSecrets).every((val, i, arr) => val === arr[0])
              ? '✅ Success! All participants have the same shared secret.'
              : '❌ Error: Shared secrets do not match!'}
          </p>
        </div>
      )}
    </div>
  );
}