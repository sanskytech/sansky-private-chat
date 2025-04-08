'use client';

import { useState } from 'react';
import { BigInteger } from 'jsbn';
import { ec } from 'elliptic';
import { randomBytes } from 'crypto';

const EC = new ec('secp256k1');

const generateECDHKeyPair = () => EC.genKeyPair();

const generatePrivateKey = (bitLength: number): BigInteger => {
  const randomBytesArray = randomBytes(bitLength / 8);
  return new BigInteger(randomBytesArray.toString('hex'), 16);
};

const modExp = (base: BigInteger, exp: BigInteger, mod: BigInteger): BigInteger => {
  return base.modPow(exp, mod);
};

// Types
type ECDHKeySet = {
  Alice: {
    privateKey: string;
    publicKey: string;
  };
  Bob: {
    privateKey: string;
    publicKey: string;
  };
};

type DHKeySet = {
  privateKeys: BigInteger[];
  publicKeys: BigInteger[];
};

type SharedSecretSet = {
  Alice?: string;
  Bob?: string;
  SharedSecret?: string;
};

export default function DiffieHellmanTest() {
  const p = new BigInteger(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    16
  );
  const g = new BigInteger("2");

  const [keys, setKeys] = useState<ECDHKeySet | DHKeySet | null>(null);
  const [sharedSecrets, setSharedSecrets] = useState<SharedSecretSet | null>(null);

  const performKeyExchange = (numParticipants: number): void => {
    if (numParticipants === 2) {
      const alice = generateECDHKeyPair();
      const bob = generateECDHKeyPair();

      const sharedSecretAlice = alice.derive(bob.getPublic()).toString(16);
      const sharedSecretBob = bob.derive(alice.getPublic()).toString(16);

      setKeys({
        Alice: {
          privateKey: alice.getPrivate("hex"),
          publicKey: alice.getPublic("hex"),
        },
        Bob: {
          privateKey: bob.getPrivate("hex"),
          publicKey: bob.getPublic("hex"),
        },
      });

      setSharedSecrets({
        Alice: sharedSecretAlice,
        Bob: sharedSecretBob,
      });
    } else {
      const privateKeys: BigInteger[] = [];
      const publicKeys: BigInteger[] = [];

      for (let i = 0; i < numParticipants; i++) {
        let privKey: BigInteger;
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

      <button
        onClick={() => performKeyExchange(2)}
        className="px-4 py-2 bg-green-500 text-white rounded mb-2"
      >
        Test ECDH (2 Participants)
      </button>

      <button
        onClick={() => performKeyExchange(3)}
        className="px-4 py-2 bg-blue-500 text-white rounded mb-4"
      >
        Test Traditional DH (3+ Participants)
      </button>

      {keys && (
        <div className="bg-white p-4 rounded shadow w-full max-w-xl text-sm">
          <h2 className="text-lg font-semibold mb-2">Generated Keys</h2>
          {'Alice' in keys && (
            <>
              <p><strong>Alice&apos;s Private Key:</strong> {keys.Alice.privateKey}</p>
              <p><strong>Alice&apos;s Public Key:</strong> {keys.Alice.publicKey}</p>
            </>
          )}
          {'Bob' in keys && (
            <>
              <p><strong>Bob&apos;s Private Key:</strong> {keys.Bob.privateKey}</p>
              <p><strong>Bob&apos;s Public Key:</strong> {keys.Bob.publicKey}</p>
            </>
          )}
          {'privateKeys' in keys && keys.privateKeys.map((priv, idx) => (
            <p key={idx}><strong>Private Key {idx + 1}:</strong> {priv.toString(16)}</p>
          ))}
          {'publicKeys' in keys && keys.publicKeys.map((pub, idx) => (
            <p key={idx}><strong>Public Key {idx + 1}:</strong> {pub.toString(16)}</p>
          ))}
        </div>
      )}

      {sharedSecrets && (
        <div className="bg-white p-4 rounded shadow mt-4 w-full max-w-xl text-sm">
          <h2 className="text-lg font-semibold">Shared Secret</h2>
          {sharedSecrets.Alice && (
            <p><strong>Alice&apos;s Shared Secret:</strong> {sharedSecrets.Alice}</p>
          )}
          {sharedSecrets.Bob && (
            <p><strong>Bob&apos;s Shared Secret:</strong> {sharedSecrets.Bob}</p>
          )}
          {sharedSecrets.SharedSecret && (
            <p><strong>Common Shared Secret:</strong> {sharedSecrets.SharedSecret}</p>
          )}
          <p className="mt-2 font-bold text-green-600">
            {Object.values(sharedSecrets).every((val, _, arr) => val === arr[0])
              ? '✅ Success! All participants have the same shared secret.'
              : '❌ Error: Shared secrets do not match!'}
          </p>
        </div>
      )}
    </div>
  );
}
