
import { BigInteger } from 'jsbn';
import { ec } from 'elliptic';
import { randomBytes } from 'crypto';

const EC = new ec('secp256k1');

export const generateECDHKeyPair = () => {
  const keyPair = EC.genKeyPair();
  return {
    privateKey: keyPair.getPrivate('hex'),
    publicKey: keyPair.getPublic('hex'),
  };
};


export const generateRandomKey = () =>{
  return randomBytes(16).toString('hex');
}

// ---  Derive Shared Secret from Private Key and Public Keys ---
export const deriveECDHSharedSecret = (
  userPrivateKeyHex: string,
  otherPublicKeysHex: string[]
) => {
  const userKey = EC.keyFromPrivate(userPrivateKeyHex, 'hex');
  let shared = userKey;

  for (const publicKeyHex of otherPublicKeysHex) {
    const otherKey = EC.keyFromPublic(publicKeyHex, 'hex');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    shared = shared.derive(otherKey.getPublic()) as any;
  }

  return shared.toString(); // Return as hex string
};

// ---  Traditional DH Key Generation for One Participant ---
export const generateDHKeyPair = (bitLength = 256) => {
  const p = new BigInteger(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    16
  );
  const g = new BigInteger("2");

  const randomBytesArray = randomBytes(bitLength / 8);
  const privateKey = new BigInteger(randomBytesArray.toString('hex'), 16);
  const publicKey = g.modPow(privateKey, p);

  return {
    privateKey: privateKey.toString(16),
    publicKey: publicKey.toString(16),
  };
};

// ---  Derive Shared Secret (DH) ---
export const deriveDHSharedSecret = (
  privateKeyHex: string,
  otherPublicKeysHex: string[]
) => {
  const p = new BigInteger(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    16
  );

  const myPriv = new BigInteger(privateKeyHex, 16);
  let shared = new BigInteger(otherPublicKeysHex[0], 16);

  for (let i = 1; i < otherPublicKeysHex.length; i++) {
    const next = new BigInteger(otherPublicKeysHex[i], 16);
    shared = shared.multiply(next).mod(p);
  }

  const finalShared = shared.modPow(myPriv, p);
  return finalShared.toString(16);
};