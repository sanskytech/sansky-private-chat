import { openDB } from 'idb';

const DB_NAME = 'SansecChat';
const STORE_NAME = 'users';

export const storeUserId = async (groupName: string, userId: string) => {
  const db = await openDB(DB_NAME, 1, {
    upgrade(db) {
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    },
  });

  await db.put(STORE_NAME, userId, `${groupName}-userId`);
};

export const getUserId = async (groupName: string) => {
  const db = await openDB(DB_NAME, 1);
  return db.get(STORE_NAME, `${groupName}-userId`);
};



//import { storeUserId, getUserId } from '@/utils/indexedDBHelper';

// Store it
//await storeUserId(groupName, data.user_id);

// Retrieve it later
//const userId = await getUserId(groupName);

