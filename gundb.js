const Gun = require('gun');

let gunInstance;

const encrypt = async (data) => await Gun.SEA.encrypt(data, process.env.SECRET);
const decrypt = async (data) => await Gun.SEA.decrypt(data, process.env.SECRET);

const initGun = (server) => {
  if (!server) {
    throw new Error('Server instance is required to initialize Gun');
  }
  if (!gunInstance) {
    gunInstance = Gun({ web: server, file: process.env.GUNDB_STORAGE_PATH });
    console.log('GunDB successfully initialized!');
  }
  return gunInstance;
};

const getGun = () => {
  if (!gunInstance) {
    throw new Error('Gun is not initialized. Call initGun(server) first.');
  }
  return gunInstance;
};

module.exports = { initGun, getGun, encrypt, decrypt };
