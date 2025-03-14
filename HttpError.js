module.exports = class extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
};
