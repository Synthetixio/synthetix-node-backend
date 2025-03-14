const HttpError = require('./HttpError');

const validateNamespace = (namespace, next) => {
  const errors = [];

  if (!namespace) {
    errors.push('Namespace cannot be empty.');
  }

  if (namespace && (namespace.length < 3 || namespace.length > 30)) {
    errors.push('Namespace must be between 3 and 30 characters long.');
  }

  if (namespace && !/^[a-z0-9-_]+$/.test(namespace)) {
    errors.push(
      'Namespace must be DNS-compatible: lowercase letters, numbers, dashes (-), or underscores (_).'
    );
  }

  if (namespace && /^-|-$/.test(namespace)) {
    errors.push('Namespace cannot start or end with a dash (-).');
  }

  if (namespace && /^_|_$/.test(namespace)) {
    errors.push('Namespace cannot start or end with an underscore (_).');
  }

  if (errors.length > 0) {
    return next(new HttpError(errors.join(' '), 400));
  }

  next();
};

module.exports = validateNamespace;
