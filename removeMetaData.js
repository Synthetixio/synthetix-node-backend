module.exports = (o) => {
  const { _, ...withoutMeta } = o;
  return withoutMeta;
};
