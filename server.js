const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.post('/signup', (req, res) => {
  const { walletAddress } = req.body;

  if (!walletAddress) {
    return res.status(400).send({ message: 'Missing wallet address' });
  }

  // Additional logic will be involved here

  console.log(walletAddress);
  res.status(200).send({ message: 'Signup successful' });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
