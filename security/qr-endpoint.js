// MiniProject/qr-endpoint.js
const express = require('express');
const { generateQR } = require('./generateQR');
const app = express();
const port = 3000;

// http://localhost:3000/qr → returns base-64 QR image
app.get('/qr', async (req, res) => {
  const secret = 'ABC123XYZ';               // same secret you’ll verify later
  const dataUrl = await generateQR(secret); // her function
  res.send(dataUrl);                        // pure Data-URL string
});

app.listen(port, () => console.log(`QR endpoint running on :${port}`));