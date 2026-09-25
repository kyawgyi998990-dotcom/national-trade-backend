const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const mongoURI = "mongodb+srv://kyawgyi998990_db_user:Aa112211@cluster0.mxqhgnb.mongodb.net/?appName=Cluster0&compressors=zlib";

mongoose.connect(mongoURI)
  .then(() => {
      console.log("Database connected successfully!");
  })
  .catch((err) => {
      console.error("Database connection failed:", err);
  });

// Product Routes ကို ချိတ်ဆက်ခြင်း
const productRoutes = require('./routes/productRoutes');
app.use('/api/products', productRoutes);

app.listen(3000, () => {
    console.log("Server is running on port 3000");
});
