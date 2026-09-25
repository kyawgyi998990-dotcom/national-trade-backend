const express = require('express');
const router = express.Router();
const Product = require('../models/Product');

// 1. ကုန်ပစ္စည်းအသစ် ထည့်သွင်းရန် (POST)
router.post('/', async (req, res) => {
    try {
        const newProduct = new Product(req.body);
        const savedProduct = await newProduct.save();
        res.status(201).json(savedProduct);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. ကုန်ပစ္စည်းအားလုံးကို ကြည့်ရှုရန် (GET)
router.get('/', async (req, res) => {
    try {
        const products = await Product.find();
        res.status(200).json(products);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
