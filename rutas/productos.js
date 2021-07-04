//const mongoose = require('mongoose');
const express = require('express');
const router = express.Router();
//const app = express();

import * as controlador from '../controladores/productosController.js'

// routes

router.get('/', controlador.getProductos);

//router.get('/listar/:id?', productosController.getById);

router.post('/', controlador.postProducto);
//router.post('/agregar', productosController.addProduct);

router.patch('/actualizar/:id', productosController.updateProduct);

router.delete('/borrar/:id', productosController.deleteProduct);

module.exports = router;
