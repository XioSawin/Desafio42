const express = require('express');
const router = express.Router();

import * as controlador from '../controladores/productosController.js'

// routes

router.get('/', controlador.getProductos);

router.post('/', controlador.postProducto);

router.patch('/actualizar/:id', productosController.updateProduct);

router.delete('/borrar/:id', productosController.deleteProduct);

module.exports = router;
