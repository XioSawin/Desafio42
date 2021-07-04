import * as negocio from '../negocio/productos.js'

export const getProductos = async (req, res) => {
    res.json({productos: await negocio.obtenerProductos()});
}

export const postProducto = async (req, res)=> {
    let producto = req.body;
    console.log(producto);

    await negocio.agregarProducto(producto);
    res.json({producto});
}
/*
// required
const mongoose = require('mongoose');
const express = require('express');
const app = express();

const productoModel = require('../model/producto');


// timestamp

function getTimestamp(){
    let date = new Date();

    let d = date.getDate();
    let mo = date.getMonth() + 1;
    let y = date.getFullYear();
    let h = date.getHours();
    let mi = date.getMinutes();
    let s = date.getSeconds();

    let today = d + '/' + mo + '/' + y + ' ' + h + ':' + mi + ':' + s;

    return today;
}



// Lista de productos
// let productList = [];

// administrador
const administrador = true; 

const getById = (req, res, next) => {
    const { id } = req.params;

    productoModel.findOne( {id: id})
        .then((producto) => res.send(producto))
        .catch((err)=>res.send(err))
}

const addProduct = (req, res, next) => {
    if (!administrador){
        res.json({error: -1, descripcion: "ruta no autorizada"});
    }

    const {id, nombre, codigo, precio, stock} = req.body;

    let producto = {
        id,
        nombre, 
        codigo, 
        precio, 
        stock
    };

    const productSaved = new productoModel(producto);
    productSaved.save()
        .then( () => res.sendStatus(201) )
        .catch ((err) => res.send(err))
    
}

const updateProduct = (req, res, next) =>{

    if (!administrador){
        res.json({error: -1, descripcion: "ruta no autorizada"});
    }

    const { id } = req.params;
    const {nombre, codigo, precio, stock} = req.body;

    productoModel.updateOne({id: id}, {
        $set: {nombre:nombre, codigo:codigo, precio:precio, stock:stock}
    })
        .then((updatedProduct)=> res.send(updatedProduct))
        .catch((err)=> res.send(err))

}

const deleteProduct = (req, res, next) => {
    if (!administrador){
        res.json({error: -1, descripcion: "ruta no autorizada"});
    }

    const {id} = req.params;

    productoModel.findOne({id:id})
        .then((producto)=>res.send(producto))
        .catch((err)=>res.send(err))
}


module.exports = {
    getById,
    addProduct,
    updateProduct, 
    deleteProduct
}

*/
