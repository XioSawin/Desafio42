const model = require('../model/producto');

export const obtenerProductos = async () => {
    return await model.obtenerProductos()
}

export const agregarProducto = async (producto) => {
    await model.agregarProducto(producto);
}