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
