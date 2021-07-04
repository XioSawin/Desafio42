import { ProductoDTO } from './ProductoDTO';
const fs = require('fs');

export default class persistenciaFileSystem {
    static instancia
    constructor() {
        if(!persistenciaFileSystem.instancia) {
            ;( async() => {
                try{
                    let datos = await fs.promises.readFile('datos.txt');
                    persistenciaFileSystem.instancia = datos;
                    console.log('Persistencia en File System');
                }
                catch {
                    await fs.promises.writeFile('datos.txt', JSON.stringify([]));
                }
            })()
        } else {
            console.log('Ya se ha utilizado esta persistencia')
            return JSON.parse(instancia);
        }
    }

    getFyH() {
        return new Date().toLocaleString()
    }

    obtenerProductos = async() => {
        try{
            let datos = await await fs.promises.readFile('datos.txt');
            return JSON.parse(datos);
        } catch (error) {
            console.log(error);
        }
    }

    agregarProductos = async(producto) => {
        try{
            let productos = JSON.parse(await fs.promises.readFile('datos.txt'));
            let dto = ProductoDTO(producto, this.getFyH());
            productos.push(dto);
            await fs.promises.writeFile('datos.txt', JSON.stringify(productos));
        } catch (error) {
            console.log(error);
        }
    }
}