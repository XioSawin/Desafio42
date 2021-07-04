import { ProductoDTO } from './ProductoDTO';

export default class persistenciaMemory {
    static instancia

    constructor (){
        if(!persistenciaMemory.instancia) {
            this.productos = [];
            persistenciaMemory.instancia = this;
            console.log('Persistencia en memoria');
        } else {
            console.log('Ya se ha utilizado esta persistencia');
            return persistenciaMemory.instancia;
        }
    }

    getFyH() {
        return new Date().toLocaleString()
    }

    obtenerProductos = () => {
        return this.productos
    }

    agregarProducto = (producto) => {
        let dto = ProductoDTO(producto, this.getFyH());
        this.productos.push(dto);
        return dto;
    }
}