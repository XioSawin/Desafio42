const mongoose = require('mongoose');

const productosCollection = 'productos';

const ProductosSchema = new mongoose.Schema({
    id: {type: Number, require: true},
    nombre: {type: String, require: true, max: 100},
    codigo: {type: Number, require: true, max: 20},
    precio: {type: Number, require: true},
    stock: {type: Number, require: true}
})

const ProductoModel = mongoose.model(productosCollection, ProductosSchema);

export default class persistenciaMongo {
    static instancia

    constructor() {
        if(!persistenciaMongo.instancia) {
            ;( async() => {
                try{
                    await mongoose.connect(process.env.DB_CONN, {
                        useNewUrlParser: true,
                        useUnifiedTopology: true,
                        useFindAndModify: false,
                        useCreateIndex: true
                    });
                    instancia = true;
                    console.log('Base de datos conectada');
                }
                catch (error){
                    console.log(error);
                }
            })()
        } else {
            console.log('Ya se ha utilizado esta persistencia - Mongo DB');
        }
    }

    obtenerProductos = async () => {
        try{
            return await ProductoModel.find({}).lean();
        } catch(error) {
            console.log(error);
        }
    }

    agregarProducto = async (producto) => {
        try {
            const productSaved = new productoModel(producto);
            await productSaved.save()
        } catch (error) {
            console.log(error);
        }
    }
}