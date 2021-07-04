import persistenciaMemory from './productoMemoryDAO.js'
import persistenciaFileSystem from './productoFileSystemDAO.js'
import persistenciaMongo from './productoMongoDBDAO.js'

/* -------------------------------------- */
/*                FACTORY                 */
/* -------------------------------------- */
class FactoryPersonaModel {
    static set(opcion) {
        console.log('**** PERSISTENCIA SELECCIONADA **** [' + opcion + ']')
        switch(opcion) {
            case 'Mem': return new persistenciaMemory()
            case 'File': return new persistenciaFileSystem()
            case 'Mongo': return new persistenciaMongo()
        }
    }
}

const opcion = process.env.PERSISTENCIA;
export default FactoryPersonaModel.set(opcion);
